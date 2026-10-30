"""
Scanner adapters: build safe argv, execute, and parse JSON output into NormalizedFinding.

Each adapter reports its true status. If a binary is missing the status is
"unavailable" and no findings are produced.
"""

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from app.core.config import settings
from app.scanners import runner
from app.scanners.normalize import NormalizedFinding, extract_cwes, norm_severity, severity_from_cvss


@dataclass
class ScannerOutcome:
    name: str
    status: str  # completed | failed | unavailable | skipped | timeout
    version: Optional[str] = None
    findings: List[NormalizedFinding] = field(default_factory=list)
    command: List[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    duration: float = 0.0
    stderr_tail: str = ""
    error: Optional[str] = None


def _snippet(root: str, rel: Optional[str], line: Optional[int], context: int = 2) -> Optional[str]:
    if not rel or not line:
        return None
    path = os.path.realpath(os.path.join(root, rel))
    if not path.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    lo, hi = max(0, line - 1 - context), min(len(lines), line + context)
    return "".join(f"{i + 1:>5} | {lines[i]}" for i in range(lo, hi))[:4000]


def _rel(root: str, path: str) -> str:
    if os.path.isabs(path):
        try:
            return os.path.relpath(path, root)
        except ValueError:
            return path
    return path.lstrip("./") if path.startswith("./") else path


def _version(binary: str, args: List[str]) -> Optional[str]:
    res = runner.run([binary, *args], timeout=30)
    text = (res.stdout or res.stderr).strip().splitlines()
    for line in text:
        m = re.search(r"\d+\.\d+\.\d+", line)
        if m:
            return m.group(0)
    return None


# --------------------------------------------------------------------------- Trivy


def parse_trivy(data: dict, root: str) -> List[NormalizedFinding]:
    out: List[NormalizedFinding] = []
    for result in data.get("Results") or []:
        target = result.get("Target")
        for v in result.get("Vulnerabilities") or []:
            cvss = None
            for src in ("nvd", "ghsa", "redhat"):
                c = (v.get("CVSS") or {}).get(src) or {}
                cvss = c.get("V3Score") or c.get("V40Score")
                if cvss:
                    break
            out.append(
                NormalizedFinding(
                    scanner="trivy",
                    finding_type="dependency",
                    title=v.get("Title") or f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                    severity=norm_severity(v.get("Severity")),
                    description=v.get("Description") or "",
                    rule_id=v.get("VulnerabilityID"),
                    vuln_id=v.get("VulnerabilityID"),
                    aliases=list(v.get("VendorIDs") or []),
                    cwe_ids=extract_cwes(v.get("CweIDs")),
                    cvss_score=cvss,
                    file_path=target,
                    package_name=v.get("PkgName"),
                    package_ecosystem=result.get("Type"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion") or None,
                    references=([v["PrimaryURL"]] if v.get("PrimaryURL") else []) + list(v.get("References") or [])[:15],
                    raw={k: v.get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "SeveritySource", "PublishedDate", "LastModifiedDate")},
                )
            )
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine")
            out.append(
                NormalizedFinding(
                    scanner="trivy",
                    finding_type="misconfig",
                    title=m.get("Title") or m.get("ID"),
                    severity=norm_severity(m.get("Severity")),
                    description=f"{m.get('Description', '')}\n\n{m.get('Message', '')}\n\nResolution: {m.get('Resolution', '')}".strip(),
                    rule_id=m.get("ID"),
                    file_path=target,
                    start_line=line,
                    code_snippet=_snippet(root, target, line),
                    references=list(m.get("References") or [])[:10],
                    raw={k: m.get(k) for k in ("ID", "Type", "Namespace", "Resolution")},
                )
            )
    return out


def run_trivy(root: str, work: str) -> ScannerOutcome:
    binary = runner.resolve_tool(settings.TRIVY_PATH)
    if not binary:
        return ScannerOutcome("trivy", "unavailable", error="trivy binary not found")
    out_file = os.path.join(work, "trivy.json")
    docker_cfg = tempfile.mkdtemp(dir=work)  # isolate from host docker credential helpers
    argv = [binary, "fs", "--format", "json", "--scanners", "vuln,misconfig", "--quiet", "--output", out_file, "--timeout", f"{settings.SCANNER_TIMEOUT}s"]
    if settings.SCANNER_OFFLINE:
        argv += ["--skip-db-update", "--offline-scan"]
    argv.append(root)
    cache = os.path.join(os.path.dirname(settings.WORK_DIR), "trivy-cache")
    res = runner.run(argv, extra_env={"DOCKER_CONFIG": docker_cfg, "TRIVY_CACHE_DIR": cache, "HOME": work})
    return _finish("trivy", binary, ["--version"], argv, res, out_file, lambda d: parse_trivy(d, root), ok_codes={0})


# --------------------------------------------------------------------------- OSV-Scanner


def _osv_fixed(vuln: dict, pkg_name: str) -> Optional[str]:
    fixed: List[str] = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name", "").lower() != pkg_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return ", ".join(dict.fromkeys(fixed)) or None


def _osv_cvss(vuln: dict) -> Optional[float]:
    ds = vuln.get("database_specific") or {}
    if isinstance(ds.get("cvss"), dict) and ds["cvss"].get("score"):
        return float(ds["cvss"]["score"])
    return None


def parse_osv(data: dict, root: str) -> List[NormalizedFinding]:
    out: List[NormalizedFinding] = []
    for result in data.get("results") or []:
        src = _rel(root, (result.get("source") or {}).get("path", ""))
        for pkg in result.get("packages") or []:
            p = pkg.get("package") or {}
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities") or []}
            groups = pkg.get("groups") or [{"ids": [i], "aliases": [], "max_severity": ""} for i in vulns]
            for g in groups:
                ids = g.get("ids") or []
                primary = next((vulns[i] for i in ids if i in vulns and i.startswith("GHSA")), None) or next((vulns[i] for i in ids if i in vulns), None)
                if not primary:
                    continue
                aliases = sorted(set(g.get("aliases") or []) | set(ids) | set(primary.get("aliases") or []))
                score = None
                try:
                    score = float(g.get("max_severity")) if g.get("max_severity") else None
                except ValueError:
                    score = None
                ghsa_sev = (primary.get("database_specific") or {}).get("severity")
                severity = norm_severity(ghsa_sev) if ghsa_sev else severity_from_cvss(score)
                out.append(
                    NormalizedFinding(
                        scanner="osv-scanner",
                        finding_type="dependency",
                        title=primary.get("summary") or f"{primary['id']} in {p.get('name')}",
                        severity=severity,
                        description=primary.get("details") or primary.get("summary") or "",
                        rule_id=primary["id"],
                        vuln_id=primary["id"],
                        aliases=[a for a in aliases if a != primary["id"]],
                        cwe_ids=extract_cwes((primary.get("database_specific") or {}).get("cwe_ids")),
                        cvss_score=score or _osv_cvss(primary),
                        file_path=src,
                        package_name=p.get("name"),
                        package_ecosystem=p.get("ecosystem"),
                        installed_version=p.get("version"),
                        fixed_version=_osv_fixed(primary, p.get("name", "")),
                        references=[r.get("url") for r in primary.get("references") or [] if r.get("url")][:15],
                        raw={"id": primary["id"], "aliases": aliases, "published": primary.get("published"), "modified": primary.get("modified")},
                    )
                )
    return out


def run_osv(root: str, work: str) -> ScannerOutcome:
    binary = runner.resolve_tool(settings.OSV_SCANNER_PATH)
    if not binary:
        return ScannerOutcome("osv-scanner", "unavailable", error="osv-scanner binary not found")
    out_file = os.path.join(work, "osv.json")
    argv = [binary, "scan", "source", "-r", "--format", "json", "--output", out_file]
    if settings.SCANNER_OFFLINE:
        argv += ["--offline-vulnerabilities"]
    argv.append(root)
    res = runner.run(argv, extra_env={"HOME": work})
    # exit 1 = vulnerabilities found; 128 = no packages found
    if res.exit_code == 128:
        return ScannerOutcome("osv-scanner", "completed", _version(binary, ["--version"]), [], argv, 128, res.duration, res.stderr[-2000:])
    return _finish("osv-scanner", binary, ["--version"], argv, res, out_file, lambda d: parse_osv(d, root), ok_codes={0, 1})


# --------------------------------------------------------------------------- Semgrep


def parse_semgrep(data: dict, root: str) -> List[NormalizedFinding]:
    out: List[NormalizedFinding] = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        rule = r.get("check_id", "")
        rel = _rel(root, r.get("path", ""))
        line = (r.get("start") or {}).get("line")
        is_secret = ".secrets." in rule or "hardcoded" in rule.lower()
        refs = meta.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        if meta.get("source"):
            refs = [meta["source"], *refs]
        out.append(
            NormalizedFinding(
                scanner="semgrep",
                finding_type="secret" if is_secret else "sast",
                title=rule.split(".")[-1].replace("-", " ").replace("_", " ").capitalize(),
                severity=norm_severity(extra.get("severity")),
                description=extra.get("message", ""),
                rule_id=rule,
                cwe_ids=extract_cwes(meta.get("cwe")),
                file_path=rel,
                start_line=line,
                end_line=(r.get("end") or {}).get("line"),
                code_snippet=None if is_secret else _snippet(root, rel, line),
                references=refs[:10],
                raw={"check_id": rule, "owasp": meta.get("owasp"), "confidence": meta.get("confidence"), "likelihood": meta.get("likelihood"), "impact": meta.get("impact")},
            )
        )
    return out


def run_semgrep(root: str, work: str) -> ScannerOutcome:
    binary = runner.resolve_tool(settings.SEMGREP_PATH)
    if not binary:
        return ScannerOutcome("semgrep", "unavailable", error="semgrep binary not found")
    out_file = os.path.join(work, "semgrep.json")
    config = settings.SEMGREP_CONFIG if settings.SEMGREP_CONFIG != "auto" else "p/default"
    argv = [binary, "scan", "--config", config, "--json", "--metrics", "off", "--quiet", "--no-git-ignore",
            "--timeout", "30", "--max-target-bytes", "1000000", "--max-memory", str(settings.SCANNER_MEMORY_LIMIT_MB),
            "-o", out_file, root]
    res = runner.run(argv, extra_env={"HOME": work, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
                     limit_memory=False)
    return _finish("semgrep", binary, ["--version"], argv, res, out_file, lambda d: parse_semgrep(d, root), ok_codes={0, 1})


# --------------------------------------------------------------------------- Gitleaks


def parse_gitleaks(data: list, root: str) -> List[NormalizedFinding]:
    out: List[NormalizedFinding] = []
    for r in data or []:
        rel = _rel(root, r.get("File", ""))
        out.append(
            NormalizedFinding(
                scanner="gitleaks",
                finding_type="secret",
                title=f"Exposed secret: {r.get('RuleID')}",
                severity="HIGH",
                description=(r.get("Description") or "Potential hard-coded credential.")
                + " The secret value is redacted and never stored by TRACE.",
                rule_id=r.get("RuleID"),
                cwe_ids=["CWE-798"],
                file_path=rel,
                start_line=r.get("StartLine"),
                end_line=r.get("EndLine"),
                raw={"RuleID": r.get("RuleID"), "Entropy": r.get("Entropy"), "Commit": r.get("Commit") or None},
            )
        )
    return out


def run_gitleaks(root: str, work: str) -> ScannerOutcome:
    binary = runner.resolve_tool(settings.GITLEAKS_PATH)
    if not binary:
        return ScannerOutcome("gitleaks", "unavailable", error="gitleaks binary not found")
    out_file = os.path.join(work, "gitleaks.json")
    argv = [binary, "dir", root, "--report-format", "json", "--report-path", out_file, "--no-banner", "--redact", "--exit-code", "0"]
    res = runner.run(argv, extra_env={"HOME": work})
    return _finish("gitleaks", binary, ["version"], argv, res, out_file, lambda d: parse_gitleaks(d, root), ok_codes={0})


# --------------------------------------------------------------------------- common


def _json_errors(out_file: str) -> str:
    """Error messages a scanner wrote into its JSON report (semgrep reports fatal errors there under --quiet)."""
    try:
        with open(out_file, "r", encoding="utf-8") as fh:
            errors = json.load(fh).get("errors") or []
    except (OSError, ValueError, AttributeError):
        return ""
    return "; ".join(str(e.get("message") or e.get("type") or e) if isinstance(e, dict) else str(e) for e in errors)


def _finish(name, binary, version_args, argv, res, out_file, parser: Callable, ok_codes) -> ScannerOutcome:
    outcome = ScannerOutcome(
        name=name,
        status="completed",
        version=_version(binary, version_args),
        command=[os.path.basename(argv[0]), *argv[1:]],
        exit_code=res.exit_code,
        duration=res.duration,
        stderr_tail=res.stderr[-3000:],
    )
    if res.timed_out:
        outcome.status, outcome.error = "timeout", f"{name} exceeded {settings.SCANNER_TIMEOUT}s"
        return outcome
    if res.exit_code not in ok_codes or not os.path.exists(out_file):
        outcome.status = "failed"
        outcome.error = f"{name} exited with code {res.exit_code}: {(res.stderr.strip() or _json_errors(out_file))[-500:]}"
        return outcome
    try:
        with open(out_file, "r", encoding="utf-8") as fh:
            outcome.findings = parser(json.load(fh))
    except (json.JSONDecodeError, OSError) as e:
        outcome.status, outcome.error = "failed", f"could not parse {name} output: {e}"
    return outcome


SCANNERS: Dict[str, Callable[[str, str], ScannerOutcome]] = {
    "trivy": run_trivy,
    "osv-scanner": run_osv,
    "semgrep": run_semgrep,
    "gitleaks": run_gitleaks,
}
SCANNER_INFO = {
    "trivy": {"category": "dependency, misconfiguration", "setting": "TRIVY_PATH"},
    "osv-scanner": {"category": "dependency", "setting": "OSV_SCANNER_PATH"},
    "semgrep": {"category": "source code (SAST)", "setting": "SEMGREP_PATH"},
    "gitleaks": {"category": "secrets", "setting": "GITLEAKS_PATH"},
}


def scanner_status() -> List[dict]:
    out = []
    for name, info in SCANNER_INFO.items():
        path = runner.resolve_tool(getattr(settings, info["setting"]))
        out.append({"name": name, "category": info["category"], "available": bool(path),
                    "version": _version(path, ["version"] if name == "gitleaks" else ["--version"]) if path else None})
    return out
