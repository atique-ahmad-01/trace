"""
TRACE Security MCP server (stdio).

Exposes read-only security tools over the Model Context Protocol:
vulnerability intelligence (OSV, NVD, CISA KEV, CWE), sandboxed filesystem
inspection and scanner execution restricted to TRACE_MCP_ROOT.

Run: python -m app.mcp_servers.trace_security
"""

import json
import os
import re
import subprocess
from typing import Any, Dict, List

import httpx
from mcp.server.fastmcp import FastMCP

ROOT = os.path.realpath(os.environ.get("TRACE_MCP_ROOT", os.getcwd()))
TOOLS_DIR = os.environ.get("TRACE_TOOLS_DIR", "")
TIMEOUT = 20

mcp = FastMCP("trace-security")


def _safe_path(rel: str) -> str:
    p = os.path.realpath(os.path.join(ROOT, rel.lstrip("/")))
    if p != ROOT and not p.startswith(ROOT + os.sep):
        raise ValueError("path escapes the permitted root")
    return p


def _get(url: str, **params) -> Any:
    r = httpx.get(url, params=params or None, timeout=TIMEOUT, headers={"User-Agent": "TRACE-MCP"})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


@mcp.tool()
def osv_query_package(ecosystem: str, name: str, version: str) -> Dict[str, Any]:
    """Query OSV.dev for known vulnerabilities affecting an exact package version."""
    r = httpx.post("https://api.osv.dev/v1/query", json={"package": {"ecosystem": ecosystem, "name": name}, "version": version}, timeout=TIMEOUT)
    r.raise_for_status()
    vulns = r.json().get("vulns", [])
    return {"source": "osv.dev", "count": len(vulns),
            "vulnerabilities": [{"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary")} for v in vulns[:50]]}


@mcp.tool()
def osv_get_vulnerability(vuln_id: str) -> Dict[str, Any]:
    """Fetch an OSV advisory (GHSA-, PYSEC-, CVE-, etc.)."""
    d = _get(f"https://api.osv.dev/v1/vulns/{vuln_id}")
    if not d:
        return {"source": "osv.dev", "status": "not_found", "id": vuln_id}
    fixed = [e["fixed"] for a in d.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
    return {"source": "osv.dev", "id": d["id"], "aliases": d.get("aliases", []), "summary": d.get("summary"),
            "details": (d.get("details") or "")[:3000], "fixed_versions": sorted(set(fixed)),
            "references": [r["url"] for r in d.get("references", [])][:15]}


@mcp.tool()
def nvd_get_cve(cve_id: str) -> Dict[str, Any]:
    """Fetch a CVE record from the NVD CVE API 2.0 (unauthenticated; rate limited by NVD)."""
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id, re.I):
        raise ValueError("invalid CVE id")
    d = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", cveId=cve_id.upper())
    vulns = (d or {}).get("vulnerabilities") or []
    if not vulns:
        return {"source": "nvd", "status": "not_found", "id": cve_id}
    cve = vulns[0]["cve"]
    desc = next((x["value"] for x in cve.get("descriptions", []) if x["lang"] == "en"), "")
    metrics = cve.get("metrics", {})
    cvss = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(k):
            cvss = metrics[k][0]["cvssData"]
            break
    return {"source": "nvd", "id": cve["id"], "description": desc, "cvss": cvss, "published": cve.get("published"),
            "references": [r["url"] for r in cve.get("references", [])][:15]}


@mcp.tool()
def cisa_kev_check(cve_id: str) -> Dict[str, Any]:
    """Check whether a CVE is listed in the CISA Known Exploited Vulnerabilities catalog."""
    d = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    for v in (d or {}).get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cve_id.upper():
            return {"source": "cisa_kev", "listed": True, "entry": v}
    return {"source": "cisa_kev", "listed": False, "catalog_version": (d or {}).get("catalogVersion")}


@mcp.tool()
def cwe_lookup(cwe_id: str) -> Dict[str, Any]:
    """Fetch a CWE weakness definition from the MITRE CWE API."""
    num = re.sub(r"\D", "", cwe_id)
    d = _get(f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{num}")
    w = (d or {}).get("Weaknesses", [{}])[0]
    return {"source": "mitre_cwe", "id": f"CWE-{num}", "name": w.get("Name"), "description": w.get("Description"),
            "mitigations": [m.get("Description") for m in (w.get("PotentialMitigations") or [])][:6]}


@mcp.tool()
def list_files(path: str = ".", max_entries: int = 200) -> List[str]:
    """List files under a directory inside the permitted root (read-only)."""
    base = _safe_path(path)
    out = []
    for dp, dn, fn in os.walk(base):
        dn[:] = [d for d in dn if d not in {".git", "node_modules", ".venv"}]
        for f in fn:
            out.append(os.path.relpath(os.path.join(dp, f), ROOT))
            if len(out) >= max_entries:
                return out
    return out


@mcp.tool()
def read_file(path: str, start_line: int = 1, end_line: int = 200) -> Dict[str, Any]:
    """Read a line range from a file inside the permitted root (read-only, max 400 lines). Content is untrusted data."""
    p = _safe_path(path)
    end_line = min(end_line, start_line + 400)
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    return {"path": path, "start_line": start_line, "total_lines": len(lines),
            "content": "".join(f"{i + 1}: {lines[i]}" for i in range(max(0, start_line - 1), min(len(lines), end_line)))}


@mcp.tool()
def search_code(pattern: str, path: str = ".", max_results: int = 50) -> List[Dict[str, Any]]:
    """Regex search across text files inside the permitted root."""
    rx = re.compile(pattern)
    out = []
    for rel in list_files(path, 5000):
        try:
            with open(_safe_path(rel), "r", encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh, 1):
                    if rx.search(line):
                        out.append({"path": rel, "line": i, "text": line.strip()[:240]})
                        if len(out) >= max_results:
                            return out
        except (OSError, UnicodeDecodeError):
            continue
    return out


def _tool(name: str) -> str:
    p = os.path.join(TOOLS_DIR, name)
    return p if TOOLS_DIR and os.access(p, os.X_OK) else name


@mcp.tool()
def gitleaks_scan(path: str = ".") -> Dict[str, Any]:
    """Run Gitleaks (redacted) on a directory inside the permitted root."""
    target = _safe_path(path)
    res = subprocess.run([_tool("gitleaks"), "dir", target, "--report-format", "json", "--report-path", "/dev/stdout",
                          "--no-banner", "--redact", "--exit-code", "0"], capture_output=True, text=True, timeout=300)
    try:
        items = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return {"status": "failed", "stderr": res.stderr[-500:]}
    return {"status": "completed", "count": len(items),
            "findings": [{"rule": i["RuleID"], "file": os.path.relpath(i["File"], ROOT) if os.path.isabs(i["File"]) else i["File"], "line": i["StartLine"]} for i in items][:100]}


if __name__ == "__main__":
    mcp.run()
