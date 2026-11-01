"""
Scan orchestration.

snapshot -> detect ecosystems -> run applicable scanners in parallel -> normalize
-> deduplicate -> upsert findings by fingerprint -> auto-resolve findings no longer
present -> update posture -> enrich intelligence -> optional AI investigation.
"""

import asyncio
import math
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from loguru import logger
from sqlalchemy import select

from app.core import database
from app.core.config import settings
from app.db.models import Finding, FindingStatus, Repository, RepositoryCommit, Scan, ScannerExecution, ScanStatus
from app.scanners import ecosystems
from app.scanners.adapters import SCANNERS, ScannerOutcome
from app.scanners.normalize import NormalizedFinding, dedupe
from app.services import snapshot

TYPE_BY_SCANNER = {"trivy": {"dependency", "misconfig"}, "osv-scanner": {"dependency"}, "semgrep": {"sast", "secret"}, "gitleaks": {"secret"}}


def posture_score(critical: int, high: int, medium: int, low: int) -> float:
    """0-100. Exponential decay over weighted open findings; never negative, sensitive to criticals."""
    weight = 10 * critical + 5 * high + 2 * medium + 0.5 * low
    return round(100 * math.exp(-weight / 60), 1)


def coverage_gap(outcomes: List[ScannerOutcome], detected: Optional[Dict]) -> Optional[str]:
    """Why a posture score would overstate safety, or None. A score must never come from code no scanner read."""
    status = {o.name: o for o in outcomes}
    if not any(o.status == "completed" for o in outcomes):
        return "no scanner completed"
    langs = sorted((detected or {}).get("language_counts") or {})
    sast = status.get("semgrep")
    if langs and (sast is None or sast.status != "completed"):
        why = sast.error if sast and sast.error else (sast.status if sast else "not run")
        return f"source code ({', '.join(langs)}) was not analyzed: semgrep {why}"
    return None


def choose_scanners(detected: Dict, requested: Optional[List[str]]) -> Dict[str, str]:
    """Returns {scanner: 'run' | 'skipped:<reason>'}."""
    plan = {}
    for name in SCANNERS:
        if requested and name not in requested:
            plan[name] = "skipped:not requested"
        elif name == "osv-scanner" and not detected["has_dependencies"]:
            plan[name] = "skipped:no dependency manifests detected"
        elif name == "semgrep" and not detected["language_counts"] and "docker" not in detected["ecosystems"]:
            plan[name] = "skipped:no supported source files"
        else:
            plan[name] = "run"
    return plan


def run_scanners_on_path(root: str, plan: Dict[str, str]) -> List[ScannerOutcome]:
    """Synchronous; runs each scanner in its own private work dir. Used by scans and verification."""
    from concurrent.futures import ThreadPoolExecutor

    work_root = tempfile.mkdtemp(prefix="scanout-", dir=settings.WORK_DIR)
    try:
        def _one(name):
            wd = os.path.join(work_root, name)
            os.makedirs(wd, mode=0o700)
            try:
                return SCANNERS[name](root, wd)
            except Exception as e:  # noqa: BLE001
                logger.exception(f"scanner {name} crashed")
                return ScannerOutcome(name, "failed", error=f"{type(e).__name__}: {e}")

        to_run = [n for n, p in plan.items() if p == "run"]
        with ThreadPoolExecutor(max_workers=4) as ex:
            outcomes = list(ex.map(_one, to_run))
        for n, p in plan.items():
            if p != "run":
                outcomes.append(ScannerOutcome(n, "skipped", error=p.split(":", 1)[1]))
        return outcomes
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def _log(scan: Scan, msg: str, level: str = "info") -> None:
    scan.log = [*(scan.log or []), {"t": datetime.now(timezone.utc).isoformat(), "level": level, "msg": msg}]
    logger.log(level.upper(), f"[scan {scan.id}] {msg}")


async def run_scan(scan_id: str) -> None:
    sid = uuid.UUID(str(scan_id))
    async with database.async_session_maker() as db:
        scan = await db.get(Scan, sid)
        if not scan:
            return
        repo = await db.get(Repository, scan.repository_id)
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.now(timezone.utc)
        _log(scan, f"Scan started for {repo.full_name} ({scan.trigger})")
        await db.commit()

        try:
            token = None
            if repo.provider == "github":
                from app.integrations.github import token_for_repo

                token = await token_for_repo(db, repo)
            source = repo.extra.get("local_path") if repo.provider == "local" else repo.clone_url
            branch = scan.branch or repo.default_branch

            def _work():
                with snapshot.checkout(repo.provider, source, branch=branch, commit=scan.commit_sha if repo.provider != "local" else None, token=token) as snap:
                    detected = ecosystems.detect(snap.path)
                    plan = choose_scanners(detected, scan.scanners_requested or None)
                    outcomes = run_scanners_on_path(snap.path, plan)
                    return snap, detected, plan, outcomes

            snap, detected, plan, outcomes = await asyncio.to_thread(_work)
            _log(scan, f"Snapshot {snap.commit_sha[:12]} on {snap.branch}; ecosystems: {', '.join(detected['ecosystems']) or 'none'}")
            scan.commit_sha, scan.branch, scan.ecosystems = snap.commit_sha, snap.branch, detected["ecosystems"]
            repo.ecosystems = detected["ecosystems"]
            repo.language = repo.language or (detected["primary_language"] or "").capitalize() or None

            await _persist(db, scan, repo, outcomes, snap, detected)
        except snapshot.SnapshotError as e:
            scan.status, scan.error_message = ScanStatus.FAILED.value, str(e)
            _log(scan, f"Snapshot failed: {e}", "error")
        except Exception as e:  # noqa: BLE001
            logger.exception("scan failed")
            scan.status, scan.error_message = ScanStatus.FAILED.value, f"{type(e).__name__}: {e}"
            _log(scan, f"Scan failed: {e}", "error")
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()

    if scan.status in (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value):
        await _post_scan(scan.id)


async def _persist(db, scan: Scan, repo: Repository, outcomes: List[ScannerOutcome], snap, detected: Optional[Dict] = None) -> None:
    all_findings: List[NormalizedFinding] = []
    covered_types = set()
    for o in outcomes:
        db.add(ScannerExecution(
            scan_id=scan.id, scanner_name=o.name, scanner_version=o.version, status=o.status, command=o.command,
            duration_seconds=round(o.duration, 2), findings_count=len(o.findings), exit_code=o.exit_code,
            stderr_tail=o.stderr_tail[-2000:] if o.status != "completed" else None, error_message=o.error,
            started_at=scan.started_at, completed_at=datetime.now(timezone.utc),
        ))
        _log(scan, f"{o.name}: {o.status}" + (f" — {len(o.findings)} raw findings in {o.duration:.1f}s" if o.status == "completed" else f" — {o.error}"),
             "info" if o.status in ("completed", "skipped") else "warning")
        if o.status == "completed":
            all_findings.extend(o.findings)
            covered_types |= TYPE_BY_SCANNER[o.name]

    merged = dedupe(all_findings)
    _log(scan, f"Normalized {len(all_findings)} raw findings into {len(merged)} unique findings")
    now = datetime.now(timezone.utc)
    existing = {f.fingerprint: f for f in (await db.execute(select(Finding).where(Finding.repository_id == repo.id))).scalars()}
    seen = set()
    new_count = 0
    for nf in merged:
        fp = nf.fingerprint()
        seen.add(fp)
        f = existing.get(fp)
        fields = dict(
            scanner_name=nf.scanner, detected_by=nf.detected_by, finding_type=nf.finding_type, rule_id=nf.rule_id,
            title=nf.title[:500], description=nf.description, severity=nf.severity, vuln_id=nf.vuln_id, aliases=nf.aliases,
            cwe_ids=nf.cwe_ids, cvss_score=nf.cvss_score, file_path=nf.file_path, start_line=nf.start_line, end_line=nf.end_line,
            code_snippet=nf.code_snippet, package_name=nf.package_name, package_ecosystem=nf.package_ecosystem,
            installed_version=nf.installed_version, fixed_version=nf.fixed_version, references=nf.references, raw_data=nf.raw,
            commit_sha=snap.commit_sha, last_scan_id=scan.id, last_seen_at=now,
        )
        if f is None:
            db.add(Finding(organization_id=repo.organization_id, repository_id=repo.id, fingerprint=fp, first_scan_id=scan.id,
                           first_seen_at=now, status=FindingStatus.OPEN.value, is_demo=repo.is_demo, **fields))
            new_count += 1
        else:
            for k, v in fields.items():
                setattr(f, k, v)
            if f.status == FindingStatus.RESOLVED.value:
                f.status, f.resolved_at = FindingStatus.OPEN.value, None
                _log(scan, f"Regression: previously resolved finding reappeared: {f.title}", "warning")

    auto_resolved = 0
    for fp, f in existing.items():
        if fp not in seen and f.finding_type in covered_types and f.status in (FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value):
            f.status, f.resolved_at = FindingStatus.RESOLVED.value, now
            auto_resolved += 1
    if auto_resolved:
        _log(scan, f"{auto_resolved} previously open findings no longer detected — marked resolved")
    await db.flush()

    sev = {s: sum(1 for f in merged if f.severity == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    scan.total_findings, scan.new_findings = len(merged), new_count
    scan.critical_count, scan.high_count, scan.medium_count, scan.low_count = sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"]
    ran = [o for o in outcomes if o.status != "skipped"]
    if ran and all(o.status != "completed" for o in ran):
        scan.status, scan.error_message = ScanStatus.FAILED.value, "No scanner completed successfully"
    elif any(o.status != "completed" for o in ran):
        scan.status = ScanStatus.PARTIAL.value
    else:
        scan.status = ScanStatus.COMPLETED.value

    open_rows = (await db.execute(select(Finding.severity).where(Finding.repository_id == repo.id, Finding.status == FindingStatus.OPEN.value))).scalars().all()
    gap = coverage_gap(outcomes, detected)
    if gap:
        repo.security_score = None
        _log(scan, f"Score withheld: {gap}. Zero findings here does not mean the code is safe.", "warning")
    else:
        repo.security_score = posture_score(*(open_rows.count(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")))
    repo.last_scanned_at, repo.last_scanned_commit = now, snap.commit_sha
    if not (await db.execute(select(RepositoryCommit).where(RepositoryCommit.repository_id == repo.id, RepositoryCommit.sha == snap.commit_sha))).scalar_one_or_none():
        db.add(RepositoryCommit(repository_id=repo.id, sha=snap.commit_sha, branch=snap.branch, message=snap.message, author=snap.author))
    _log(scan, f"Scan {scan.status.lower()}: {len(merged)} findings ({new_count} new). Repository score {repo.security_score}")


async def _post_scan(scan_id: uuid.UUID) -> None:
    """Best-effort enrichment and optional auto-investigation; failures never fail the scan."""
    from app.intel.service import enrich_findings

    async with database.async_session_maker() as db:
        scan = await db.get(Scan, scan_id)
        try:
            n = await enrich_findings(db, scan.repository_id, only_scan=scan.id)
            _log(scan, f"Vulnerability intelligence enriched for {n} identifiers")
        except Exception as e:  # noqa: BLE001
            _log(scan, f"Intelligence enrichment failed: {e}", "warning")
        await db.commit()

        if scan.auto_investigate:
            from app.agents.service import create_investigation

            top = (await db.execute(
                select(Finding).where(Finding.last_scan_id == scan.id, Finding.status == FindingStatus.OPEN.value,
                                      Finding.severity.in_(["CRITICAL", "HIGH"])).order_by(Finding.cvss_score.desc().nullslast()).limit(3)
            )).scalars().all()
            for f in top:
                inv = await create_investigation(db, f, user_id=scan.triggered_by)
                _log(scan, f"Queued AI investigation {str(inv.id)[:8]} for: {f.title[:80]}")
            await db.commit()
