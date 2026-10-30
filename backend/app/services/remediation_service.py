"""
Remediation workflow: human approval, verification agent, GitHub pull requests.

Rules enforced here:
- Nothing is applied or opened as a PR without an explicit approval record.
- Proposals with insufficient evidence cannot be approved for application (guidance only).
- Verification applies the patch to an isolated snapshot, re-runs the relevant scanners
  before and after, and only passes when the target finding disappears without new
  HIGH/CRITICAL regressions. Repository tests are NOT executed (TRACE never runs
  repository code); that is reported explicitly and left to the PR's CI.
- PRs are never merged automatically.
"""

import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from loguru import logger

from app.core import database
from app.core.config import settings
from app.db.models import Finding, RemediationProposal, Repository, VerificationRun
from app.scanners import runner
from app.scanners.normalize import dedupe
from app.services import snapshot
from app.services.scan_service import run_scanners_on_path

SCANNERS_FOR_TYPE = {"dependency": ["osv-scanner", "trivy"], "sast": ["semgrep"], "secret": ["gitleaks", "semgrep"], "misconfig": ["trivy"]}


class RemediationError(Exception):
    pass


def _validate_patch_paths(patch: str, allowed: List[str]) -> None:
    for line in patch.splitlines():
        if line.startswith(("--- ", "+++ ")):
            path = line[4:].strip()
            if path == "/dev/null":
                continue
            path = path[2:] if path[:2] in ("a/", "b/") else path
            if ".." in path.split("/") or path.startswith("/") or (allowed and path not in allowed):
                raise RemediationError(f"patch touches disallowed path: {path}")


def apply_patch(root: str, patch: str) -> tuple[bool, str]:
    pfile = os.path.join(os.path.dirname(root), "trace.patch")
    with open(pfile, "w") as fh:
        fh.write(patch)
    git = runner.resolve_tool(settings.GIT_PATH) or "git"
    chk = runner.run([git, "apply", "--check", "--whitespace=nowarn", pfile], cwd=root, timeout=60)
    if chk.exit_code != 0:
        return False, chk.stderr.strip()[-500:]
    res = runner.run([git, "apply", "--whitespace=nowarn", pfile], cwd=root, timeout=60)
    return res.exit_code == 0, res.stderr.strip()[-500:]


async def run_verification(run_id: str) -> None:
    rid = uuid.UUID(str(run_id))
    async with database.async_session_maker() as db:
        vr = await db.get(VerificationRun, rid)
        prop = await db.get(RemediationProposal, vr.proposal_id)
        finding = await db.get(Finding, prop.finding_id)
        repo = await db.get(Repository, finding.repository_id)
        vr.status = "running"
        await db.commit()
        token = None
        if repo.provider == "github":
            from app.integrations.github import token_for_repo

            token = await token_for_repo(db, repo)

    steps: List[Dict[str, Any]] = []
    scanners = SCANNERS_FOR_TYPE.get(finding.finding_type, ["semgrep"])

    def _work():
        source = (repo.extra or {}).get("local_path") if repo.provider == "local" else repo.clone_url
        commit = prop.base_commit if repo.provider != "local" and prop.base_commit and not prop.base_commit.startswith("local-") else None
        with snapshot.checkout(repo.provider, source, branch=repo.default_branch, commit=commit, token=token) as snap:
            steps.append({"step": "snapshot", "detail": snap.commit_sha})
            plan = {n: ("run" if n in scanners else "skipped:not relevant") for n in ("trivy", "osv-scanner", "semgrep", "gitleaks")}
            before = run_scanners_on_path(snap.path, plan)
            steps.append({"step": "scan_before", "detail": {o.name: o.status for o in before if o.status != "skipped"}})
            applied, msg = apply_patch(snap.path, prop.patch)
            steps.append({"step": "apply_patch", "ok": applied, "detail": msg or "applied cleanly"})
            if not applied:
                return before, None, applied
            from app.services.patching import syntax_problem

            for rel in prop.files_changed or []:
                with open(os.path.join(snap.path, rel), "r", encoding="utf-8", errors="replace") as fh:
                    problem = syntax_problem(rel, fh.read())
                steps.append({"step": "syntax_check", "file": rel, "ok": problem is None, "detail": problem or "parses"})
                if problem:
                    return before, None, True  # applied, but the result does not parse
            after = run_scanners_on_path(snap.path, plan)
            steps.append({"step": "scan_after", "detail": {o.name: o.status for o in after if o.status != "skipped"}})
            return before, after, applied

    try:
        if not prop.patch:
            raise RemediationError("proposal has no patch to verify")
        _validate_patch_paths(prop.patch, prop.files_changed or [])
        before, after, applied = await asyncio.to_thread(_work)
        fps_before = {f.fingerprint(): f for o in before if o.status == "completed" for f in dedupe(list(o.findings))}
        incomplete = [o.name for o in (before + (after or [])) if o.status not in ("completed", "skipped")]
        async with database.async_session_maker() as db:
            vr = await db.get(VerificationRun, rid)
            prop = await db.get(RemediationProposal, vr.proposal_id)
            vr.patch_applied, vr.scanners = applied, scanners
            vr.target_finding_present_before = finding.fingerprint in fps_before
            vr.findings_before = len(fps_before)
            if after is not None:
                fps_after = {f.fingerprint(): f for o in after if o.status == "completed" for f in dedupe(list(o.findings))}
                vr.findings_after = len(fps_after)
                vr.target_finding_present_after = finding.fingerprint in fps_after
                new = [fps_after[k] for k in fps_after.keys() - fps_before.keys()]
                vr.new_findings = [{"title": f.title, "severity": f.severity, "file": f.file_path, "id": f.vuln_id or f.rule_id} for f in new][:50]
                vr.resolved_findings = [{"title": f.title, "severity": f.severity, "id": f.vuln_id or f.rule_id}
                                        for k, f in fps_before.items() if k not in fps_after][:50]
                regressions = [f for f in new if f.severity in ("CRITICAL", "HIGH")]
                passed = (vr.target_finding_present_before and not vr.target_finding_present_after and not regressions and not incomplete)
                reasons = []
                if not vr.target_finding_present_before:
                    reasons.append("target finding not reproduced before patch (cannot attribute fix)")
                if vr.target_finding_present_after:
                    reasons.append("target finding still detected after patch")
                if regressions:
                    reasons.append(f"{len(regressions)} new HIGH/CRITICAL findings introduced")
                if incomplete:
                    reasons.append(f"scanners incomplete: {', '.join(incomplete)}")
            else:
                bad = [st for st in steps if st.get("step") == "syntax_check" and not st["ok"]]
                reasons = [f"patched file fails syntax check: {bad[0]['file']}: {bad[0]['detail']}"] if bad else ["patch did not apply cleanly to the base snapshot"]
                passed = False
            vr.status = "passed" if passed else "failed"
            vr.details = {"steps": steps, "reasons": reasons,
                          "tests": "not executed — TRACE never runs repository code; rely on CI checks on the pull request"}
            vr.completed_at = datetime.now(timezone.utc)
            if prop.status not in ("pr_opened",):
                prop.status = "verified" if passed else "verification_failed"
            await db.commit()
    except Exception as e:  # noqa: BLE001
        logger.exception("verification failed")
        async with database.async_session_maker() as db:
            vr = await db.get(VerificationRun, rid)
            vr.status, vr.error_message, vr.details = "error", f"{type(e).__name__}: {e}"[:1000], {"steps": steps}
            vr.completed_at = datetime.now(timezone.utc)
            await db.commit()


async def open_pull_request(db, prop: RemediationProposal, user) -> Dict[str, Any]:
    from app.integrations import github

    finding = await db.get(Finding, prop.finding_id)
    repo = await db.get(Repository, finding.repository_id)
    if repo.provider != "github" or not repo.full_name:
        raise RemediationError("Pull requests require a GitHub-connected repository")
    if prop.status not in ("approved", "verified"):
        raise RemediationError("Proposal must be approved (and ideally verified) before opening a PR")
    if not prop.patch:
        raise RemediationError("Proposal has no patch")
    token = await github.token_for_repo(db, repo)
    if not token:
        raise RemediationError("No GitHub credential with write access is configured")
    _validate_patch_paths(prop.patch, prop.files_changed or [])
    base_sha = prop.base_commit
    if not base_sha or base_sha.startswith("local-"):
        branches = await github.list_branches(repo.full_name, token)
        base_sha = next((b["sha"] for b in branches if b["name"] == repo.default_branch), None)

    def _patched_files():
        with snapshot.checkout("github", repo.clone_url, branch=repo.default_branch, commit=base_sha, token=token) as snap:
            ok, msg = apply_patch(snap.path, prop.patch)
            if not ok:
                raise RemediationError(f"patch does not apply to {base_sha[:12]}: {msg}")
            out = {}
            for rel in prop.files_changed:
                with open(os.path.join(snap.path, rel), "r", encoding="utf-8") as fh:
                    out[rel] = fh.read()
            return out

    files = await asyncio.to_thread(_patched_files)
    branch = f"{settings.REMEDIATION_PR_BRANCH_PREFIX}{str(prop.id)[:8]}"
    body = (f"## TRACE remediation\n\n**Finding:** {finding.title}\n**Identifier:** {finding.vuln_id or finding.rule_id}\n"
            f"**Severity:** {finding.severity}\n\n### Root cause\n{prop.root_cause or 'n/a'}\n\n### Changes\n{prop.description or ''}\n\n"
            f"### Side effects\n{prop.side_effects or 'n/a'}\n\nApproved in TRACE by {user.email}. Verification status: {prop.status}.\n"
            "This PR was opened after explicit human approval and will not be merged automatically.")
    pr = await github.create_pull_request(repo.full_name, token, repo.default_branch, branch, prop.title[:200], body, files, base_sha)
    prop.pr_number, prop.pr_url, prop.branch_name, prop.status = pr["number"], pr["html_url"], branch, "pr_opened"
    return {"pr_number": pr["number"], "pr_url": pr["html_url"]}
