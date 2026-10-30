"""
Authorized repository snapshots.

Clones are shallow, hook-less and made into a private temp directory that is
always removed afterwards. Repository content is treated as untrusted: nothing
in it is executed, symlinks escaping the snapshot are removed, and size is capped.
"""

import base64
import hashlib
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

from app.core.config import BACKEND_DIR, settings
from app.scanners import runner

# Local-path repositories are restricted to these roots (fixtures for demo/tests).
LOCAL_REPO_ROOTS = [str(BACKEND_DIR / "tests" / "fixtures")]


class SnapshotError(Exception):
    pass


@dataclass
class Snapshot:
    path: str
    commit_sha: str
    branch: Optional[str]
    message: Optional[str] = None
    author: Optional[str] = None


def _git_env(token: Optional[str]) -> dict:
    env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        # Passed via env (not argv) so it never appears in process listings or logs.
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader", "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}"})
    return env


def _git(args, cwd=None, token=None, timeout=300):
    git = runner.resolve_tool(settings.GIT_PATH) or "git"
    base = [git, "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.symlinks=true"]
    return runner.run([*base, *args], cwd=cwd, extra_env=_git_env(token), timeout=timeout)


def _sanitize_tree(root: str) -> None:
    real_root = os.path.realpath(root)
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                target = os.path.realpath(p)
                if not target.startswith(real_root + os.sep):
                    os.unlink(p)
                continue
            if name in filenames:
                try:
                    st = os.lstat(p)
                    total += st.st_size
                    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        os.chmod(p, st.st_mode & ~(stat.S_ISUID | stat.S_ISGID))
                except OSError:
                    pass
        if total > settings.MAX_REPO_SIZE_MB * 1024 * 1024:
            raise SnapshotError(f"Repository exceeds MAX_REPO_SIZE_MB={settings.MAX_REPO_SIZE_MB}")


def _validate_clone_url(url: str) -> None:
    if not url.startswith("https://"):
        raise SnapshotError("Only https:// clone URLs are allowed")
    if any(c in url for c in (" ", "\n", "\t")) or url.startswith("https://-"):
        raise SnapshotError("Invalid clone URL")


def _content_hash(root: str) -> str:
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in sorted(os.walk(root)):
        dirnames.sort()
        for f in sorted(filenames):
            p = os.path.join(dirpath, f)
            h.update(os.path.relpath(p, root).encode())
            try:
                with open(p, "rb") as fh:
                    h.update(fh.read())
            except OSError:
                pass
    return h.hexdigest()[:40]


def _local_path_allowed(path: str) -> bool:
    real = os.path.realpath(path)
    return any(real == os.path.realpath(r) or real.startswith(os.path.realpath(r) + os.sep) for r in LOCAL_REPO_ROOTS)


@contextmanager
def checkout(provider: str, source: str, branch: Optional[str] = None, commit: Optional[str] = None, token: Optional[str] = None) -> Iterator[Snapshot]:
    os.makedirs(settings.WORK_DIR, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="snap-", dir=settings.WORK_DIR)
    os.chmod(tmp, 0o700)
    dest = os.path.join(tmp, "repo")
    try:
        if provider == "local":
            if not _local_path_allowed(source) or not os.path.isdir(source):
                raise SnapshotError("Local repository path is not in an allowed root")
            shutil.copytree(source, dest, symlinks=True, ignore=shutil.ignore_patterns(".git", "node_modules", ".venv"))
            _sanitize_tree(dest)
            yield Snapshot(path=dest, commit_sha=f"local-{_content_hash(dest)}", branch=branch or "local")
            return

        _validate_clone_url(source)
        args = ["clone", "--depth", "1", "--no-tags", "--single-branch", "--filter=blob:limit=5m"]
        if branch and not commit:
            args += ["--branch", branch]
        args += ["--", source, dest]
        res = _git(args, token=token)
        if res.exit_code != 0:
            raise SnapshotError(f"git clone failed: {res.stderr.strip()[-400:]}")
        if commit:
            res = _git(["fetch", "--depth", "1", "origin", commit], cwd=dest, token=token)
            if res.exit_code != 0:
                raise SnapshotError(f"git fetch {commit} failed: {res.stderr.strip()[-300:]}")
            _git(["checkout", "--quiet", "FETCH_HEAD"], cwd=dest)
        info = _git(["log", "-1", "--format=%H%x00%s%x00%an"], cwd=dest).stdout.strip().split("\x00")
        cur_branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dest).stdout.strip()
        shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)
        _sanitize_tree(dest)
        yield Snapshot(
            path=dest,
            commit_sha=info[0] if info and info[0] else (commit or "unknown"),
            branch=branch or (cur_branch if cur_branch != "HEAD" else None),
            message=info[1] if len(info) > 1 else None,
            author=info[2] if len(info) > 2 else None,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
