"""
Safe subprocess execution for scanners and git.

- argv lists only (never a shell), no interpolation of untrusted strings into a shell
- minimal environment (application secrets are never inherited)
- wall-clock timeout with process-group kill
- CPU-time / file-size / open-file / data-memory limits via setrlimit (POSIX)
"""

import os
import resource
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from app.core.config import settings

_ALLOWED_ENV = {"HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"}


@dataclass
class ProcResult:
    argv: List[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


def resolve_tool(name_or_path: str) -> Optional[str]:
    """Locate a binary: explicit path, then TOOLS_DIR, then PATH."""
    if os.path.isabs(name_or_path):
        return name_or_path if os.access(name_or_path, os.X_OK) else None
    candidate = os.path.join(settings.TOOLS_DIR, name_or_path)
    if os.access(candidate, os.X_OK):
        return candidate
    return shutil.which(name_or_path)


def _limits():
    os.setsid()
    cpu = settings.SCANNER_TIMEOUT + 60
    for res, val in (
        (resource.RLIMIT_CPU, cpu),
        (resource.RLIMIT_FSIZE, 2 * 1024**3),
        (resource.RLIMIT_NOFILE, 4096),
        (resource.RLIMIT_CORE, 0),
    ):
        try:
            soft, hard = resource.getrlimit(res)
            new = val if hard == resource.RLIM_INFINITY else min(val, hard)
            resource.setrlimit(res, (new, hard))
        except (ValueError, OSError):
            pass
    # RLIMIT_DATA, not RLIMIT_AS: Go (wazero in gitleaks) and OCaml (semgrep) runtimes reserve far more
    # address space than they use and crash at startup under an address-space cap. Not enforced on macOS.
    try:
        mem = settings.SCANNER_MEMORY_LIMIT_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_DATA, (mem, mem))
    except (ValueError, OSError):
        pass


def run(
    argv: List[str],
    *,
    cwd: Optional[str] = None,
    timeout: Optional[int] = None,
    extra_env: Optional[Dict[str, str]] = None,
    max_output: int = 50 * 1024 * 1024,
) -> ProcResult:
    env = {k: v for k, v in os.environ.items() if k in _ALLOWED_ENV}
    env["PATH"] = os.pathsep.join([settings.TOOLS_DIR, "/usr/bin", "/bin", "/usr/local/bin"])
    env["GIT_TERMINAL_PROMPT"] = "0"
    if extra_env:
        env.update(extra_env)
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=_limits,
        shell=False,
    )
    try:
        out, err = proc.communicate(timeout=timeout or settings.SCANNER_TIMEOUT)
        timed_out = False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        timed_out = True
    return ProcResult(
        argv=argv,
        exit_code=None if timed_out else proc.returncode,
        stdout=out[:max_output].decode("utf-8", "replace"),
        stderr=err[-200_000:].decode("utf-8", "replace"),
        duration=time.monotonic() - start,
        timed_out=timed_out,
    )
