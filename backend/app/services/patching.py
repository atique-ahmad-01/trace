"""
Patch generation: deterministic dependency-manifest upgrades and validated code replacements.
Produces unified diffs (a/ b/ paths) that verification applies with `git apply`.
"""

import difflib
import json
import os
import re
from typing import Any, Dict, Optional


def unified_diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), f"a/{path}", f"b/{path}"))


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def patch_requirements(text: str, pkg: str, target: str) -> Optional[str]:
    out, changed = [], False
    for line in text.splitlines(keepends=True):
        m = re.match(r"^(\s*)([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([^\s;#]*)(.*)$", line.rstrip("\n"))
        if m and _norm(m.group(2)) == _norm(pkg):
            op = "==" if (m.group(4) in (None, "==", "<=", "<")) else m.group(4)
            newline = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{op}{target}{m.group(6)}" + ("\n" if line.endswith("\n") else "")
            out.append(newline)
            changed = changed or newline != line
        else:
            out.append(line)
    return "".join(out) if changed else None


def patch_package_json(text: str, pkg: str, target: str) -> Optional[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    changed = False
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if pkg in deps:
            prefix = re.match(r"^[\^~]?", deps[pkg]).group(0)
            deps[pkg] = f"{prefix}{target}"
            changed = True
    if not changed:
        return None
    indent = 2 if re.search(r'^\{\n  "', text) else 4 if re.search(r'^\{\n    "', text) else 2
    return json.dumps(data, indent=indent) + ("\n" if text.endswith("\n") else "")


def patch_pyproject(text: str, pkg: str, target: str) -> Optional[str]:
    rx = re.compile(rf'(^|\n)(\s*"?{re.escape(pkg)}"?\s*=\s*")([^"]*)(")', re.I)
    new, n = rx.subn(lambda m: f"{m.group(1)}{m.group(2)}^{target}{m.group(4)}", text, count=1)
    if n:
        return new
    rx2 = re.compile(rf'("{re.escape(pkg)}\s*(?:\[[^\]]*\])?\s*)(==|>=|~=|\^)?\s*([0-9][^",;]*)', re.I)
    new, n = rx2.subn(lambda m: f"{m.group(1)}>={target}", text, count=1)
    return new if n else None


def patch_go_mod(text: str, pkg: str, target: str) -> Optional[str]:
    t = target if target.startswith("v") else f"v{target}"
    rx = re.compile(rf"(^|\n)(\s*{re.escape(pkg)}\s+)(v[^\s]+)")
    new, n = rx.subn(lambda m: f"{m.group(1)}{m.group(2)}{t}", text, count=1)
    return new if n else None


MANIFEST_PATCHERS = {
    "requirements": patch_requirements,
    "package.json": patch_package_json,
    "pyproject.toml": patch_pyproject,
    "go.mod": patch_go_mod,
}


def manifest_candidates(file_path: str) -> list:
    """The finding's file plus the editable manifest for lock files."""
    d, base = os.path.dirname(file_path or ""), os.path.basename(file_path or "")
    sibling = {"package-lock.json": "package.json", "yarn.lock": "package.json", "pnpm-lock.yaml": "package.json",
               "poetry.lock": "pyproject.toml", "uv.lock": "pyproject.toml", "go.sum": "go.mod"}
    out = [file_path] if file_path else []
    if base in sibling:
        out.insert(0, os.path.join(d, sibling[base]) if d else sibling[base])
    return out


def make_patch(finding: Dict[str, Any], target: Optional[str], files: Dict[str, str], replacement: Optional[str] = None) -> Dict[str, Any]:
    if replacement is not None:
        return _code_patch(finding, files, replacement)
    pkg = finding.get("package_name")
    for path in manifest_candidates(finding.get("file_path")):
        text = files.get(path)
        if text is None:
            continue
        base = os.path.basename(path)
        key = "requirements" if base.endswith(".txt") and "requirements" in base else base
        fn = MANIFEST_PATCHERS.get(key)
        if not fn:
            continue
        new = fn(text, pkg, target)
        if new and new != text:
            note = "Lock file must be regenerated (npm install / poetry lock / go mod tidy)." if path != finding.get("file_path") else None
            return {"diff": unified_diff(path, text, new), "files": [path], "note": note, "new_content": {path: new}}
    return {"diff": None, "files": [], "note": f"No supported manifest entry for {pkg} in {manifest_candidates(finding.get('file_path'))}"}


def _code_patch(finding: Dict[str, Any], files: Dict[str, str], replacement: str) -> Dict[str, Any]:
    path = finding.get("file_path")
    text = files.get(path)
    if text is None:
        return {"diff": None, "files": [], "note": "source file not available"}
    nums = [int(n) for n in re.findall(r"^\s*(\d+) \|", finding.get("code_snippet") or "", re.M)]
    if not nums:
        return {"diff": None, "files": [], "note": "snippet line range unknown"}
    lo, hi = min(nums), max(nums)
    lines = text.splitlines(keepends=True)
    if hi > len(lines):
        return {"diff": None, "files": [], "note": "snippet out of range (file changed)"}
    replacement = re.sub(r"^```\w*\n|```$", "", replacement.strip("\n")).rstrip() + "\n"
    replacement = "\n".join(re.sub(r"^\s*\d+ \| ", "", l) for l in replacement.splitlines()) + "\n"
    rep_lines = replacement.count("\n")
    if rep_lines == 0 or rep_lines > (hi - lo + 1) * 3 + 10:
        return {"diff": None, "files": [], "note": "replacement size implausible"}
    new = "".join(lines[: lo - 1]) + replacement + "".join(lines[hi:])
    if new == text:
        return {"diff": None, "files": [], "note": "replacement identical to original"}
    original = "".join(lines[lo - 1: hi])
    problem = structural_problem(path, original, replacement) or syntax_problem(path, new)
    if problem:
        return {"diff": None, "files": [], "note": f"model patch rejected: {problem}"}
    return {"diff": unified_diff(path, text, new), "files": [path], "note": None, "new_content": {path: new}}


_DEF_RE = re.compile(r"^\s*(@[\w.]+.*|(async\s+)?def\s+\w+|class\s+\w+|(export\s+)?(async\s+)?function\s+\w+)")


def structural_problem(path: str, original: str, replacement: str) -> Optional[str]:
    """A fix must not delete function/class definitions or decorators (e.g. routes) from the snippet."""
    kept = {l.strip() for l in replacement.splitlines()}
    for line in original.splitlines():
        m = _DEF_RE.match(line)
        if m:
            sig = re.split(r"[(:]", line.strip(), maxsplit=1)[0]
            if not any(k.startswith(sig) for k in kept):
                return f"removes definition '{line.strip()[:60]}'"
    return None


def syntax_problem(path: str, content: str) -> Optional[str]:
    """Parse-only check (never executes code). Python is parsed with ast; other files get a bracket-balance check."""
    if path.endswith(".py"):
        import ast

        try:
            ast.parse(content)
        except SyntaxError as e:
            return f"invalid Python syntax at line {e.lineno}: {e.msg}"
        return None
    if path.endswith((".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".c", ".cs", ".php")):
        stripped = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1|//[^\n]*|/\*.*?\*/", "", content, flags=re.S)
        pairs, stack = {")": "(", "]": "[", "}": "{"}, []
        for ch in stripped:
            if ch in "([{":
                stack.append(ch)
            elif ch in pairs:
                if not stack or stack.pop() != pairs[ch]:
                    return "unbalanced brackets"
        if stack:
            return "unbalanced brackets"
    return None
