"""Project ecosystem detection from manifest/lock files (no repository code is executed)."""

import os
from typing import Dict, List, Set

MANIFESTS: Dict[str, List[str]] = {
    "python": ["requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "uv.lock", "Pipfile"],
    "javascript": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"],
    "go": ["go.mod", "go.sum"],
    "ruby": ["Gemfile", "Gemfile.lock"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "php": ["composer.json", "composer.lock"],
    "dotnet": ["packages.lock.json"],
    "docker": ["Dockerfile"],
    "terraform": [],
}
# Every language Semgrep can parse. A source file missing here is silently left out of SAST, so err on adding.
SOURCE_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".vue": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".sc": "scala",
    ".go": "go", ".rb": "ruby", ".rs": "rust", ".php": "php", ".cs": "dotnet", ".swift": "swift",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".sh": "bash", ".bash": "bash", ".lua": "lua", ".ex": "elixir", ".exs": "elixir", ".sol": "solidity",
    ".dart": "dart", ".ml": "ocaml", ".mli": "ocaml", ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
    ".cls": "apex", ".trigger": "apex", ".r": "r", ".jl": "julia", ".hcl": "terraform",
    ".tf": "terraform",
}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "vendor", "target"}


def detect(root: str, max_files: int = 50_000) -> Dict[str, object]:
    ecosystems: Set[str] = set()
    manifests: List[str] = []
    lang_counts: Dict[str, int] = {}
    by_name = {m: eco for eco, ms in MANIFESTS.items() for m in ms}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            seen += 1
            if seen > max_files:
                break
            if f in by_name or f.endswith((".csproj",)):
                ecosystems.add(by_name.get(f, "dotnet"))
                manifests.append(os.path.relpath(os.path.join(dirpath, f), root))
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXT:
                lang = SOURCE_EXT[ext]
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
                if lang == "terraform":
                    ecosystems.add("terraform")
    primary = max(lang_counts, key=lang_counts.get) if lang_counts else None
    return {
        "ecosystems": sorted(ecosystems | set(lang_counts)),
        "manifests": sorted(manifests)[:200],
        "primary_language": primary,
        "language_counts": lang_counts,
        "has_dependencies": any(e in ecosystems for e in MANIFESTS if e not in ("docker", "terraform")),
    }
