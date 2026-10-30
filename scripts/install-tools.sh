#!/usr/bin/env bash
# Installs native scanner binaries (Trivy, Gitleaks, OSV-Scanner) and uv into ./.tools/bin.
# Semgrep is installed into the backend virtualenv via pip (see backend/requirements.txt).
# Binaries are fetched from official GitHub releases for the current OS/CPU.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.tools/bin"
mkdir -p "$BIN"

UV_VERSION="${UV_VERSION:-0.13.6}"
TRIVY_VERSION="${TRIVY_VERSION:-0.76.1}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
OSV_VERSION="${OSV_VERSION:-2.7.0}"

os="$(uname -s)"; cpu="$(uname -m)"
case "$os-$cpu" in
  Darwin-x86_64) UV_T=x86_64-apple-darwin;  TRIVY_T=macOS-64bit;   GL_T=darwin_x64;   OSV_T=darwin_amd64 ;;
  Darwin-arm64)  UV_T=aarch64-apple-darwin; TRIVY_T=macOS-ARM64;   GL_T=darwin_arm64; OSV_T=darwin_arm64 ;;
  Linux-x86_64)  UV_T=x86_64-unknown-linux-gnu; TRIVY_T=Linux-64bit; GL_T=linux_x64;  OSV_T=linux_amd64 ;;
  Linux-aarch64) UV_T=aarch64-unknown-linux-gnu; TRIVY_T=Linux-ARM64; GL_T=linux_arm64; OSV_T=linux_arm64 ;;
  *) echo "Unsupported platform $os-$cpu" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

fetch_tar() { # url binary-name
  echo "→ $2"
  curl -fsSL "$1" -o "$tmp/a.tgz"
  mkdir -p "$tmp/x" && tar -xzf "$tmp/a.tgz" -C "$tmp/x"
  find "$tmp/x" -type f -name "$2" -exec install -m 0755 {} "$BIN/$2" \;
  rm -rf "$tmp/x" "$tmp/a.tgz"
}

[ -x "$BIN/uv" ] || fetch_tar "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$UV_T.tar.gz" uv
[ -x "$BIN/trivy" ] || fetch_tar "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_${TRIVY_T}.tar.gz" trivy
[ -x "$BIN/gitleaks" ] || fetch_tar "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_${GL_T}.tar.gz" gitleaks
if [ ! -x "$BIN/osv-scanner" ]; then
  echo "→ osv-scanner"
  curl -fsSL "https://github.com/google/osv-scanner/releases/download/v$OSV_VERSION/osv-scanner_$OSV_T" -o "$BIN/osv-scanner"
  chmod 0755 "$BIN/osv-scanner"
fi

# Semgrep (Python package) in an isolated uv tool environment. 1.182.1 is the last
# release with Intel macOS wheels; cryptography<46 keeps prebuilt wheels on Intel macs.
SEMGREP_VERSION="${SEMGREP_VERSION:-1.182.1}"
if [ ! -x "$BIN/semgrep" ]; then
  echo "→ semgrep"
  export UV_PYTHON_INSTALL_DIR="$ROOT/.tools/python" UV_TOOL_DIR="$ROOT/.tools/uv-tools" UV_TOOL_BIN_DIR="$BIN"
  echo 'cryptography<46' > "$tmp/constraints.txt"
  "$BIN/uv" tool install --python 3.12 --constraints "$tmp/constraints.txt" "semgrep==$SEMGREP_VERSION"
fi

echo "Installed into $BIN:"
for t in uv trivy gitleaks osv-scanner semgrep; do printf '  %-12s %s\n' "$t" "$("$BIN/$t" --version 2>/dev/null | tail -1)"; done
