#!/usr/bin/env bash
# Installs pinned scanner releases into a bin directory.
# Every download is checked against the SHA-256 checksum file published with the release.
#
# Usage: scripts/install-scanners.sh [bin-dir]
#   Linux (CI runners): installs hadolint, trivy, actionlint, gitleaks and osv-scanner.
#   macOS: installs trivy and osv-scanner from their official prebuilt releases. Homebrew builds these two from
#          source on Intel Macs (no bottles), which takes gigabytes of disk. Install hadolint, actionlint and gitleaks
#          with Homebrew: brew install hadolint actionlint gitleaks
#   SCANNERS="trivy osv-scanner" limits the run to the listed scanners on either system.
set -euo pipefail

HADOLINT_VERSION="2.15.1"
TRIVY_VERSION="0.75.0"
ACTIONLINT_VERSION="1.7.12"
GITLEAKS_VERSION="8.30.1"
OSV_SCANNER_VERSION="2.6.0"

BIN_DIR="${1:-${RUNNER_TEMP:-/tmp}/mikeops-guard-bin}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$BIN_DIR"

OS="$(uname -s)"
case "$OS" in
  Linux) DEFAULT_SCANNERS="hadolint trivy actionlint gitleaks osv-scanner" ;;
  Darwin) DEFAULT_SCANNERS="trivy osv-scanner" ;;
  *) echo "Unsupported operating system: $OS (Linux and macOS are supported)" >&2; exit 1 ;;
esac
SCANNERS="${SCANNERS:-$DEFAULT_SCANNERS}"

case "$(uname -m)" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac

wanted() { [[ " $SCANNERS " == *" $1 "* ]]; }

linux_only() {
  if [[ "$OS" != "Linux" ]]; then
    echo "$1: not installed by this script on macOS. Use: brew install $1" >&2
    return 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{ print $1 }'
  else shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

# download <url> <checksums-url> <asset-name>: fails unless the file matches the published SHA-256
download() {
  local url="$1" sums_url="$2" asset="$3"
  curl -fsSL --retry 3 -o "$WORK_DIR/$asset" "$url"
  curl -fsSL --retry 3 -o "$WORK_DIR/$asset.sums" "$sums_url"
  local expected actual
  expected="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$WORK_DIR/$asset.sums")"
  if [[ -z "$expected" ]]; then
    echo "No checksum for $asset in $sums_url" >&2
    exit 1
  fi
  actual="$(sha256_of "$WORK_DIR/$asset")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Checksum mismatch for $asset: expected $expected, got $actual" >&2
    exit 1
  fi
  echo "  verified $asset (sha256 $expected)"
}

install_tarball_binary() {
  local asset="$1" binary="$2"
  tar -xzf "$WORK_DIR/$asset" -C "$WORK_DIR" "$binary"
  install -m 0755 "$WORK_DIR/$binary" "$BIN_DIR/$binary"
}

if wanted hadolint && linux_only hadolint; then
  [[ "$ARCH" == "amd64" ]] && HL_ARCH="x86_64" || HL_ARCH="arm64"
  asset="hadolint-linux-$HL_ARCH"
  base="https://github.com/hadolint/hadolint/releases/download/v$HADOLINT_VERSION"
  download "$base/$asset" "$base/checksums.sha256" "$asset"
  install -m 0755 "$WORK_DIR/$asset" "$BIN_DIR/hadolint"
fi

if wanted trivy; then
  if [[ "$OS" == "Darwin" ]]; then
    [[ "$ARCH" == "amd64" ]] && TV_ARCH="64bit" || TV_ARCH="ARM64"
    asset="trivy_${TRIVY_VERSION}_macOS-$TV_ARCH.tar.gz"
  else
    [[ "$ARCH" == "amd64" ]] && TV_ARCH="64bit" || TV_ARCH="ARM64"
    asset="trivy_${TRIVY_VERSION}_Linux-$TV_ARCH.tar.gz"
  fi
  base="https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION"
  download "$base/$asset" "$base/trivy_${TRIVY_VERSION}_checksums.txt" "$asset"
  install_tarball_binary "$asset" trivy
fi

if wanted actionlint && linux_only actionlint; then
  asset="actionlint_${ACTIONLINT_VERSION}_linux_$ARCH.tar.gz"
  base="https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VERSION"
  download "$base/$asset" "$base/actionlint_${ACTIONLINT_VERSION}_checksums.txt" "$asset"
  install_tarball_binary "$asset" actionlint
fi

if wanted gitleaks && linux_only gitleaks; then
  [[ "$ARCH" == "amd64" ]] && GL_ARCH="x64" || GL_ARCH="arm64"
  asset="gitleaks_${GITLEAKS_VERSION}_linux_$GL_ARCH.tar.gz"
  base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
  download "$base/$asset" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" "$asset"
  install_tarball_binary "$asset" gitleaks
fi

if wanted osv-scanner; then
  [[ "$OS" == "Darwin" ]] && OSV_OS="darwin" || OSV_OS="linux"
  asset="osv-scanner_${OSV_OS}_$ARCH"
  base="https://github.com/google/osv-scanner/releases/download/v$OSV_SCANNER_VERSION"
  download "$base/$asset" "$base/osv-scanner_SHA256SUMS" "$asset"
  install -m 0755 "$WORK_DIR/$asset" "$BIN_DIR/osv-scanner"
fi

echo "Installed scanners into $BIN_DIR"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$BIN_DIR" >> "$GITHUB_PATH"
fi
