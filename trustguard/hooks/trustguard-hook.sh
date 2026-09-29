#!/bin/sh
# Bootstrap for the TrustGuard GitHub Copilot plugin (macOS/Linux).
#
# GitHub Copilot invokes this script on each hook event. It executes trustguard-copilot
# from the PATH when present (manual/MDM installs win); otherwise it installs
# the pinned release for this OS/arch into ~/.trustguard/bin in the background,
# verifying its SHA-256 against the table below, and evaluates from the next
# event on. Every bootstrap failure fails open (GitHub Copilot must never brick) with a
# warning on stderr.
#
# The VERSION and SHA256_* table are updated per release.
set -u

VERSION="0.1.0"
EVENT="${1:-}"
BASE_URL="${TRUSTGUARD_COPILOT_DOWNLOAD_BASE:-https://github.com/NeuralTrust/trustguard-copilot-plugin/releases/download}"
BIN_DIR="${TRUSTGUARD_COPILOT_BIN_DIR:-$HOME/.trustguard/bin}"

# Per-platform SHA-256 of the release binaries (filled per release).
SHA256_darwin_amd64="8ec3228281f0e7a132c32d366371f291a54f84634bef9407770537d455984809"
SHA256_darwin_arm64="ce72322315e7294705acf7811550243b1237f9e4bd94154f2e50b7425bea3b95"
SHA256_linux_amd64="db4559d8f795f0cec61affbbff0750034512de80438d666b494e298334c56f04"
SHA256_linux_arm64="cc2c9f3c2d479763404ad36d7c4276bae43382163e0e782dfbef8fbee11c43d7"
SHA256_windows_amd64="38f35dd1fcc1167b8e062a0408c3f52f09728cfcc12d09ad82952be0ead36949"
SHA256_windows_arm64="3a35a476e3f628fafd8bdd6f4b49a327db5bd2c2e4bab1a09c60d1e2911e7858"

fail_open() {
    echo "trustguard-copilot bootstrap: $1 — allowing without evaluation" >&2
    # Empty allow: GitHub Copilot continues when stdout is empty / exit 0.
    # Never print {}: VS Code's Agent Host treats it as a final answer and
    # skips later hooks for the event (microsoft/vscode#338457).
    exit 0
}

run_hook() {
    "$1" hook "$EVENT" || fail_open "hook process failed"
    exit 0
}

EXT=""
case "$(uname -s)" in
    Darwin) OS="darwin" ;;
    Linux) OS="linux" ;;
    MINGW* | MSYS* | CYGWIN*) OS="windows" EXT=".exe" ;;
    *) OS="" ;;
esac

# MDM (Kandji) first — org binary must win over any developer PATH copy.
MDM_BIN="/Library/Application Support/TrustGuard/bin/trustguard-copilot$EXT"
if [ -x "$MDM_BIN" ]; then
    run_hook "$MDM_BIN"
fi

if command -v trustguard-copilot >/dev/null 2>&1; then
    run_hook "$(command -v trustguard-copilot)"
fi

# Local install (make install-local) drops an unversioned binary here.
LOCAL_BIN="$BIN_DIR/trustguard-copilot$EXT"
if [ -x "$LOCAL_BIN" ]; then
    run_hook "$LOCAL_BIN"
fi

BIN="$BIN_DIR/trustguard-copilot-$VERSION$EXT"
if [ -x "$BIN" ]; then
    run_hook "$BIN"
fi

if [ -z "$OS" ]; then
    fail_open "unsupported OS $(uname -s); install trustguard-copilot manually"
fi
case "$(uname -m)" in
    x86_64 | amd64) ARCH="amd64" ;;
    arm64 | aarch64) ARCH="arm64" ;;
    *) fail_open "unsupported arch $(uname -m); install trustguard-copilot manually" ;;
esac

WANT_SHA=$(eval "printf '%s' \"\${SHA256_${OS}_${ARCH}:-}\"")
if [ -z "$WANT_SHA" ]; then
    fail_open "no pinned checksum for ${OS}/${ARCH} (release ${VERSION} not published yet?); install trustguard-copilot manually"
fi

URL="$BASE_URL/v$VERSION/trustguard-copilot_${VERSION}_${OS}_${ARCH}${EXT}"
mkdir -p "$BIN_DIR" 2>/dev/null || fail_open "cannot create $BIN_DIR"

install_binary() {
    TMP="$BIN.download.$$"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 5 --max-time 300 -o "$TMP" "$URL" || { rm -f "$TMP"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 300 -O "$TMP" "$URL" || { rm -f "$TMP"; return 1; }
    else
        return 1
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        GOT_SHA=$(sha256sum "$TMP" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        GOT_SHA=$(shasum -a 256 "$TMP" | cut -d' ' -f1)
    else
        rm -f "$TMP"
        return 1
    fi
    if [ "$GOT_SHA" != "$WANT_SHA" ]; then
        rm -f "$TMP"
        return 1
    fi

    chmod 0755 "$TMP" || { rm -f "$TMP"; return 1; }
    mv -f "$TMP" "$BIN" || { rm -f "$TMP"; return 1; }
}

LOCK="$BIN_DIR/install-copilot-$VERSION.lock"
if [ -d "$LOCK" ] && [ -n "$(find "$LOCK" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then
    rmdir "$LOCK" 2>/dev/null || :
fi
if mkdir "$LOCK" 2>/dev/null; then
    ( install_binary; rmdir "$LOCK" 2>/dev/null ) >/dev/null 2>&1 &
fi
fail_open "trustguard-copilot $VERSION not installed yet; fetching it in the background"
