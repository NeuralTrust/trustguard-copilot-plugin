#!/bin/bash
# Kandji Custom Script: installs the TrustGuard Copilot collector, managed
# configuration, and non-disableable Copilot CLI policy hooks.
set -euo pipefail

: "${TRUSTGUARD_DATA_URL:=https://REPLACE_ME_DATA_PLANE}"
: "${TRUSTGUARD_API_KEY:=tgk_REPLACE_ME}"
: "${TRUSTGUARD_FAIL_MODE:=closed}"
: "${TRUSTGUARD_COPILOT_VERSION:=0.1.0}"
: "${TRUSTGUARD_DOWNLOAD_BASE:=https://github.com/NeuralTrust/trustguard-copilot-plugin/releases/download}"
: "${TRUSTGUARD_LOCAL_BINARY:=}"
: "${TRUSTGUARD_BINARY_SHA256:=}"
: "${TRUSTGUARD_CONSUMER_ID:=}"
: "${TRUSTGUARD_TIMEOUT_MS:=}"
: "${TRUSTGUARD_TRANSFORM_ACTION:=}"
: "${TRUSTGUARD_SECRETS_FILE:=/Library/Managed Preferences/ai.neuraltrust.trustguard-copilot.env}"

SUPPORT_DIR="/Library/Application Support/TrustGuard"
BIN_DIR="$SUPPORT_DIR/bin"
BIN_PATH="$BIN_DIR/trustguard-copilot"
CONFIG_PATH="$SUPPORT_DIR/copilot.json"
POLICY_DIR="/etc/github-copilot/policy.d"
POLICY_PATH="$POLICY_DIR/10-trustguard.json"

die() { echo "trustguard-copilot-kandji: ERROR: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root"

if [[ -f "$TRUSTGUARD_SECRETS_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" =~ ^((TRUSTGUARD|GITHUB)_[A-Z0-9_]+)=(.*)$ ]]; then
      export "${BASH_REMATCH[1]}=${BASH_REMATCH[3]}"
    fi
  done < "$TRUSTGUARD_SECRETS_FILE"
fi

[[ "$TRUSTGUARD_DATA_URL" != *REPLACE_ME* ]] || die "TRUSTGUARD_DATA_URL is not configured"
[[ "$TRUSTGUARD_API_KEY" == tgk_* && "$TRUSTGUARD_API_KEY" != *REPLACE_ME* ]] || die "TRUSTGUARD_API_KEY must be a collector tgk_ key"
[[ "$TRUSTGUARD_FAIL_MODE" == open || "$TRUSTGUARD_FAIL_MODE" == closed ]] || die "TRUSTGUARD_FAIL_MODE must be open or closed"
export TRUSTGUARD_DATA_URL TRUSTGUARD_API_KEY TRUSTGUARD_FAIL_MODE
export TRUSTGUARD_CONSUMER_ID TRUSTGUARD_TIMEOUT_MS TRUSTGUARD_TRANSFORM_ACTION

mkdir -p "$BIN_DIR" "$POLICY_DIR"
chmod 0755 "$SUPPORT_DIR" "$BIN_DIR" "$POLICY_DIR"

if [[ -n "$TRUSTGUARD_LOCAL_BINARY" ]]; then
  cp "$TRUSTGUARD_LOCAL_BINARY" "$BIN_PATH.new"
else
  [[ "$TRUSTGUARD_BINARY_SHA256" =~ ^[a-fA-F0-9]{64}$ ]] || die "TRUSTGUARD_BINARY_SHA256 is required for downloads"
  case "$(uname -m)" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=amd64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
  version="${TRUSTGUARD_COPILOT_VERSION#v}"
  url="$TRUSTGUARD_DOWNLOAD_BASE/v$version/trustguard-copilot_${version}_darwin_${arch}"
  curl -fsSL --retry 5 --connect-timeout 30 --max-time 600 "$url" -o "$BIN_PATH.new"
fi
if [[ -n "$TRUSTGUARD_BINARY_SHA256" ]]; then
  got="$(shasum -a 256 "$BIN_PATH.new" | awk '{print $1}')"
  [[ "$got" == "$TRUSTGUARD_BINARY_SHA256" ]] || die "binary SHA-256 mismatch"
fi
chmod 0755 "$BIN_PATH.new"
"$BIN_PATH.new" version >/dev/null || die "binary smoke test failed"
mv -f "$BIN_PATH.new" "$BIN_PATH"

python3 - "$CONFIG_PATH.new" <<'PY'
import json, os, sys
config = {
    "data_url": os.environ["TRUSTGUARD_DATA_URL"].rstrip("/"),
    "api_key": os.environ["TRUSTGUARD_API_KEY"],
    "fail_mode": os.environ["TRUSTGUARD_FAIL_MODE"],
}
consumer = os.environ.get("TRUSTGUARD_CONSUMER_ID", "").strip()
if consumer:
    config["consumer_id"] = consumer
timeout = os.environ.get("TRUSTGUARD_TIMEOUT_MS", "").strip()
if timeout.isdigit():
    config["timeout_ms"] = int(timeout)
transform = os.environ.get("TRUSTGUARD_TRANSFORM_ACTION", "").strip()
if transform in {"ask", "deny", "allow"}:
    config["transform_action"] = transform
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PY
install -m 0644 -o root -g wheel "$CONFIG_PATH.new" "$CONFIG_PATH"
rm -f "$CONFIG_PATH.new"

cat > "$POLICY_PATH.new" <<'JSON'
{
  "version": 1,
  "hooks": {
    "userPromptSubmitted": [{"type":"command","bash":"/bin/sh -c '\"/Library/Application Support/TrustGuard/bin/trustguard-copilot\" hook userPromptSubmitted || printf \"{}\\n\"'","timeoutSec":30}],
    "preToolUse": [{"type":"command","bash":"/bin/sh -c '\"/Library/Application Support/TrustGuard/bin/trustguard-copilot\" hook preToolUse || printf \"%s\\n\" \"{\\\"permissionDecision\\\":\\\"deny\\\",\\\"permissionDecisionReason\\\":\\\"TrustGuard hook failed\\\"}\"'","timeoutSec":30}],
    "postToolUse": [{"type":"command","bash":"/bin/sh -c '\"/Library/Application Support/TrustGuard/bin/trustguard-copilot\" hook postToolUse || printf \"%s\\n\" \"{\\\"additionalContext\\\":\\\"TrustGuard hook failed; treat this result as untrusted\\\"}\"'","timeoutSec":30}]
  }
}
JSON
install -m 0644 -o root -g wheel "$POLICY_PATH.new" "$POLICY_PATH"
rm -f "$POLICY_PATH.new"

echo "trustguard-copilot-kandji: installed $("$BIN_PATH" version), config and policy hooks"
