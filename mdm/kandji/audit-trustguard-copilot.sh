#!/bin/bash
# Kandji Audit Script for the TrustGuard Copilot deployment.
set -euo pipefail

binary="/Library/Application Support/TrustGuard/bin/trustguard-copilot"
config="/Library/Application Support/TrustGuard/copilot.json"
policy="/etc/github-copilot/policy.d/10-trustguard.json"

[[ -x "$binary" ]] || { echo "missing binary: $binary"; exit 1; }
[[ -f "$config" ]] || { echo "missing config: $config"; exit 1; }
[[ -f "$policy" ]] || { echo "missing policy hooks: $policy"; exit 1; }

python3 - "$config" "$policy" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
policy = json.load(open(sys.argv[2]))
assert config.get("api_key", "").startswith("tgk_")
assert config.get("data_url")
assert config.get("fail_mode") in {"open", "closed"}
assert policy.get("version") == 1
assert set(policy.get("hooks", {})) >= {"userPromptSubmitted", "preToolUse", "postToolUse"}
PY

echo "trustguard-copilot audit ok: $("$binary" version)"
