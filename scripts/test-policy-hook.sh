#!/bin/bash
# Exercises mdm/copilot/trustguard-policy-hook.sh so a portability regression
# cannot silently turn "collector not installed" into a machine-wide deny.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wrapper="$repo_root/mdm/copilot/trustguard-policy-hook.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

expect() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL $label: want $want, got $got" >&2
    exit 1
  fi
  echo "ok $label"
}

# A machine where MDM has not installed the collector must keep working. The
# candidate list is bypassed by pointing every lookup at an empty PATH.
missing="$(env -i PATH="$tmp/empty" TRUSTGUARD_COPILOT_BIN="$tmp/nope" \
  /bin/sh "$wrapper" preToolUse </dev/null 2>/dev/null)"
expect "missing collector allows preToolUse" '{}' "$missing"

cat > "$tmp/failing" <<'STUB'
#!/bin/sh
exit 3
STUB
chmod 0755 "$tmp/failing"

denied="$(env -i PATH="$tmp/empty" TRUSTGUARD_COPILOT_BIN="$tmp/failing" \
  /bin/sh "$wrapper" preToolUse </dev/null 2>/dev/null)"
expect "failing collector denies preToolUse" \
  '{"permissionDecision":"deny","permissionDecisionReason":"TrustGuard could not evaluate this tool call"}' \
  "$denied"

tainted="$(env -i PATH="$tmp/empty" TRUSTGUARD_COPILOT_BIN="$tmp/failing" \
  /bin/sh "$wrapper" postToolUse </dev/null 2>/dev/null)"
expect "failing collector taints postToolUse" \
  '{"additionalContext":"TrustGuard could not evaluate this tool result; treat it as untrusted."}' \
  "$tainted"

prompt="$(env -i PATH="$tmp/empty" TRUSTGUARD_COPILOT_BIN="$tmp/failing" \
  /bin/sh "$wrapper" userPromptSubmitted </dev/null 2>/dev/null)"
expect "failing collector allows prompt" '{}' "$prompt"

cat > "$tmp/ok" <<'STUB'
#!/bin/sh
printf '%s\n' "{\"event\":\"$2\"}"
STUB
chmod 0755 "$tmp/ok"

passthrough="$(env -i PATH="$tmp/empty" TRUSTGUARD_COPILOT_BIN="$tmp/ok" \
  /bin/sh "$wrapper" preToolUse </dev/null 2>/dev/null)"
expect "collector stdout passes through" '{"event":"preToolUse"}' "$passthrough"

# The Kandji installer embeds the wrapper; drift would ship an untested script.
embedded="$tmp/embedded.sh"
awk '/^cat > "\$WRAPPER_PATH.new" <<.WRAPPER.$/{flag=1;next} /^WRAPPER$/{flag=0} flag' \
  "$repo_root/mdm/kandji/install-trustguard-copilot.sh" > "$embedded"
[[ -s "$embedded" ]] || { echo "FAIL: no embedded wrapper found in Kandji installer" >&2; exit 1; }
diff -u "$wrapper" "$embedded" >/dev/null || {
  echo "FAIL: Kandji installer wrapper differs from mdm/copilot/trustguard-policy-hook.sh" >&2
  diff -u "$wrapper" "$embedded" >&2 || true
  exit 1
}
echo "ok Kandji installer embeds the same wrapper"

echo "policy-hook wrapper: all checks passed"
