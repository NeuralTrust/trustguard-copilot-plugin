#!/bin/sh
# Policy-hook wrapper for Copilot CLI on macOS and Linux.
#
# Copilot preToolUse command hooks fail closed on a non-zero exit, so this
# wrapper always exits 0 and answers on stdout instead. It also separates two
# cases an administrator must not confuse:
#
#   collector not installed -> allow, so a machine that MDM has not finished
#                              provisioning keeps working
#   collector failed        -> enforce, because the org policy is in place and
#                              the evaluation could not be completed
set -u

EVENT="${1:-}"

allow() {
    printf '{}\n'
    exit 0
}

enforce() {
    case "$EVENT" in
        preToolUse)
            printf '%s\n' '{"permissionDecision":"deny","permissionDecisionReason":"TrustGuard could not evaluate this tool call"}'
            ;;
        postToolUse)
            printf '%s\n' '{"additionalContext":"TrustGuard could not evaluate this tool result; treat it as untrusted."}'
            ;;
        *)
            # userPromptSubmitted output is discarded by Copilot anyway.
            printf '{}\n'
            ;;
    esac
    exit 0
}

BIN=""
for candidate in \
    "${TRUSTGUARD_COPILOT_BIN:-}" \
    "/Library/Application Support/TrustGuard/bin/trustguard-copilot" \
    "/opt/trustguard/bin/trustguard-copilot" \
    "/usr/local/bin/trustguard-copilot"
do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        BIN="$candidate"
        break
    fi
done
if [ -z "$BIN" ]; then
    BIN="$(command -v trustguard-copilot 2>/dev/null || true)"
fi

if [ -z "$BIN" ]; then
    echo "trustguard-policy-hook: collector not installed; allowing $EVENT" >&2
    allow
fi

"$BIN" hook "$EVENT" || enforce
exit 0
