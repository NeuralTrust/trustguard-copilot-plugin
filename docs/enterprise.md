# Enterprise deployment

## Local Copilot CLI

Deploy three files per machine: the collector binary, the managed configuration,
and the policy hook file under `/etc/github-copilot/policy.d/` (on Windows,
`C:\ProgramData\GitHub\Copilot\policy.d\`). Policy hooks are loaded before user,
repository, and plugin hooks and cannot be disabled by `disableAllHooks`.

Paths differ per platform, so `mdm/copilot/policy-hooks.json` never calls the
collector directly on Unix. It calls the wrapper
`mdm/copilot/trustguard-policy-hook.sh`, installed at
`/usr/local/bin/trustguard-policy-hook` on both macOS and Linux, which resolves
the collector at runtime:

| Platform | Collector | Managed config |
|---|---|---|
| macOS | `/Library/Application Support/TrustGuard/bin/trustguard-copilot` | `/Library/Application Support/TrustGuard/copilot.json` |
| Linux | `/opt/trustguard/bin/trustguard-copilot` or `/usr/local/bin/trustguard-copilot` | `/etc/trustguard/copilot.json` |
| Windows | `%ProgramData%\TrustGuard\bin\trustguard-copilot.exe` | `%ProgramData%\TrustGuard\copilot.json` |

Set `TRUSTGUARD_COPILOT_BIN` to override the lookup for a non-standard image.

Because Copilot treats a non-zero `preToolUse` exit as a deny, the wrapper
distinguishes two failures on purpose: if the collector is **not installed** the
event is allowed, so a machine mid-provisioning is not bricked; if the collector
**is installed and fails**, the event is enforced (`deny` for `preToolUse`,
untrusted context for `postToolUse`). The Windows commands apply the same rule
with a `Test-Path` guard.

`make policy-hook-test` covers both branches.

## VS Code Agent mode

Install the TrustGuard plugin from the organization marketplace. Agent hooks
are currently a VS Code preview feature. Ensure the enterprise policy permits
hooks and controls marketplace sources.

## Cloud coding agent

Cloud jobs do not receive local MDM policy, user hooks, or installed plugins.
To cover them:

1. Commit a Copilot hook file under `.github/hooks/`.
2. Make the collector binary available in the job image, or use an HTTP hook
   endpoint that accepts Copilot's event payload.
3. Add the TrustGuard host to the cloud-agent firewall allowlist.
4. Provide credentials through the approved GitHub environment mechanism.

`preToolUse` fires in cloud jobs, but `ask` is treated as `deny` because no user
is present. `userPromptSubmitted` command-hook output is ignored, so it is
audit-only unless enforcement is implemented through the Copilot SDK.

## Coverage limits

- Agent prompts and tool calls: covered by hooks.
- Inline completions / ghost text: not exposed to hooks.
- Tool output can only be marked as untrusted after execution; `postToolUse`
  cannot undo the call.
