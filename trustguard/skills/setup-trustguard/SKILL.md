---
name: setup-trustguard
description: Verify and configure TrustGuard lifecycle hooks for GitHub Copilot CLI and VS Code Agent mode.
---

# Set up TrustGuard for GitHub Copilot

1. Verify `trustguard-copilot version` succeeds.
2. Verify `~/.trustguard/copilot.json` exists for local installs, or that the
   enterprise file exists at the platform TrustGuard support path.
3. Confirm the plugin is enabled and `hooks.json` registers
   `userPromptSubmitted`, `preToolUse`, and `postToolUse`.
4. Trigger a harmless prompt and tool call, then confirm both evaluations in
   TrustGuard with `attributes.source.application=copilot-plugin`.
5. Never print or copy the collector API key.

For enterprise Copilot CLI deployments, verify the administrator policy hook
file exists under `/etc/github-copilot/policy.d/` on macOS/Linux or
`C:\ProgramData\GitHub\Copilot\policy.d\` on Windows.

Cloud coding-agent jobs require repository hooks and a firewall rule for the
TrustGuard host; local MDM files are not available there.
