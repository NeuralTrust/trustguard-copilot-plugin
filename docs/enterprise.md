# Enterprise deployment

## Local Copilot CLI

Deploy the binary, `/Library/Application Support/TrustGuard/copilot.json`, and
the policy file under `/etc/github-copilot/policy.d/`. Policy hooks are loaded
before user, repository, and plugin hooks and cannot be disabled by
`disableAllHooks`.

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
