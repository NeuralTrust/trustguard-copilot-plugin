# TrustGuard for GitHub Copilot

TrustGuard evaluates GitHub Copilot agent lifecycle events before they continue.
It supports Copilot CLI and Copilot Agent mode in VS Code. Inline code
completions do not expose hooks and are outside this plugin's scope.

## Events

| Copilot hook | TrustGuard evaluation | Control |
| --- | --- | --- |
| `userPromptSubmitted` | LLM input | Audit/evaluate; Copilot discards command-hook output |
| `preToolUse` | Shell input or MCP `tools/call` | `allow`, `ask`, or `deny` |
| `postToolUse` | MCP-style tool result | Marks blocked/sensitive output as untrusted context |

The complete hook stdin JSON is preserved in `attributes.copilot`. The source is
stamped as `attributes.source.application=copilot-plugin`. `consumer_id` is
sent only when configured explicitly.

## Install as a plugin

The distributable plugin lives in [`trustguard/`](./trustguard):

```bash
copilot plugin marketplace add NeuralTrust/trustguard-copilot-plugin
copilot plugin install trustguard@neuraltrust
```

For local development:

```bash
make install-local
copilot plugin install ./trustguard
```

Create `~/.trustguard/copilot.json`:

```json
{
  "data_url": "https://your-trustguard-data-plane",
  "api_key": "tgk_REPLACE_ME",
  "fail_mode": "open"
}
```

Environment variables override user configuration:

- `TRUSTGUARD_DATA_URL`
- `TRUSTGUARD_API_KEY`
- `TRUSTGUARD_FAIL_MODE` (`open` or `closed`)
- `TRUSTGUARD_TIMEOUT_MS`
- `TRUSTGUARD_TRANSFORM_ACTION` (`ask`, `deny`, or `allow`)
- `TRUSTGUARD_CONSUMER_ID`

## Enterprise deployment

The Kandji scripts under [`mdm/kandji/`](./mdm/kandji) install:

- `/Library/Application Support/TrustGuard/bin/trustguard-copilot`
- `/Library/Application Support/TrustGuard/copilot.json`
- `/etc/github-copilot/policy.d/10-trustguard.json`

Copilot CLI policy hooks are machine-wide, load before other hooks, and cannot
be disabled by repository settings. VS Code hooks are currently preview and can
be governed by VS Code enterprise policy.

Copilot cloud coding-agent jobs only load hooks committed under
`.github/hooks/*.json`; they do not receive local plugins, user hooks, MDM
files, or policy hooks. Reaching TrustGuard from cloud also requires an
administrator firewall allow rule.

## Failure behavior

The marketplace bootstrap exits successfully after emitting `{}` when
installation or execution fails. This prevents an incomplete personal install
from bricking Copilot, whose `preToolUse` command hooks fail closed on non-zero
exits. Enterprise policy hooks deny `preToolUse` and mark `postToolUse` output
as untrusted if the collector process itself fails. TrustGuard's configured
`fail_mode` controls normal data-plane errors returned by the collector.

## Development

```bash
make test
make lint
make build
make dist VERSION=0.1.0
```

Releases use the same prepare/publish state machine as the other TrustGuard IDE
plugins: merging a release pin PR triggers tag and GitHub Release publication.
