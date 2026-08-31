# Kandji deployment

Deploy `install-trustguard-copilot.sh` as a root Custom Script. Configure the
collector values in Kandji or in a root-owned secrets file based on
`secrets.env.example`.

The script installs the collector binary and config, the
`/usr/local/bin/trustguard-policy-hook` wrapper, and Copilot CLI policy hooks.
Run `audit-trustguard-copilot.sh` as the Library Item audit script.

Recommended settings:

- Execution: daily, so version pins and configuration drift are repaired.
- `TRUSTGUARD_COPILOT_VERSION`: pin the approved release.
- `TRUSTGUARD_BINARY_SHA256`: required SHA-256 for that release and Mac
  architecture (not required when using a pre-staged local binary).
- `TRUSTGUARD_FAIL_MODE`: use `open` while piloting; move to `closed` only after
  data-plane availability and latency are established.
- Keep the `tgk_` collector key in Kandji secrets, never in this repository.

Policy hooks are installed at `/etc/github-copilot/policy.d/10-trustguard.json`
and invoke `/usr/local/bin/trustguard-policy-hook`, whose body is embedded in the
installer and kept in sync with `mdm/copilot/trustguard-policy-hook.sh` by CI.
They protect Copilot CLI. VS Code discovers plugin/workspace hooks separately;
use enterprise VS Code policy to prevent users from disabling hooks.
