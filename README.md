# lanlock

Keep selected internal domains on `DIRECT` in a ClashTUI-managed Mihomo setup.

For each domain, mihomo-internal keeps these two entries in sync:

- a `DOMAIN-SUFFIX,...,DIRECT` rule
- a `+.domain` entry in `dns.fake-ip-filter`

It can regenerate the Mihomo config through ClashTUI and check the route that
Mihomo actually used.

## Install

Python 3.10 or newer is required. Install into an isolated environment:
distribution Pythons reject a system-wide `pip install` with
`externally-managed-environment`.

With [uv](https://docs.astral.sh/uv/):

```bash
uv tool install "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

Or with pipx:

```bash
pipx install "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

Or into a virtual environment:

```bash
python -m venv ~/.venvs/lanlock
~/.venvs/lanlock/bin/pip install "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

From a local clone (editable):

```bash
git clone https://github.com/moevis/lanlock.git
cd lanlock
python -m venv .venv
.venv/bin/pip install -e ".[tui]"
```

All forms install the `mihomo-internal` and `mihomo-tui` commands; drop
`[tui]` to skip the terminal UI.

## Update

```bash
uv tool install --force --refresh "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
# or
pipx install --force "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

Virtual environment or local clone:

```bash
~/.venvs/lanlock/bin/pip install --upgrade --force-reinstall \
  "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"

cd lanlock && git pull
.venv/bin/pip install -e ".[tui]"   # non-editable: --force-reinstall ".[tui]"
```

For uv, `--refresh` checks GitHub for the latest commit and `--force`
reinstalls the tool even if the package version is unchanged.
Check the installed version with

```bash
mihomo-internal --version
```

## Before You Start

Use an existing ClashTUI Mihomo profile. Mihomo must be running with its
controller enabled. Applying changes also requires the `clashtui` command on
`PATH`.

On macOS, the default is `~/.config/clashtui/mihomo`, with a fallback to
`$XDG_CONFIG_HOME/clashtui/mihomo` if only that directory has an override.
For a portable ClashTUI install, lanlock uses `data/mihomo` next to the
ClashTUI executable.

For a custom setup, pass ClashTUI’s `mihomo` subdirectory, which contains
`core_override_config.yaml`.

```bash
mihomo-tui --config-dir "/path/to/clashtui/mihomo"
```

If the override file is missing, start ClashTUI once with the Mihomo core.
When adding domains, the override must contain the profile's `rules` and `dns`
sections. ClashTUI replaces these top-level sections when it merges the
override, so copy them from the active profile first if they are missing.

## Commands

```bash
mihomo-internal ls
mihomo-internal add corp.example
mihomo-internal rm corp.example
mihomo-internal sync
mihomo-internal check
mihomo-internal tui
```

`add`, `rm`, and `sync` save the override, keep one `.bak` backup, and apply
the change through ClashTUI. Use `--no-apply` to edit the file only:

```bash
mihomo-internal add --no-apply corp.example
mihomo-internal sync --no-apply
```

`mihomo-internal tui` and `mihomo-tui` are equivalent. The TUI requires the `tui`
extra.

Useful global options:

```text
--config-dir PATH    ClashTUI's mihomo directory
--api URL            Mihomo controller, default http://127.0.0.1:9090
--profile NAME       use this ClashTUI profile
```

If the controller requires authentication, set:

```bash
export LANLOCK_API_SECRET=...
```
