# lanlock

Keep selected internal domains on `DIRECT` in a ClashTUI- or FlClash-managed
Mihomo setup.

For each domain, lanlock keeps these entries in sync:

- a `DOMAIN-SUFFIX,...,DIRECT` rule
- a `+.domain` entry in `dns.fake-ip-filter`
- in a FlClash profile, a `+.domain` entry in `dns.nameserver-policy`

It regenerates the config through ClashTUI, saves a FlClash profile for the
next core start, and checks the route that Mihomo actually used.

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

All forms install the `lanlock` and `lanlock-tui` commands; drop `[tui]` to
skip the terminal UI.

## Update

```bash
uv tool install --force --refresh "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
# or
pipx install --force "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

For the first update after the command rename, run `pipx uninstall lanlock`
before the install: older pipx keeps the retired `mihomo-*` launchers.

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
lanlock --version
```

## Before You Start

Two setups are supported: ClashTUI and FlClash. `lanlock ls` prints
which one was resolved; when both are installed, pass
`--backend clashtui|flclash` (or `--config-dir`).

With ClashTUI, use an existing Mihomo profile. Mihomo must be running with its
controller enabled. Applying changes also requires the `clashtui` command on
`PATH`.

On macOS, the default is `~/.config/clashtui/mihomo`, with a fallback to
`$XDG_CONFIG_HOME/clashtui/mihomo` if only that directory has an override.
For a portable ClashTUI install, lanlock uses `data/mihomo` next to the
ClashTUI executable.

For a custom setup, pass ClashTUI’s `mihomo` subdirectory, which contains
`core_override_config.yaml`.

```bash
lanlock-tui --config-dir "/path/to/clashtui/mihomo"
```

If the override file is missing, start ClashTUI once with the Mihomo core.
When adding domains, the override must contain the profile's `rules` and `dns`
sections. ClashTUI replaces these top-level sections when it merges the
override, so copy them from the active profile first if they are missing.

With FlClash, lanlock edits the selected local profile in
`~/Library/Application Support/com.follow.clash` (`$LANLOCK_FLCLASH_DIR` to
override). Reapply the profile or restart the core to load a change. url and
custom profiles are refused: their rules live in FlClash's database, not the
profile file. Live connections and rule attribution need FlClash's External
Controller (Tools → Settings → General → Inbound, with a non-empty
外部控制器密钥), which binds `127.0.0.1:9090`; point `--api` there and export
`LANLOCK_API_SECRET`.

## Commands

```bash
lanlock ls
lanlock add corp.example
lanlock rm corp.example
lanlock sync
lanlock check
lanlock tui
```

`add`, `rm`, and `sync` save the file, keep one `.bak` backup, and apply the
change through ClashTUI; with FlClash they print the reload step instead. Use
`--no-apply` to edit the file only:

```bash
lanlock add --no-apply corp.example
lanlock sync --no-apply
```

`lanlock tui` and `lanlock-tui` start the same UI; it needs the `tui` extra, and
without that extra `lanlock-tui` reports the missing extra instead of starting.
`check` reports what the controller saw; without one (a plain FlClash setup,
for example) it reports DNS answers only.

Useful global options:

```text
--backend NAME       clashtui or flclash (default: detect)
--config-dir PATH    ClashTUI's mihomo directory, or FlClash's data directory
--api URL            Mihomo controller, default http://127.0.0.1:9090
--profile NAME       ClashTUI profile, or a FlClash profile name or id
--resolver SERVERS   FlClash nameserver-policy value, default system://
```

If the controller requires authentication, set:

```bash
export LANLOCK_API_SECRET=...
```
