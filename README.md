# lanlock

Keep selected internal domains on `DIRECT` in a ClashTUI-managed Mihomo setup.

For each domain, mihomo-internal keeps these two entries in sync:

- a `DOMAIN-SUFFIX,...,DIRECT` rule
- a `+.domain` entry in `dns.fake-ip-filter`

It can regenerate the Mihomo config through ClashTUI and check the route that
Mihomo actually used.

## Install

Python 3.10 or newer is required.

```bash
python -m pip install .
```

This installs the `mihomo-internal` and `mihomo-tui` commands.

Install the terminal UI extra when needed:

```bash
python -m pip install '.[tui]'
```

## Before You Start

Use an existing ClashTUI Mihomo profile. Mihomo must be running with its
controller enabled. Applying changes also requires the `clashtui` command on
`PATH`.

By default, mihomo-internal uses the `mihomo` directory under the platform config
directory. Override it with `--config-dir`:

```bash
mihomo-internal --config-dir ~/.config/clashtui/mihomo ls
```

The override file is `core_override_config.yaml` in that directory. When
adding domains, the override must contain the profile's `rules` and `dns`
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

### TUI keys

`j`/`k` move, `a` add, `d` delete, `y` sync, `v` verify, `t` DNS test,
`w` apply, `s` save, `r` reload, `l` live connections, `q` quit.

Adding a host below a parent (`aaa.bbb.cc`) asks whether to add that host or
`*.bbb.cc`. Both are stored as a `DOMAIN-SUFFIX` rule plus a matching
`dns.fake-ip-filter` entry, so hosts below the chosen name are covered; an
explicit `*.` or `+.` prefix skips the prompt.

`l` lists the controller's open connections plus failed dials. Mihomo keeps no
connection history: `/connections` is live-only and `/logs` streams new lines,
so ended successful connections cannot be replayed. Failed dials are captured
while the TUI runs and recorded in `failures.json` under the state directory
(`$XDG_STATE_HOME/mihomo-internal`, `~/Library/Application
Support/mihomo-internal`, or `%LOCALAPPDATA%\mihomo-internal`), keeping the
newest 200 per controller URL across restarts. `f` filters the panel: all →
failed only → open only. Select a row and press Enter to add that host (or its
parent).

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
