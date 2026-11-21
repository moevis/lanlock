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
