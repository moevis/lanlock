# lanlock

Keep selected internal domains on `DIRECT` in a ClashTUI-managed Mihomo setup.

For each domain, mihomo-internal keeps these two entries in sync:

- a `DOMAIN-SUFFIX,...,DIRECT` rule
- a `+.domain` entry in `dns.fake-ip-filter`

It can regenerate the Mihomo config through ClashTUI and check the route that
Mihomo actually used.

## Install

Python 3.10 or newer is required.

Install straight from GitHub:

```bash
python -m pip install "lanlock @ git+https://github.com/moevis/lanlock.git"
```

Install the terminal UI extra when needed:

```bash
python -m pip install "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

Or install from a local clone (add `-e` to keep it editable):

```bash
git clone https://github.com/moevis/lanlock.git
cd lanlock
python -m pip install ".[tui]"
```

All forms install the `mihomo-internal` and `mihomo-tui` commands.

## Update

From a local clone:

```bash
cd lanlock
git pull
python -m pip install --force-reinstall ".[tui]"   # -e ".[tui]" when editable
```

From the GitHub URL, keeping the extra you installed:

```bash
python -m pip install --upgrade --force-reinstall \
  "lanlock[tui] @ git+https://github.com/moevis/lanlock.git"
```

`--force-reinstall` matters while the version stays 0.1.0: without it pip sees
the installed version as already satisfying the requirement. Check what is
installed:

```bash
mihomo-internal --version
mihomo-tui --version
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
