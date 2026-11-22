# lanlock

Manage domain suffix routes in a ClashTUI- or FlClash-managed Mihomo setup.

Keeps `DIRECT` rules and DNS exceptions in sync, and verifies the outbound
Mihomo actually used.

![Full lanlock TUI showing the changed outbound, DNS filters, and pending apply](assets/lanlock-tui.svg)

## Install

Requires Python 3.10+ and `uv`. From a local checkout:

```bash
uv tool install '.[tui]'
```

To update from a newer checkout, add `--force`. Omit `[tui]` for CLI-only use.

## Before You Start

Run `lanlock ls` to check the selected backend and profile. If both backends
are installed, pass `--backend clashtui` or `--backend flclash`. Use
`--config-dir` for a non-default location.

- **ClashTUI:** Start Mihomo with its controller enabled and make sure
  `clashtui` is on `PATH`. If needed, point `--config-dir` at the `mihomo`
  directory containing `core_override_config.yaml`. Copy the active profile's
  `rules` and `dns` sections into that file if missing; ClashTUI replaces them
  instead of merging them.
- **FlClash:** Select a local file profile (URL and custom profiles are not
  editable). Reapply the profile or restart the core after saving. For Live
  and routing verification, enable External Controller in **Tools → Settings
  → General → Inbound** and set a non-empty secret. The default controller
  address is `127.0.0.1:9090`.

## Commands

```bash
lanlock ls
lanlock add corp.example
lanlock rm corp.example
lanlock sync
lanlock check
lanlock tui
```

`add`, `rm`, and `sync` keep one `.bak` backup. Use `--no-apply` to save
without applying.

`+.example.com` covers both the domain and its subdomains. A rule pinned to
the `MATCH` target does not follow later changes to the global fallback.

`check` reports what the controller saw; without one (a plain FlClash setup,
for example) it reports DNS answers only.

See `lanlock --help` for profile, controller, and resolver options.
