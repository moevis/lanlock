import json
import os
from pathlib import Path
from stat import S_IMODE
import socket
import subprocess
import sys

import pytest
from ruamel.yaml import YAML

from lanlock import MihomoConfig, __version__, cli
from lanlock import config as config_mod


OVERRIDE = '''# Keep this comment
rules:
  - 'DOMAIN,exception.corp.example,PROXY'
  - 'GEOSITE,private,DIRECT'
  - 'MATCH,PROXY'
dns:
  enable: true
  fake-ip-filter: ["+.existing.example", 'geosite:private']
sniffer:
  skip-domain: ['+.corp.example']
'''


@pytest.fixture
def cfg(tmp_path):
    core = tmp_path / "mihomo"
    core.mkdir()
    config = MihomoConfig(core)
    Path(config.override).write_text(OVERRIDE, encoding="utf-8")
    return config


OVERRIDE_FILE = "core_override_config.yaml"


def _install_override(directory, text):
    directory.mkdir(parents=True)
    (directory / OVERRIDE_FILE).write_text(text, encoding="utf-8")
    return directory


@pytest.fixture
def macos_home(tmp_path, monkeypatch):
    """Simulate macOS with a private home and no real executable lookup."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(config_mod.sys, "platform", "darwin")
    monkeypatch.setattr(config_mod.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        config_mod.os.path, "expanduser",
        lambda path: os.fspath(home) + path[1:] if path.startswith("~") else path,
    )
    return home


def test_macos_reads_override_from_xdg_install_when_native_missing(macos_home, tmp_path, monkeypatch):
    (macos_home / ".config" / "clashtui" / "mihomo").mkdir(parents=True)
    xdg = tmp_path / "xdg"
    _install_override(xdg / "clashtui" / "mihomo", "xdg override\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", os.fspath(xdg))

    assert config_mod._clashtui_dir() == os.path.join(os.fspath(xdg), "clashtui", "mihomo")
    assert config_mod.resolve() == ("clashtui", os.path.join(os.fspath(xdg), "clashtui", "mihomo"))
    assert MihomoConfig().read() == "xdg override\n"


def test_macos_prefers_native_override_over_xdg_install(macos_home, tmp_path, monkeypatch):
    _install_override(macos_home / ".config" / "clashtui" / "mihomo", "native override\n")
    xdg = tmp_path / "xdg"
    _install_override(xdg / "clashtui" / "mihomo", "xdg override\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", os.fspath(xdg))

    assert config_mod._clashtui_dir() == os.path.join("~/.config", "clashtui", "mihomo")
    backend, resolved = config_mod.resolve(backend="clashtui")
    assert backend == "clashtui"
    assert os.path.normpath(resolved) == os.path.normpath(
        os.path.expanduser("~/.config/clashtui/mihomo"))
    assert MihomoConfig(backend="clashtui").read() == "native override\n"


def test_portable_layout_beside_real_executable_selects_override(tmp_path, monkeypatch):
    binary = tmp_path / "bin" / "clashtui"
    binary.parent.mkdir()
    binary.write_text("", encoding="utf-8")
    _install_override(binary.parent / "data" / "mihomo", "portable override\n")
    monkeypatch.setattr(config_mod.shutil, "which",
                        lambda name: os.fspath(binary) if name == "clashtui" else None)

    resolved = config_mod._clashtui_dir()
    assert resolved == os.path.join(os.fspath(binary.parent), "data", "mihomo")
    assert MihomoConfig(resolved).read() == "portable override\n"


def test_portable_layout_follows_symlinked_executable(tmp_path, monkeypatch):
    installed = tmp_path / "opt" / "clashtui"
    installed.mkdir(parents=True)
    target = installed / "clashtui"
    target.write_text("", encoding="utf-8")
    _install_override(installed / "data" / "mihomo", "portable symlink override\n")
    link = tmp_path / "bin" / "clashtui"
    link.parent.mkdir()
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    monkeypatch.setattr(config_mod.shutil, "which", lambda name: os.fspath(link))

    resolved = config_mod._clashtui_dir()
    assert resolved == os.path.join(os.fspath(installed), "data", "mihomo")
    assert MihomoConfig(resolved).read() == "portable symlink override\n"


def test_add_edits_only_target_sections_and_preserves_precedence(cfg):
    text, changed = cfg.add("*.Corp.Example.")
    assert changed
    doc = YAML(typ="safe").load(text)
    assert doc["rules"] == [
        "DOMAIN,exception.corp.example,PROXY",
        "DOMAIN-SUFFIX,corp.example,DIRECT",
        "GEOSITE,private,DIRECT",
        "MATCH,PROXY",
    ]
    assert doc["dns"]["fake-ip-filter"] == ["+.existing.example", "geosite:private", "+.corp.example"]
    assert doc["sniffer"]["skip-domain"] == ["+.corp.example"]
    assert "# Keep this comment" in text
    assert cfg.add("corp.example", text) == (text, False)


def test_add_preserves_unrelated_indentless_lists(cfg):
    unrelated = "sniffer:\n  skip-domain:\n  - '+.unrelated.example'\n"
    text = "rules:\n- MATCH,DIRECT\ndns:\n  fake-ip-filter: []\n" + unrelated
    updated, changed = cfg.add("corp.example", text)
    assert changed
    assert unrelated in updated


def test_sync_ignores_patterns_and_false_direct_matches(cfg):
    text = '''rules: ["DOMAIN-SUFFIX,one.example,DIRECT,no-resolve", "DOMAIN-SUFFIX,public.example,DIRECT-OTHER"]
dns:
  fake-ip-filter: ['+.lan', '+.two.example', '+.*.wild.example', '*']
'''
    text, added = cfg.sync(text)
    assert added == [("lan", "rule"), ("one.example", "filter"), ("two.example", "rule")]
    assert cfg.rows(text) == [{"domain": d, "rule": True, "filter": True}
                              for d in ("lan", "one.example", "two.example")]
    assert cfg.sync(text) == (text, [])


def test_remove_matches_quoted_and_final_entries(cfg):
    text = '''rules:
  - "DOMAIN-SUFFIX,CoRP.Example,DIRECT" # remove
  - DOMAIN-SUFFIX,sub.corp.example,DIRECT
  - DOMAIN-SUFFIX,corp.example,PROXY
dns:
  fake-ip-filter:
    - "+.corp.example"'''
    text, changed = cfg.remove("corp.example", text)
    assert changed
    doc = YAML(typ="safe").load(text)
    assert doc["rules"] == ["DOMAIN-SUFFIX,sub.corp.example,DIRECT", "DOMAIN-SUFFIX,corp.example,PROXY"]
    assert doc["dns"]["fake-ip-filter"] == []


@pytest.mark.parametrize("text, message", [
    ("rules: unexpected\ndns: {}\n", "YAML list"),
    ("rules: []\n", "profile's dns section"),
    ("dns: {}\n", "profile's rules section"),
    ("rules: []\ndns: {fake-ip-filter-mode: whitelist}", "blacklist"),
    ("other: &list []\nrules: *list\ndns: {}", "anchors or merges"),
])
def test_rejects_unsafe_edits(cfg, text, message):
    with pytest.raises(ValueError, match=message):
        cfg.add("corp.example", text)


def test_save_keeps_last_good_backup_and_mode(cfg):
    path = Path(cfg.override)
    backup = path.with_suffix(".yaml.bak")
    path.chmod(0o640)
    mode = S_IMODE(path.stat().st_mode)
    updated, _ = cfg.add("corp.example")
    cfg.save(updated)
    cfg.save(updated)
    with pytest.raises(ValueError, match="invalid YAML"):
        cfg.save("rules: [broken")
    assert path.read_text() == updated
    assert backup.read_text() == OVERRIDE
    assert S_IMODE(path.stat().st_mode) == S_IMODE(backup.stat().st_mode) == mode


def test_save_preserves_file_line_endings(cfg):
    path = Path(cfg.override)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(OVERRIDE.replace("\n", "\r\n"))
    text, changed = cfg.add("corp.example")
    assert changed and "\r" not in text
    cfg.save(text)
    with open(path, encoding="utf-8", newline="") as f:
        saved = f.read()
    assert saved == text.replace("\n", "\r\n")


def test_no_apply_cli_exits_cleanly_on_invalid_configuration(cfg, capsys):
    path = Path(cfg.override)
    path.write_text("rules: invalid\n")
    assert cli.main(["--config-dir", cfg.config_dir, "add", "corp.example", "--no-apply"]) == 2
    assert "rules must be a YAML list" in capsys.readouterr().err
    assert path.read_text() == "rules: invalid\n"
    assert not path.with_suffix(".yaml.bak").exists()


@pytest.mark.parametrize("entrypoint", ['tui_main(["--help"])', 'main(["tui"])'])
@pytest.mark.parametrize("dependency", ["rich", "textual", "rich.text", "textual.widgets"])
def test_tui_commands_report_missing_optional_dependencies(entrypoint, dependency):
    result = subprocess.run(
        [sys.executable, "-c", (
            "import builtins, sys\n"
            "import_ = builtins.__import__\n"
            "def without_dependency(name, *args, **kwargs):\n"
            f"    if name.split('.')[0] == {dependency.split('.')[0]!r}:\n"
            f"        raise ModuleNotFoundError(name={dependency!r})\n"
            "    return import_(name, *args, **kwargs)\n"
            "builtins.__import__ = without_dependency\n"
            "from lanlock import cli\n"
            f"sys.exit(cli.{entrypoint})\n"
        )],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "[tui]" in result.stderr
    assert "Traceback" not in result.stderr


def test_apply_reloads_through_clashtui_without_os_service(cfg, monkeypatch):
    monkeypatch.setattr(cfg, "controller_state", lambda: "ready")
    root = Path(cfg.config_dir).parent
    generated = root / "core runtime" / "config.yaml"
    generated.parent.mkdir()
    with (root / "config.yaml").open("w", encoding="utf-8") as f:
        YAML().dump({"mihomo": {"core": {"config_path": os.fspath(generated)}}}, f)
    text, _ = cfg.add("corp.example")
    text = text.replace("  enable: true\n", "  enable: true\n  fake-ip-range6: 'fd00:1::1/64'\n")
    cfg.save(text)
    root_flag = f"--config-dir={Path(cfg.config_dir).parent}"

    def run(cmd, **kwargs):
        if cmd == ["clashtui", root_flag, "profile", "select"]:
            return subprocess.CompletedProcess(cmd, 0, "Current Profile: local profile\n", "")
        if cmd == ["clashtui", root_flag, "profile", "select", "--name=local profile"]:
            generated.write_text(text)
            return subprocess.CompletedProcess(cmd, 0, "Profile selected: local profile\n", "")
        pytest.fail(f"unexpected subprocess: {cmd[0]}")

    monkeypatch.setattr(config_mod.subprocess, "run", run)
    monkeypatch.setattr(config_mod.socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("fd00:1::2", 0, 0, 0)),
    ])
    log = []
    assert cfg.apply(log=log.append, domains=["corp.example"])
    assert any("rule=y filter=y dns=fd00:1::2 FAKE-IP" in line for line in log)


@pytest.mark.parametrize("state", ["unauthorized", "unavailable"])
def test_apply_reports_controller_failure_before_selecting_profile(cfg, monkeypatch, state):
    monkeypatch.setattr(cfg, "controller_state", lambda: state)
    monkeypatch.setattr(cfg, "active_profile", lambda: pytest.fail("profile lookup before API check"))
    log = []
    assert cfg.apply(log=log.append) is False
    assert state in log[-1]
    assert ("LANLOCK_API_SECRET" in log[-1]) == (state == "unauthorized")


def test_apply_reports_profile_command_failure_even_if_exit_zero(cfg, monkeypatch):
    cfg.profile_override = "local"
    monkeypatch.setattr(cfg, "controller_state", lambda: "ready")
    monkeypatch.setattr(config_mod.subprocess, "run",
                        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "", "Failed to load Config"))
    log = []
    assert cfg.apply(log=log.append, domains=[]) is False
    assert "Failed to load Config" in log[-1]


def test_dns_uses_the_system_resolver_and_checks_all_addresses(monkeypatch):
    def resolve(host, port, *, type):
        assert host == "corp.example" and type == socket.SOCK_STREAM
        return [
            (socket.AF_INET6, type, 0, "", ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET, type, 0, "", ("198.18.0.2", 0)),
        ]

    monkeypatch.setattr(config_mod.socket, "getaddrinfo", resolve)
    assert config_mod.dns_check("corp.example") == ("198.18.0.2", "FAKE-IP")


def test_failure_history_roundtrip_and_dedupe(tmp_path):
    cfg = MihomoConfig(tmp_path / "mihomo", state_dir=tmp_path / "state")
    cfg.record_failure({"host": "a.example", "port": 443, "rule": "DomainSuffix",
                        "payload": "example", "outbound": "DIRECT",
                        "detail": "first", "count": 2})
    cfg.record_failure({"host": "b.example", "port": 8443, "rule": "DomainSuffix",
                        "payload": "example", "outbound": "DIRECT", "detail": "second"})
    cfg.record_failure({"host": "a.example", "port": 443, "rule": "DomainSuffix",
                        "payload": "example", "outbound": "DIRECT", "detail": "again"})

    history = cfg.failure_history()
    assert [h["host"] for h in history] == ["a.example", "b.example"]
    assert history[0]["detail"] == "again"
    assert history[0]["time"]
    assert list(history[0]) == ["host", "port", "rule", "payload",
                                "outbound", "detail", "time", "api"]
    assert history[0]["api"] == cfg.api


def test_failure_history_ignores_corrupt_files_and_bad_entries(tmp_path):
    cfg = MihomoConfig(tmp_path / "mihomo", state_dir=tmp_path / "state")
    path = Path(cfg.failure_log)
    path.parent.mkdir(parents=True)
    path.write_text("not json", encoding="utf-8")
    assert cfg.failure_history() == []

    path.write_text(json.dumps([{"host": "a.example", "port": 1, "api": cfg.api},
                                7, {"port": 2}]), encoding="utf-8")
    assert [h["host"] for h in cfg.failure_history()] == ["a.example"]


def test_failure_history_is_scoped_to_the_controller(tmp_path):
    state = tmp_path / "state"
    core = tmp_path / "mihomo"
    first = MihomoConfig(core, state_dir=state, api="http://127.0.0.1:9090")
    second = MihomoConfig(core, state_dir=state, api="http://127.0.0.1:9091")
    first.record_failure({"host": "a.example", "port": 1, "rule": "r",
                          "payload": "", "outbound": "DIRECT", "detail": "a"})
    second.record_failure({"host": "b.example", "port": 2, "rule": "r",
                           "payload": "", "outbound": "DIRECT", "detail": "b"})

    assert [h["host"] for h in first.failure_history()] == ["a.example"]
    assert [h["host"] for h in second.failure_history()] == ["b.example"]


def test_failure_history_caps_entries_and_detail(tmp_path):
    cfg = MihomoConfig(tmp_path / "mihomo", state_dir=tmp_path / "state")
    path = Path(cfg.failure_log)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps([
        {"host": f"h{i}.example", "port": 1, "api": cfg.api} for i in range(205)
    ]), encoding="utf-8")
    history = cfg.failure_history()
    assert len(history) == 200
    assert history[0]["host"] == "h0.example"

    cfg.record_failure({"host": "long.example", "port": 443, "rule": "r",
                        "payload": "", "outbound": "DIRECT", "detail": "x" * 5000})
    assert len(cfg.failure_history()[0]["detail"]) == 2000


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"lanlock {__version__}"


def test_default_state_dir_uses_the_product_name(macos_home):
    assert os.path.normpath(os.path.expanduser(config_mod._default_state_dir())) == \
        os.path.normpath(os.path.join(os.fspath(macos_home), "Library",
                                      "Application Support", "lanlock"))
