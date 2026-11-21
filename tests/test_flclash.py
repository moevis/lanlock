"""FlClash backend: the selected profile is the file lanlock edits."""
import json
import os
import plistlib
import sqlite3
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from lanlock import MihomoConfig, cli
from lanlock import config as config_mod

PROFILE = """mixed-port: 7890
rules:
  - GEOSITE,private,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"""

DEFAULTS = ["dns.msftnsci.com", "www.msftnsci.com", "www.msftconnecttest.com"]


@pytest.fixture
def macos_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(config_mod.sys, "platform", "darwin")
    monkeypatch.setattr(config_mod.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        config_mod.os.path, "expanduser",
        lambda path: os.fspath(home) + path[1:] if path.startswith("~") else path,
    )
    return home


def _database(root, rows, added_rules=()):
    with sqlite3.connect(root / "database.sqlite") as db:
        db.execute('CREATE TABLE profiles (id INTEGER PRIMARY KEY, label TEXT NOT NULL, '
                   'type TEXT NOT NULL, overrides TEXT, "order" INTEGER)')
        db.executemany('INSERT INTO profiles (id, label, type, overrides, "order") '
                       'VALUES (?, ?, ?, ?, ?)', rows)
        db.execute('CREATE TABLE rules (id INTEGER PRIMARY KEY, profile_id INTEGER, '
                   'rule_action TEXT, content TEXT, rule_target TEXT)')
        db.executemany('INSERT INTO rules (profile_id, rule_action, content, rule_target) '
                       'VALUES (?, ?, ?, ?)', added_rules)


def _prefs(home, profile_id=None, dns=None):
    """Write FlClash's own settings; ``dns`` is its app-level patch DNS."""
    preferences = home / "Library" / "Preferences"
    preferences.mkdir(parents=True, exist_ok=True)
    settings = {}
    if profile_id is not None:
        settings["currentProfileId"] = profile_id
    if dns is not None:
        settings["patchClashConfig"] = {"dns": dns}
    with open(preferences / "com.follow.clash.plist", "wb") as f:
        plistlib.dump({"flutter.config": json.dumps(settings)}, f)


def _flclash_dir(home, rows=None, added_rules=()):
    """FlClash stores each profile as ``profiles/<id>.yaml`` next to ``label`` rows."""
    root = home / "Library" / "Application Support" / "com.follow.clash"
    (root / "profiles").mkdir(parents=True)
    rows = rows if rows is not None else [
        (1, "maomao-reality", "file", None, 0),
        (2, "backup", "file", None, 1),
    ]
    _database(root, rows, added_rules)
    for profile_id, _, _, _, _ in rows:
        (root / "profiles" / f"{profile_id}.yaml").write_text(PROFILE, encoding="utf-8")
    return root


@pytest.fixture
def cfg(macos_home):
    _prefs(macos_home, profile_id=1)
    return MihomoConfig(os.fspath(_flclash_dir(macos_home)))


def _load(text):
    return YAML(typ="safe").load(text)


def test_detection_falls_back_to_flclash(macos_home):
    root = _flclash_dir(macos_home)
    assert config_mod.resolve() == ("flclash", os.fspath(root))
    configured = MihomoConfig()
    assert configured.flclash and configured.config_dir == os.fspath(root)


def test_both_setups_are_an_error_instead_of_a_guess(macos_home, capsys):
    root = _flclash_dir(macos_home)
    native = macos_home / ".config" / "clashtui" / "mihomo"
    native.mkdir(parents=True)
    (native / "core_override_config.yaml").write_text("rules: []\ndns: {}\n")

    with pytest.raises(ValueError, match="found both") as excinfo:
        config_mod.resolve()
    assert os.fspath(native) in str(excinfo.value)
    assert os.fspath(root) in str(excinfo.value)
    assert MihomoConfig(backend="clashtui").override == os.path.join(
        os.fspath(native), "core_override_config.yaml")
    assert MihomoConfig(backend="flclash").flclash
    assert cli.main(["ls"]) == 2
    assert "error: found both" in capsys.readouterr().err
    from lanlock.tui import main as tui_main
    assert tui_main([]) == 2
    captured = capsys.readouterr()
    assert "error: found both" in captured.err
    assert "Traceback" not in captured.err


def test_explicit_directory_with_both_markers_is_an_error(macos_home, tmp_path):
    mixed = tmp_path / "mixed"
    (mixed / "profiles").mkdir(parents=True)
    (mixed / "database.sqlite").write_bytes(b"")
    (mixed / "core_override_config.yaml").write_text("rules: []\n")
    with pytest.raises(ValueError, match="holds both"):
        config_mod.resolve(os.fspath(mixed))


def test_override_follows_the_selected_profile(cfg):
    assert cfg.flclash
    assert cfg.override == os.path.join(cfg.profiles_dir, "1.yaml")
    assert cfg.active_profile() == "maomao-reality"
    assert cfg.profiles() == ["maomao-reality", "backup"]
    assert cfg.generated == os.path.join(cfg.config_dir, "config.yaml")


def test_profile_option_selects_by_label_or_id(cfg):
    assert MihomoConfig(cfg.config_dir, profile="backup").override.endswith("2.yaml")
    assert MihomoConfig(cfg.config_dir, profile="2").override.endswith("2.yaml")
    with pytest.raises(ValueError, match="no FlClash profile 'gone'"):
        MihomoConfig(cfg.config_dir, profile="gone").read()
    with pytest.raises(ValueError, match=r"available: maomao-reality \(#1\)"):
        MihomoConfig(cfg.config_dir, profile="gone").read()


def test_ambiguous_selector_names_the_candidates(macos_home):
    rows = [(1, "same", "file", None, 0), (2, "same", "file", None, 1)]
    config = MihomoConfig(os.fspath(_flclash_dir(macos_home, rows)), profile="same")
    with pytest.raises(ValueError, match=r"matches more than one.*same \(#1\), same \(#2\)"):
        config.read()


def test_missing_selection_is_reported_instead_of_guessed(macos_home):
    config = MihomoConfig(os.fspath(_flclash_dir(macos_home)))
    assert config.active_profile() is None
    with pytest.raises(ValueError, match="cannot tell which FlClash profile"):
        config.read()


def test_add_writes_rule_filter_and_policy(cfg):
    text, changed = cfg.add("corp.example")
    assert changed
    document = _load(text)
    # Same precedence as ClashTUI: before IP/GEO/MATCH rules.
    assert document["rules"] == [
        "DOMAIN-SUFFIX,corp.example,DIRECT",
        "GEOSITE,private,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY",
    ]
    # The profile had no dns section: FlClash's app-level filters are carried over.
    assert document["dns"]["fake-ip-filter"] == DEFAULTS + ["+.corp.example"]
    assert document["dns"]["nameserver-policy"] == {"+.corp.example": ["system://"]}
    assert cfg.add("corp.example", text) == (text, False)


def test_existing_dns_section_without_a_filter_list_is_seeded(cfg):
    text = "rules:\n  - MATCH,PROXY\ndns:\n  enable: true\n"
    text, changed = cfg.add("corp.example", text)
    assert changed
    assert _load(text)["dns"]["fake-ip-filter"] == DEFAULTS + ["+.corp.example"]


def test_seed_comes_from_flclash_settings_not_the_generated_config(cfg, macos_home):
    # config.yaml describes whichever profile ran last; it must not seed another.
    Path(cfg.generated).write_text(
        "dns:\n  fake-ip-filter: ['+.from-another-profile']\n", encoding="utf-8")
    _prefs(macos_home, profile_id=1, dns={"fake-ip-filter": ["+.app-level"]})
    text, _ = cfg.add("corp.example")
    assert _load(text)["dns"]["fake-ip-filter"] == ["+.app-level", "+.corp.example"]


def test_add_refuses_to_write_filters_into_a_whitelist_configuration(cfg, macos_home):
    _prefs(macos_home, profile_id=1,
           dns={"fake-ip-filter": ["+.keep"], "fake-ip-filter-mode": "whitelist"})
    with pytest.raises(ValueError, match="blacklist"):
        cfg.add("corp.example")


def test_edits_are_refused_when_flclash_overrides_the_same_dns_keys(macos_home):
    overrides = json.dumps({"dnsOverrideKeys": ["nameserver-policy"]})
    rows = [(1, "overridden", "file", overrides, 0)]
    config = MihomoConfig(os.fspath(_flclash_dir(macos_home, rows)))
    with pytest.raises(ValueError, match="overrides nameserver-policy"):
        config.add("corp.example")


def test_edits_are_refused_for_a_profile_lanlock_cannot_write(macos_home):
    rows = [(1, "subscription", "url", None, 0)]
    config = MihomoConfig(os.fspath(_flclash_dir(macos_home, rows)))
    with pytest.raises(ValueError, match="is a url profile"):
        config.add("corp.example")


def test_edits_are_refused_when_a_flclash_added_rule_already_covers_it(macos_home):
    rows = [(1, "with-rules", "file", None, 0)]
    added = [(1, "DOMAIN-SUFFIX", "corp.example", "REJECT")]
    config = MihomoConfig(os.fspath(_flclash_dir(macos_home, rows, added)))
    with pytest.raises(ValueError, match="added rule 'DOMAIN-SUFFIX,corp.example'"):
        config.add("sub.corp.example")


def test_remove_drops_lanlock_entries_and_keeps_the_seeded_filter_list(cfg):
    text, _ = cfg.add("corp.example")
    text, changed = cfg.remove("corp.example", text)
    assert changed
    document = _load(text)
    assert document["rules"] == ["GEOSITE,private,DIRECT", "GEOIP,CN,DIRECT", "MATCH,PROXY"]
    assert document["dns"]["fake-ip-filter"] == DEFAULTS
    assert "nameserver-policy" not in document["dns"]


def test_remove_keeps_a_resolver_the_user_chose(cfg):
    text, _ = cfg.add("corp.example")
    text = text.replace("system://", "10.0.0.53")
    text, changed = cfg.remove("corp.example", text)
    assert changed
    document = _load(text)
    assert document["dns"]["nameserver-policy"] == {"+.corp.example": ["10.0.0.53"]}


def test_sync_agrees_on_rules_and_filters_only(cfg):
    text = """rules: ["DOMAIN-SUFFIX,corp.example,DIRECT"]
dns:
  fake-ip-filter: ['+.other.example']
"""
    text, added = cfg.sync(text)
    assert added == [("corp.example", "filter"), ("other.example", "rule")]
    document = _load(text)
    assert document["dns"]["fake-ip-filter"] == ["+.other.example", "+.corp.example"]
    assert "nameserver-policy" not in document["dns"]
    assert cfg.sync(text) == (text, [])


def test_save_refuses_a_file_that_changed_since_it_was_read(cfg):
    text, _ = cfg.add("corp.example")
    Path(cfg.override).write_text("rules:\n  - MATCH,OTHER\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed since it was read"):
        cfg.save(text, expect=PROFILE)


def test_apply_reports_saved_but_not_applied(cfg, monkeypatch):
    monkeypatch.setattr(config_mod, "dns_check_retry",
                        lambda domain, tries=2, networks=None: ("10.0.0.1", "ok"))

    def no_clashtui(*args, **kwargs):
        raise AssertionError("FlClash must not shell out to clashtui")

    monkeypatch.setattr(config_mod.subprocess, "run", no_clashtui)
    text, _ = cfg.add("corp.example")
    cfg.save(text, expect=PROFILE)
    lines = []
    assert cfg.apply(log=lines.append)
    output = "\n".join(lines)
    assert "profile: maomao-reality (#1)" in output
    assert "rule=y filter=y policy=y" in output
    assert "saved, NOT applied" in output
    assert "dns=" not in output


def test_apply_warns_when_the_edited_profile_is_not_the_selected_one(cfg, macos_home):
    _prefs(macos_home, profile_id=2)
    lines = []
    assert MihomoConfig(cfg.config_dir, profile="1").apply(log=lines.append)
    assert "not selected" in "\n".join(lines)


def test_apply_reports_an_unknown_profile(macos_home):
    root = _flclash_dir(macos_home)
    lines = []
    assert MihomoConfig(os.fspath(root)).apply(log=lines.append) is False
    assert "cannot tell which FlClash profile" in "\n".join(lines)


def test_cli_add_writes_the_profile(cfg, capsys):
    assert cli.main(["--config-dir", cfg.config_dir, "add", "corp.example",
                     "--no-apply"]) == 0
    assert "added   corp.example" in capsys.readouterr().out
    assert cfg.rows() == [{"domain": "corp.example", "rule": True, "filter": True}]
    assert Path(cfg.override).with_suffix(".yaml.bak").exists()


def test_add_matches_the_profile_sequence_indent(cfg):
    text = ("mixed-port: 7890\nproxies:\n  - name: a\n    type: ss\n"
            "rules:\n  - MATCH,PROXY\n")
    updated, changed = cfg.add("corp.example", text)
    assert changed
    assert "  - name: a\n    type: ss\n" in updated
    assert "rules:\n  - DOMAIN-SUFFIX,corp.example,DIRECT\n  - MATCH,PROXY\n" in updated


def test_resolver_must_not_be_blank(cfg):
    with pytest.raises(ValueError, match="must name a DNS server"):
        MihomoConfig(cfg.config_dir, resolver="   ")
