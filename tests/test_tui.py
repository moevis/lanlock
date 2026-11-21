"""Regression tests for the TUI's in-flight apply/audit state boundaries.

Textual is an optional dependency: without it the whole module is skipped.
Every config operation is a fake; nothing touches the real controller or network.
"""
import asyncio
import queue
import re
import threading

import pytest

pytest.importorskip("textual")


from lanlock import cli  # noqa: E402
from lanlock.tui import (FailureSeen, LanlockApp, LiveScreen, ScopeScreen,  # noqa: E402
                         main as tui_main, wildcard_parent)
from textual.widgets import DataTable, Input, Static  # noqa: E402

BASE_TEXT = """\
rules:
  - DOMAIN-SUFFIX,corp.example,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - MATCH,PROXY
dns:
  fake-ip-filter:
    - '+.corp.example'
  default-nameserver:
    - 1.1.1.1
"""

_RULE_RE = re.compile(r"^\s*-\s+DOMAIN-SUFFIX,([^,]+),DIRECT", re.M)
_FILTER_RE = re.compile(r"^\s*-\s+'\+\.([^']+)'", re.M)


class FakeConfig:
    """Stands in for MihomoConfig; gates apply/audit to provoke races."""

    def __init__(self, text=BASE_TEXT, *, apply_result=True,
                 block_apply=False, block_audit=False, block_status=False):
        self._text = text
        self.saves = []
        self.save_error = None
        self.read_error = None
        self.rows_error = None
        self.add_error = None

        self.apply_result = apply_result
        self.apply_error = None
        self.apply_calls = 0
        self.apply_domains = []
        self.apply_started = threading.Event()
        self.apply_release = threading.Event()
        if not block_apply:
            self.apply_release.set()

        self.audit_error = None
        self.audit_calls = 0
        self.audit_domains = []
        self.audit_started = threading.Event()
        self.audit_release = threading.Event()
        if not block_audit:
            self.audit_release.set()

        self.status_calls = 0
        self.status_started = threading.Event()
        self.status_release = threading.Event()
        if not block_status:
            self.status_release.set()

        self.connections = []
        self.failure_feed = queue.Queue()
        self.history = []
        self.recorded = []

    @property
    def override(self):
        return "/tmp/lanlock-test/core_override_config.yaml"

    def read(self, path=None):
        if self.read_error is not None:
            raise self.read_error
        return self._text

    def rows(self, text=None):
        if self.rows_error is not None:
            raise self.rows_error
        text = self._text if text is None else text
        rules = set(_RULE_RE.findall(text))
        filt = set(_FILTER_RE.findall(text))
        return [{"domain": d, "rule": d in rules, "filter": d in filt}
                for d in sorted(rules | filt)]

    def save(self, text):
        if self.save_error is not None:
            raise self.save_error
        self.saves.append(text)
        self._text = text

    def add(self, domain, text=None):
        if self.add_error is not None:
            raise self.add_error
        text = self._text if text is None else text
        changed = False
        if f"DOMAIN-SUFFIX,{domain},DIRECT" not in text:
            anchor = "  - IP-CIDR,127.0.0.0/8,DIRECT"
            text = text.replace(
                anchor, f"  - DOMAIN-SUFFIX,{domain},DIRECT\n{anchor}", 1)
            changed = True
        marker = "    - '+." + domain + "'"
        if marker not in text:
            text = text.replace(
                "  default-nameserver:", marker + "\n  default-nameserver:", 1)
            changed = True
        return text, changed

    def remove(self, domain, text=None):
        text = self._text if text is None else text
        before = text
        text = re.sub(
            rf"^\s*-\s+DOMAIN-SUFFIX,{re.escape(domain)},DIRECT\s*\n",
            "", text, flags=re.M)
        text = re.sub(rf"^\s*-\s+'\+\.{re.escape(domain)}'\s*\n",
                      "", text, flags=re.M)
        return text, text != before

    def sync(self, text=None):
        text = self._text if text is None else text
        added = []
        for row in self.rows(text):
            if row["rule"] != row["filter"]:
                text, changed = self.add(row["domain"], text)
                if changed:
                    added.append(
                        (row["domain"], "filter" if row["rule"] else "rule"))
        return text, added

    def active_profile(self):
        self.status_calls += 1
        self.status_started.set()
        if not self.status_release.wait(5):
            raise TimeoutError("fake status gate not released")
        return f"fake-profile-{self.status_calls}"

    def controller_state(self):
        return "ready"

    def live_connections(self):
        return list(self.connections)

    def failure_history(self):
        return [dict(entry) for entry in self.history]

    def record_failure(self, failure):
        self.recorded.append(dict(failure))

    def failure_stream(self, stop=None):
        while stop is None or not stop.is_set():
            try:
                item = self.failure_feed.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                return
            yield item

    def dns(self, domain):
        return "203.0.113.7", "ok"

    def apply(self, log=print, domains=None):
        self.apply_calls += 1
        self.apply_domains.append(list(domains or []))
        self.apply_started.set()
        if not self.apply_release.wait(5):
            raise TimeoutError("fake apply gate not released")
        if self.apply_error is not None:
            raise self.apply_error
        return self.apply_result

    def audit(self, log=print, domains=None):
        self.audit_calls += 1
        self.audit_domains.append(list(domains or []))
        self.audit_started.set()
        if not self.audit_release.wait(5):
            raise TimeoutError("fake audit gate not released")
        if self.audit_error is not None:
            raise self.audit_error
        return [{"domain": d, "verdict": "LEAK", "detail": "PROXY"}
                for d in (domains or [])]


class Harness(LanlockApp):
    """Observes UI-thread completion without depending on RichLog internals."""

    def __init__(self, cfg):
        super().__init__(cfg)
        self.messages = []
        self.apply_done = threading.Event()
        self.verify_done = threading.Event()
        self.status_done = threading.Event()
        self.failure_seen = threading.Event()

    def log_write(self, msg):
        self.messages.append(msg)
        super().log_write(msg)

    def _failure_arrived(self, failure):
        super()._failure_arrived(failure)
        self.failure_seen.set()

    def _apply_finished(self, ok, error):
        super()._apply_finished(ok, error)
        self.apply_done.set()

    def _apply_save_failed(self, message):
        super()._apply_save_failed(message)
        self.apply_done.set()

    def _after_verify(self, results, token):
        super()._after_verify(results, token)
        self.verify_done.set()

    def _verify_failed(self, token, message):
        super()._verify_failed(token, message)
        self.verify_done.set()

    def _status_finished(self, request_id, snapshot, error):
        super()._status_finished(request_id, snapshot, error)
        # Stale completions leave the newest request pending; only a settled
        # result (success or lookup failure) releases the waiting test.
        if not self._status_pending:
            self.status_done.set()


def _log(app):
    return "\n".join(app.messages)


async def _wait_event(event):
    assert await asyncio.to_thread(event.wait, 5), "worker callback never ran"


def test_status_reports_controller_readiness():
    async def scenario():
        cfg = FakeConfig()
        app = Harness(cfg)
        async with app.run_test():
            # The lookup runs in a worker, so readiness only appears once the
            # UI thread applies its completion callback.
            await _wait_event(app.status_done)
            status = str(app.query_one("#status", Static).render())
            assert "profile: fake-profile-1" in status
            assert "controller: ready" in status
            assert "pending" not in status
    asyncio.run(scenario())


def test_late_status_completion_after_unmount_is_ignored():
    async def scenario():
        app = Harness(FakeConfig())
        async with app.run_test():
            await _wait_event(app.status_done)
        # The status worker can land while run_test tears the app down; the
        # old render path then queried an already-detached Static and raised.
        app._status_finished(app._status_request, ("late", True), None)
        assert app._profile == "fake-profile-1"
    asyncio.run(scenario())


def test_status_lookup_blocked_keeps_ui_and_editor_live():
    async def scenario():
        cfg = FakeConfig(block_status=True)
        app = Harness(cfg)
        async with app.run_test() as pilot:
            await _wait_event(cfg.status_started)
            status = str(app.query_one("#status", Static).render())
            assert "profile: pending" in status
            assert "controller: pending" in status

            # Real key input keeps working while the external lookup hangs.
            await pilot.press("a")
            await pilot.press(*"new.example")
            await pilot.press("enter")

            assert app.dirty
            assert any(r["domain"] == "new.example" for r in app.rows)
            status = str(app.query_one("#status", Static).render())
            assert "DIRTY" in status
            assert "profile: pending" in status
            assert not app.status_done.is_set()

            cfg.status_release.set()
            await _wait_event(app.status_done)

            status = str(app.query_one("#status", Static).render())
            assert "profile: fake-profile-1" in status
            assert "controller: ready" in status
            assert "pending" not in status
            assert app.dirty  # the external result never rewrites the buffer
    asyncio.run(scenario())


def test_status_requests_coalesce_without_stale_overwrite():
    async def scenario():
        cfg = FakeConfig(block_status=True)
        app = Harness(cfg)
        async with app.run_test():
            await _wait_event(cfg.status_started)
            for _ in range(5):
                app._request_status_refresh()

            # One blocked lookup owns the worker: rapid requests only mark a
            # newer generation, they do not start more threads.
            assert cfg.status_calls == 1

            cfg.status_release.set()
            await _wait_event(app.status_done)

            # Exactly one refetch covers every queued request, and only the
            # newest snapshot is shown (the older one is discarded).
            assert cfg.status_calls == 2
            status = str(app.query_one("#status", Static).render())
            assert "profile: fake-profile-2" in status
            assert "fake-profile-1" not in status
    asyncio.run(scenario())


def test_apply_is_single_flight_and_keeps_newer_edits():
    async def scenario():
        cfg = FakeConfig(block_apply=True)
        app = Harness(cfg)
        async with app.run_test():
            app._add_domain("first.example")
            before = app.text
            app.action_apply()
            await _wait_event(cfg.apply_started)

            # A second apply while one is slow must not start another worker.
            app.action_apply()
            assert cfg.apply_calls == 1

            # Edits during apply are kept, not folded into the saved snapshot.
            app._add_domain("new.example")
            assert app.dirty
            assert "new.example" in app.text

            # Saving and reloading are blocked while the worker owns the file.
            app.action_save()
            app.action_reload()
            assert cfg.saves == [before]
            assert "new.example" in app.text
            assert "apply in progress" in _log(app)

            cfg.apply_release.set()
            await _wait_event(app.apply_done)

            assert not app.applying
            assert cfg.apply_calls == 1
            assert cfg.saves == [before]  # exactly one save of the snapshot
            assert app._saved_text == before
            assert app.dirty  # the newer edit was never marked clean
            assert any(r["domain"] == "new.example" for r in app.rows)
            assert cfg.apply_domains == [["corp.example", "first.example"]]
    asyncio.run(scenario())


def test_apply_invalidates_existing_audit():
    async def scenario():
        cfg = FakeConfig()
        app = Harness(cfg)
        async with app.run_test():
            app._after_verify(
                [{"domain": "corp.example", "verdict": "ok", "detail": "DIRECT"}],
                app._state_epoch)
            assert app.audit

            app.action_apply()
            assert app.audit == {}  # apply may change the live controller
            await _wait_event(app.apply_done)
    asyncio.run(scenario())


def test_failed_reload_keeps_prior_state():
    async def scenario():
        cfg = FakeConfig()
        app = Harness(cfg)
        async with app.run_test():
            app._add_domain("new.example")
            assert app.dirty
            text, rows, saved = app.text, list(app.rows), app._saved_text

            cfg.read_error = OSError("override disappeared")
            app.action_reload()
            assert (app.text, app.rows, app._saved_text, app.dirty) == \
                (text, rows, saved, True)

            # Read succeeds but parsing the staged rows fails: the old text
            # must not have been installed either.
            cfg.read_error = None
            cfg._text = "rules:\n  - DOMAIN-SUFFIX,other.example,DIRECT\n"
            cfg.rows_error = ValueError("unsupported target shape")
            app.action_reload()
            assert (app.text, app.rows, app._saved_text, app.dirty) == \
                (text, rows, saved, True)
            assert "reload FAILED" in _log(app)
    asyncio.run(scenario())


def test_stale_audit_after_edit_is_discarded():
    async def scenario():
        cfg = FakeConfig(block_audit=True)
        app = Harness(cfg)
        async with app.run_test():
            app.action_verify()
            await _wait_event(cfg.audit_started)
            app._add_domain("new.example")

            cfg.audit_release.set()
            await _wait_event(app.verify_done)

            assert app.audit == {}
            assert "ignored stale verify results" in _log(app)
            assert cfg.audit_domains == [["corp.example"]]
    asyncio.run(scenario())


def test_stale_audit_after_reload_is_discarded():
    async def scenario():
        cfg = FakeConfig(block_audit=True)
        app = Harness(cfg)
        async with app.run_test():
            app.action_verify()
            await _wait_event(cfg.audit_started)
            app.action_reload()

            cfg.audit_release.set()
            await _wait_event(app.verify_done)

            assert app.audit == {}
            assert "ignored stale verify results" in _log(app)
    asyncio.run(scenario())


def test_apply_failure_reports_that_override_was_saved():
    async def scenario():
        cfg = FakeConfig(apply_result=False)
        app = Harness(cfg)
        async with app.run_test():
            app._add_domain("first.example")
            before = app.text
            app.action_apply()
            await _wait_event(app.apply_done)

            assert cfg.saves == [before]
            assert not app.dirty
            log = _log(app)
            assert "apply FAILED" in log
            assert "override saved" in log
    asyncio.run(scenario())


def test_apply_save_failure_clears_guard_and_keeps_dirty():
    async def scenario():
        cfg = FakeConfig()
        cfg.save_error = ValueError("invalid yaml")
        app = Harness(cfg)
        async with app.run_test():
            app._add_domain("new.example")
            app.action_apply()
            await _wait_event(app.apply_done)

            assert not app.applying
            assert app.dirty
            assert cfg.apply_calls == 0
            assert "override not saved" in _log(app)
    asyncio.run(scenario())


def test_clean_save_and_apply_do_not_rewrite_override():
    async def scenario():
        cfg = FakeConfig()
        app = Harness(cfg)
        async with app.run_test():
            app.action_save()
            assert cfg.saves == []  # no .bak/override churn when clean

            app.action_apply()
            await _wait_event(app.apply_done)
            assert cfg.saves == []
            assert cfg.apply_calls == 1
    asyncio.run(scenario())


def test_edit_error_leaves_state_untouched():
    async def scenario():
        cfg = FakeConfig()
        app = Harness(cfg)
        async with app.run_test():
            text, rows, saved = app.text, list(app.rows), app._saved_text
            cfg.add_error = ValueError("unsupported target shape")
            app._add_domain("new.example")

            assert (app.text, app.rows, app._saved_text) == (text, rows, saved)
            assert not app.dirty
            assert "unsupported target shape" in _log(app)
    asyncio.run(scenario())


def test_dns_configuration_error_is_reported_in_tui(monkeypatch):
    async def scenario():
        cfg = FakeConfig()

        def dns(domain):
            raise ValueError("dns.fake-ip-range6 must be an IPv6 CIDR")

        monkeypatch.setattr(cfg, "dns", dns)
        app = Harness(cfg)
        async with app.run_test() as pilot:
            await pilot.press("t")
            assert "dns.fake-ip-range6 must be an IPv6 CIDR" in _log(app)

    asyncio.run(scenario())


def test_wildcard_parent_only_offers_a_real_parent():
    assert wildcard_parent("aaa.bbb.cc", "aaa.bbb.cc") == "bbb.cc"
    assert wildcard_parent("www.corp.example", "www.corp.example") == "corp.example"
    assert wildcard_parent("corp.example", "corp.example") is None
    assert wildcard_parent("*.aaa.bbb.cc", "aaa.bbb.cc") is None
    assert wildcard_parent("+.aaa.bbb.cc", "aaa.bbb.cc") is None
    assert wildcard_parent(".aaa.bbb.cc", "aaa.bbb.cc") is None


def _two_domains():
    cfg = FakeConfig()
    text, _ = cfg.add("other.example", cfg.read())
    return FakeConfig(text)


def test_jk_moves_the_table_but_types_in_the_input():
    async def scenario():
        app = Harness(_two_domains())
        async with app.run_test() as pilot:
            table = app.query_one(DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.press("j")
            assert table.cursor_row == 1
            await pilot.press("k")
            assert table.cursor_row == 0

            await pilot.press("a")
            await pilot.press("j")
            assert app.query_one(Input).value == "j"
            assert table.cursor_row == 0
    asyncio.run(scenario())


def test_add_asks_for_the_host_or_its_parent():
    async def scenario():
        app = Harness(FakeConfig())
        async with app.run_test() as pilot:
            await pilot.press("a")
            await pilot.press(*"aaa.bbb.cc")
            await pilot.press("enter")
            assert isinstance(app.screen, ScopeScreen)
            assert app.screen.domain == "aaa.bbb.cc"
            assert app.screen.parent_domain == "bbb.cc"

            # App-level single-key actions stay out of the modal's way.
            before = app.text
            await pilot.press("d")
            assert isinstance(app.screen, ScopeScreen)
            assert app.text == before

            await pilot.click("#parent")
            assert "DOMAIN-SUFFIX,bbb.cc,DIRECT" in app.text
            assert "aaa.bbb.cc" not in app.text
    asyncio.run(scenario())


def test_add_exact_host_from_the_chooser():
    async def scenario():
        app = Harness(FakeConfig())
        async with app.run_test() as pilot:
            app._request_add("aaa.bbb.cc")
            await pilot.pause()
            assert isinstance(app.screen, ScopeScreen)
            await pilot.click("#exact")
            assert "DOMAIN-SUFFIX,aaa.bbb.cc,DIRECT" in app.text
    asyncio.run(scenario())


def test_live_screen_lists_failures_and_active_connections():
    async def scenario():
        cfg = FakeConfig()
        cfg.failure_feed.put({"host": "bad.corp.example", "port": 443,
                              "rule": "DomainSuffix", "payload": "corp.example",
                              "outbound": "DIRECT", "detail": "dial tcp: timeout"})
        cfg.connections = [
            {"metadata": {"host": "corp.example", "destinationPort": "443"},
             "rule": "DomainSuffix", "rulePayload": "corp.example",
             "chains": ["DIRECT"]},
        ]
        app = Harness(cfg)
        async with app.run_test() as pilot:
            await _wait_event(app.failure_seen)
            await pilot.press("l")
            for _ in range(100):
                if isinstance(app.screen, LiveScreen) and len(app.screen._rows) >= 2:
                    break
                await asyncio.sleep(0.01)
            screen = app.screen
            assert isinstance(screen, LiveScreen)
            assert screen._rows[0]["state"] == "FAIL"
            assert screen._rows[0]["host"] == "bad.corp.example"
            assert cfg.recorded and cfg.recorded[0]["host"] == "bad.corp.example"
            assert screen._rows[1]["state"] == "live"
            assert screen._rows[1]["host"] == "corp.example"

            await pilot.press("j")
            assert screen.query_one(DataTable).cursor_row == 1
            await pilot.press("k")
            assert screen.query_one(DataTable).cursor_row == 0

            await pilot.press("enter")
            assert isinstance(app.screen, ScopeScreen)
            await pilot.click("#exact")
            assert "DOMAIN-SUFFIX,bad.corp.example,DIRECT" in app.text
    asyncio.run(scenario())


def test_live_screen_refuses_ip_destinations():
    async def scenario():
        cfg = FakeConfig()
        cfg.failure_feed.put({"host": "10.1.2.3", "port": 443,
                              "rule": "IP-CIDR", "payload": "10.0.0.0/8",
                              "outbound": "DIRECT", "detail": "dial tcp: timeout"})
        app = Harness(cfg)
        async with app.run_test() as pilot:
            await _wait_event(app.failure_seen)
            await pilot.press("l")
            for _ in range(100):
                if isinstance(app.screen, LiveScreen) and app.screen._rows:
                    break
                await asyncio.sleep(0.01)
            await pilot.press("enter")
            assert isinstance(app.screen, LiveScreen)
            assert "cannot add 10.1.2.3" in str(
                app.screen.query_one("#live-help", Static).render())
    asyncio.run(scenario())


def test_escape_closes_the_live_screen():
    async def scenario():
        app = Harness(FakeConfig())
        async with app.run_test() as pilot:
            await pilot.press("l")
            assert isinstance(app.screen, LiveScreen)
            await pilot.press("escape")
            assert not isinstance(app.screen, LiveScreen)
    asyncio.run(scenario())


def test_late_failure_after_unmount_is_ignored():
    async def scenario():
        app = Harness(FakeConfig())
        async with app.run_test():
            pass
        # The watcher can post while run_test drains a closing app; the old
        # handler logged through query_one and raised NoMatches.
        assert app._logs_stop.is_set()  # on_unmount stopped the watcher
        app._failure_seen(FailureSeen({
            "host": "late.corp.example", "port": 443, "rule": "DomainSuffix",
            "payload": "corp.example", "outbound": "DIRECT", "detail": "x"}))
        assert app.failures == []
    asyncio.run(scenario())


def test_live_screen_shows_recorded_failures_and_filters():
    async def scenario():
        cfg = FakeConfig()
        cfg.history = [{"host": "old.corp.example", "port": 8443,
                        "rule": "DomainSuffix", "payload": "corp.example",
                        "outbound": "DIRECT", "detail": "dial tcp: timeout",
                        "time": "2026-11-20 09:00:00"}]
        cfg.connections = [
            {"metadata": {"host": "corp.example", "destinationPort": "443"},
             "rule": "DomainSuffix", "rulePayload": "corp.example",
             "chains": ["DIRECT"]},
        ]
        app = Harness(cfg)
        async with app.run_test() as pilot:
            await pilot.press("l")
            for _ in range(100):
                if isinstance(app.screen, LiveScreen) and len(app.screen._rows) >= 2:
                    break
                await asyncio.sleep(0.01)
            screen = app.screen
            assert isinstance(screen, LiveScreen)
            recorded = next(r for r in screen._rows if r["host"] == "old.corp.example")
            assert recorded["state"] == "FAIL"
            assert recorded["when"] == "2026-11-20 09:00:00"

            await pilot.press("f")
            assert [r["state"] for r in screen._rows] == ["FAIL"]
            await pilot.press("f")
            assert [r["state"] for r in screen._rows] == ["live"]
            await pilot.press("f")
            assert {r["state"] for r in screen._rows} == {"FAIL", "live"}
            assert "filter: all" in str(
                screen.query_one("#live-help", Static).render())
    asyncio.run(scenario())


def test_repeat_failure_keeps_first_seen_time_and_count():
    async def scenario():
        cfg = FakeConfig()
        app = Harness(cfg)
        async with app.run_test():
            failure = {"host": "bad.corp.example", "port": 443,
                       "rule": "DomainSuffix", "payload": "corp.example",
                       "outbound": "DIRECT", "detail": "first"}
            app._failure_arrived(dict(failure))
            first = app.failures[0]["time"]
            app._failure_arrived(dict(failure, detail="again"))

            assert len(app.failures) == 1
            assert app.failures[0]["count"] == 2
            assert app.failures[0]["detail"] == "again"
            assert app.failures[0]["time"] == first
            assert len(cfg.recorded) == 1
    asyncio.run(scenario())


def test_loaded_history_is_refreshed_once_per_session():
    async def scenario():
        cfg = FakeConfig()
        cfg.history = [{"host": "bad.corp.example", "port": 443,
                        "rule": "DomainSuffix", "payload": "corp.example",
                        "outbound": "DIRECT", "detail": "old",
                        "time": "2026-11-20 09:00:00"}]
        app = Harness(cfg)
        async with app.run_test():
            assert len(app.failures) == 1 and app.failures[0]["count"] == 1

            app._failure_arrived({"host": "bad.corp.example", "port": 443,
                                  "rule": "DomainSuffix", "payload": "corp.example",
                                  "outbound": "DIRECT", "detail": "new"})
            entry = app.failures[0]
            assert entry["count"] == 2
            assert entry["detail"] == "new"
            assert entry["time"] != "2026-11-20 09:00:00"
            assert len(cfg.recorded) == 1

            app._failure_arrived({"host": "bad.corp.example", "port": 443,
                                  "rule": "DomainSuffix", "payload": "corp.example",
                                  "outbound": "DIRECT", "detail": "newer"})
            assert app.failures[0]["detail"] == "newer"
            assert len(cfg.recorded) == 1
    asyncio.run(scenario())


def test_tui_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        tui_main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("mihomo-tui ")


@pytest.mark.parametrize("entrypoint, subcommand", [
    (cli.tui_main, False),
    (cli.main, True),
], ids=["tui_main", "cli_main_tui"])
def test_tui_startup_reports_missing_override(entrypoint, subcommand, tmp_path, capsys):
    missing = tmp_path / "missing" / "mihomo"
    assert not missing.exists()
    argv = ["--config-dir", str(missing)] + (["tui"] if subcommand else [])

    assert entrypoint(argv) == 2

    captured = capsys.readouterr()
    override = missing / "core_override_config.yaml"
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert str(override) in captured.err
    assert "--config-dir" in captured.err
    assert "Traceback" not in captured.err
    assert not missing.exists()
    assert not override.exists()
    assert not (missing / "config" / "config.yaml").exists()
