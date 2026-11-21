"""Textual UI for lanlock."""
import argparse
import ipaddress
import sys
import threading
import time

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static

from . import __version__
from .config import DEFAULT_API, DEFAULT_RESOLVER, MihomoConfig, norm

VERDICT_STYLE = {
    "ok": "green",
    "LEAK": "bold red",
    "FAKE-IP": "yellow",
    "skip": "dim",
    "unknown": "dim yellow",
}

FAILURE_HISTORY = 50
LIVE_REFRESH = 2.0
MAX_LIVE_ROWS = 200


def _rule_label(rule, payload=""):
    rule = rule or "?"
    return f"{rule}/{payload}" if payload else rule


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def wildcard_parent(raw, domain):
    """Return the parent to offer as a wildcard, or None when there is no choice.

    A short name has no meaningful parent (``bbb.cc`` must not offer ``cc``),
    and an explicit ``*.``, ``+.`` or leading dot already states the scope.
    """
    if raw.strip().startswith(("*.", "+.", ".")):
        return None
    if domain.count(".") < 2:
        return None
    parent = domain.split(".", 1)[1]
    return parent if "." in parent else None



class StatusLoaded(Message):
    """Off-thread result of the clashtui/controller status lookup."""

    def __init__(self, request_id: int, snapshot, error) -> None:
        super().__init__()
        self.request_id = request_id
        self.snapshot = snapshot
        self.error = error


class FailureSeen(Message):
    """One failed dial captured off the controller log stream."""

    def __init__(self, failure) -> None:
        super().__init__()
        self.failure = failure


class FailureWatchFailed(Message):
    """The log watcher could not subscribe; failures will not be collected."""

    def __init__(self, error: str) -> None:
        super().__init__()
        self.error = error


class ConnectionsLoaded(Message):
    """Off-thread snapshot of the controller's open connections."""

    def __init__(self, rows, error=None) -> None:
        super().__init__()
        self.rows = rows
        self.error = error


class ScopeScreen(ModalScreen):
    """Ask whether to add the typed host or its whole parent subtree."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=False)]

    CSS = """
    ScopeScreen { align: center middle; }
    #scope { width: 72; height: auto; background: $panel; border: thick $primary; padding: 1 2; }
    #scope Button { width: 100%; margin-top: 1; }
    """

    def __init__(self, domain: str, parent: str) -> None:
        super().__init__()
        self.domain = domain
        self.parent_domain = parent

    def compose(self) -> ComposeResult:
        with Vertical(id="scope"):
            yield Static(f"Add [b]{self.domain}[/b] or all of "
                         f"[b]{self.parent_domain}[/b]?")
            yield Button(self.domain, id="exact", variant="primary")
            yield Button(f"*.{self.parent_domain}   (all of {self.parent_domain})",
                         id="parent")
            yield Button("cancel", id="cancel")
            yield Static("[dim]Both entries are DOMAIN-SUFFIX, so hosts below "
                         "the chosen name are covered too.[/]")

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.dismiss({"exact": self.domain,
                      "parent": self.parent_domain}.get(event.button.id))

    def action_cancel(self) -> None:
        self.dismiss(None)


class LiveScreen(ModalScreen):
    """Open connections plus recorded failures, with a state filter."""

    BINDINGS = [
        Binding("escape", "cancel", "close", show=False),
        Binding("j", "cursor_down", "down", show=False),
        Binding("k", "cursor_up", "up", show=False),
        Binding("f", "cycle_filter", "filter", show=False),
    ]

    CSS = """
    LiveScreen { align: center middle; }
    #live-box { width: 90%; height: 80%; background: $panel; border: thick $primary; padding: 0 1; }
    #live-title { height: 1; }
    #live-table { height: 1fr; }
    #live-help { height: 1; color: $text-muted; }
    """

    FILTERS = ("all", "fail", "live")
    FILTER_LABEL = {"all": "all", "fail": "failed only", "live": "open only"}

    def __init__(self, load_connections, failures) -> None:
        super().__init__()
        self._load = load_connections
        self._failures = failures
        self._active = []
        self._rows = []
        self._filter = "all"
        self._error = None
        self._help = None
        self._timer = None

    def compose(self) -> ComposeResult:
        with Vertical(id="live-box"):
            yield Static("open connections · failed dials (this run + recorded)",
                         id="live-title")
            yield DataTable(id="live-table")
            yield Static("Enter add · j/k move · f filter · Esc close", id="live-help")

    def on_mount(self) -> None:
        table = self.query_one("#live-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("state", "host", "port", "rule", "out", "n", "when")
        table.focus()
        self._help = self.query_one("#live-help", Static)
        self._fill()
        self._timer = self.set_interval(LIVE_REFRESH, self._refresh)
        self._refresh()

    def on_unmount(self) -> None:
        if self._timer is not None:
            self._timer.stop()

    # ---------- data ----------
    def _refresh(self) -> None:
        self._load_worker()

    @work(thread=True, exclusive=True, group="live")
    def _load_worker(self) -> None:
        try:
            rows = self._load()
        except Exception as e:
            self.post_message(ConnectionsLoaded(None, f"{type(e).__name__}: {e}"))
            return
        self.post_message(ConnectionsLoaded(rows, None))

    @on(ConnectionsLoaded)
    def _loaded(self, event: ConnectionsLoaded) -> None:
        if not self.is_running:
            # A worker can deliver after the screen was dismissed.
            return
        if event.error is not None:
            self._error = event.error
        else:
            self._active = event.rows or []
            self._error = None
        self._fill()

    @staticmethod
    def _active_rows(connections) -> list:
        counts = {}
        for conn in connections:
            if not isinstance(conn, dict):
                continue
            metadata = conn.get("metadata") or {}
            host = metadata.get("host") or metadata.get("destinationIP") or "?"
            chains = conn.get("chains") or []
            key = (host, str(metadata.get("destinationPort") or ""),
                   _rule_label(conn.get("rule"), conn.get("rulePayload") or ""),
                   chains[0] if chains else "-")
            counts[key] = counts.get(key, 0) + 1
        return [{"state": "live", "host": host, "port": port, "rule": rule,
                 "out": out, "n": str(count)}
                for (host, port, rule, out), count
                in sorted(counts.items())[:MAX_LIVE_ROWS]]

    def _fill(self) -> None:
        table = self.query_one("#live-table", DataTable)
        keep = table.cursor_row
        rows = []
        if self._filter in ("all", "fail"):
            for failure in self._failures():
                rows.append({"state": "FAIL", "host": failure.get("host") or "?",
                             "port": str(failure.get("port") or ""),
                             "rule": _rule_label(failure.get("rule"),
                                                 failure.get("payload") or ""),
                             "out": failure.get("outbound") or "-",
                             "n": str(failure.get("count", 1)),
                             "when": failure.get("time") or ""})
        if self._filter in ("all", "live"):
            rows.extend(self._active_rows(self._active))
        self._rows = rows
        table.clear(columns=False)
        for row in rows:
            style = "bold red" if row["state"] == "FAIL" else "dim"
            table.add_row(Text(row["state"], style=style), row["host"], row["port"],
                          row["rule"], row["out"], row["n"], row.get("when", ""))
        if rows:
            table.move_cursor(row=min(max(0, keep), len(rows) - 1))
        self._show_help()

    def _show_help(self, text=None) -> None:
        if self._help is None:
            return
        if text is None:
            text = (f"Enter add · j/k move · f filter: "
                    f"{self.FILTER_LABEL[self._filter]} · Esc close")
            if self._error:
                text = f"[red]{self._error}[/]"
        self._help.update(text)

    def action_cycle_filter(self) -> None:
        index = (self.FILTERS.index(self._filter) + 1) % len(self.FILTERS)
        self._filter = self.FILTERS[index]
        self._fill()

    # ---------- actions ----------
    @on(DataTable.RowSelected)
    def _selected(self, event: DataTable.RowSelected) -> None:
        index = event.cursor_row
        if not 0 <= index < len(self._rows):
            return
        host = self._rows[index]["host"]
        if host == "?" or _is_ip(host):
            self._show_help(f"[yellow]cannot add {host}: not a domain[/]")
            return
        self.dismiss(host)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_cursor_down(self) -> None:
        self.query_one("#live-table", DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#live-table", DataTable).action_cursor_up()


class LanlockApp(App):
    TITLE = "lanlock"
    SUB_TITLE = "internal domains stay DIRECT"

    CSS = """
    #status { height: 1; padding: 0 1; background: $panel; }
    #table { height: 1fr; }
    #add { height: 3; }
    #log { height: 10; border-top: solid $primary; }
    """

    BINDINGS = [
        Binding("a", "focus_add", "add"),
        Binding("d", "delete", "delete"),
        Binding("y", "sync", "sync"),
        Binding("v", "verify", "verify"),
        Binding("t", "test_dns", "test"),
        Binding("w", "apply", "apply"),
        Binding("s", "save", "save"),
        Binding("r", "reload", "reload"),
        Binding("l", "live", "live"),
        Binding("j", "cursor_down", "down", show=False),
        Binding("k", "cursor_up", "up", show=False),
        Binding("escape", "blur_input", "blur", show=False),
        Binding("q", "quit", "quit"),
    ]

    def __init__(self, cfg=None):
        super().__init__()
        self.cfg = cfg or MihomoConfig()
        self.text = self.cfg.read()
        self.rows = self.cfg.rows(self.text)
        self.audit = {}
        # UI-thread state: the buffer, the last text known to be on disk, and
        # the snapshot of the one in-flight apply (None when idle).
        self._saved_text = self.text
        self._apply_text = None
        # Bumped whenever the edited rows or the generated config may have
        # changed; a verify worker only lands if its token still matches.
        self._state_epoch = 0
        # External status (clashtui profile + controller readiness) is looked
        # up off the UI thread. Cached values render immediately; the counters
        # coalesce overlapping requests and reject older completions.
        self._profile = None
        self._controller = None
        self._status_pending = True
        self._status_error = None
        self._status_lock = threading.Lock()
        self._status_request = 0
        self._status_running = False
        self._status_line = None
        # Failed dials, newest first; filled by the log watcher on the UI thread.
        self.failures = []
        self._recorded_keys = set()
        self._logs_stop = threading.Event()
        self._history_error = False

    @property
    def dirty(self) -> bool:
        return self.text != self._saved_text

    @property
    def applying(self) -> bool:
        return self._apply_text is not None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="status")
        yield DataTable(id="table")
        yield Input(placeholder="domain — Enter adds · Esc back to the list", id="add")
        yield RichLog(id="log", markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        self._status_line = self.query_one("#status", Static)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("domain", "direct rule", "fake-ip-filter", "live")
        self.fill_table()
        table.focus()
        self._load_history()
        self._request_status_refresh()
        self._watch_logs()
        self.log_write("[dim]a add · d delete · y sync rule/filter · v verify · t dns · "
                       "w apply · s save · r reload · l live · j/k move · q quit[/]")

    def on_unmount(self) -> None:
        self._logs_stop.set()

    # ---------- helpers ----------
    def log_write(self, msg: str) -> None:
        self.query_one(RichLog).write(msg)

    def refresh_status(self) -> None:
        """Render the current editor and cached external status immediately."""
        if self._status_line is None or not self.is_running:
            # A status worker can finish while the app shuts down; nothing to paint.
            return
        if self._profile is None and self._status_pending:
            prof = "[dim]pending…[/]"
        else:
            prof = f"[b]{self._profile or '?'}[/]"
        if self._controller is None and self._status_pending:
            controller = "[dim]pending…[/]"
        else:
            controller = f"[b]{self._controller or '?'}[/]"
        if self.applying:
            state = "[bold yellow]APPLYING[/]"
            if self.dirty:
                state += " [bold red]DIRTY[/]"
        else:
            state = "[bold red]DIRTY[/]" if self.dirty else "saved"
        leaks = sum(1 for v in self.audit.values() if v[0] == "LEAK")
        verified = f"   leaks: [bold red]{leaks}[/]" if self.audit else ""
        unsynced = sum(1 for r in self.rows if r["rule"] != r["filter"])
        synced = f"   unsynced: [yellow]{unsynced}[/]" if unsynced else ""
        failed = "   status: [yellow]lookup failed[/]" if self._status_error else ""
        self._status_line.update(
            f"profile: {prof}   controller: {controller}   "
            f"file: {self.cfg.override}   {state}{verified}{synced}{failed}")

    def _request_status_refresh(self) -> None:
        """Queue a fresh external-status lookup, coalescing pending ones."""
        with self._status_lock:
            self._status_request += 1
        self._status_pending = True
        self._status_error = None
        self.refresh_status()
        self._start_status_worker()

    def _start_status_worker(self) -> None:
        with self._status_lock:
            if self._status_running:
                return
            self._status_running = True
            request_id = self._status_request
        self._status_worker(request_id)

    # Own group: the status lookup never cancels or joins apply/verify.
    # Not exclusive: cancelling a thread worker does not stop a blocked
    # subprocess/HTTP call, so overlapping requests are coalesced instead.
    @work(thread=True, group="status")
    def _status_worker(self, request_id: int) -> None:
        while True:
            try:
                snapshot = (self.cfg.active_profile() or "?",
                            self.cfg.controller_state())
            except Exception as e:
                self.post_message(
                    StatusLoaded(request_id, None, f"{type(e).__name__}: {e}"))
                return
            with self._status_lock:
                latest = self._status_request
            if latest == request_id:
                self.post_message(StatusLoaded(request_id, snapshot, None))
                return
            # Requests arrived while the lookup was blocked: fetch once more
            # for the newest one instead of delivering this older snapshot.
            request_id = latest

    @on(StatusLoaded)
    def _status_loaded(self, event: StatusLoaded) -> None:
        self._status_finished(event.request_id, event.snapshot, event.error)

    def _status_finished(self, request_id: int, snapshot, error) -> None:
        if not self.is_running:
            # Shutting down: do not retry lookups or paint a closed app.
            return
        with self._status_lock:
            latest = self._status_request
            self._status_running = False
        if request_id != latest:
            # A request landed after the worker's last check; its result is
            # already stale, so retry rather than overwriting newer status.
            self._start_status_worker()
            return
        self._status_pending = False
        if error is None:
            self._profile, self._controller = snapshot
            self._status_error = None
        else:
            self._status_error = error
        self.refresh_status()

    # ---------- live connections and failures ----------
    # Own group: the subscription ends only when the app unmounts.
    @work(thread=True, group="logs")
    def _watch_logs(self) -> None:
        try:
            for failure in self.cfg.failure_stream(self._logs_stop):
                self.post_message(FailureSeen(failure))
        except ValueError as e:
            self.post_message(FailureWatchFailed(str(e)))
        except Exception as e:
            self.post_message(FailureWatchFailed(f"{type(e).__name__}: {e}"))

    @on(FailureSeen)
    def _failure_seen(self, event: FailureSeen) -> None:
        if not self.is_running:
            # A worker can post after Textual tears the widget tree down.
            return
        self._failure_arrived(event.failure)

    def _load_history(self) -> None:
        try:
            history = self.cfg.failure_history()
        except Exception as e:
            self.log_write(f"[yellow]failure history unavailable:[/] {e}")
            return
        known = {(f["host"], f["port"]) for f in self.failures}
        for entry in history:
            if (entry["host"], entry["port"]) not in known:
                entry.setdefault("count", 1)
                self.failures.append(entry)
        del self.failures[FAILURE_HISTORY:]

    def _failure_arrived(self, failure) -> None:
        key = (failure["host"], failure["port"])
        known = next((f for f in self.failures
                      if (f["host"], f["port"]) == key), None)
        is_new = known is None
        if is_new:
            known = dict(failure)
            known["count"] = 0
            self.failures.insert(0, known)
            del self.failures[FAILURE_HISTORY:]
        else:
            # Keep the recorded time until this session's first occurrence.
            known.update({k: v for k, v in failure.items() if k != "time"})
        known["count"] = known.get("count", 0) + 1
        if key in self._recorded_keys:
            return
        # One write per host:port per run keeps a retrying dial from rewriting
        # the state file, while a new session still refreshes the record.
        known["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._recorded_keys.add(key)
        try:
            self.cfg.record_failure(known)
        except OSError as e:
            if not self._history_error:
                self._history_error = True
                self.log_write(f"[yellow]cannot save failure history:[/] {e}")
        if is_new:
            self.log_write(f"[red]failed[/] {known['host']}:{known['port']} "
                           f"{_rule_label(known['rule'], known['payload'])} -> "
                           f"{known['outbound']} [dim](l to inspect and add)[/]")

    @on(FailureWatchFailed)
    def _failure_watch_failed(self, event: FailureWatchFailed) -> None:
        if not self.is_running:
            return
        self.log_write(f"[yellow]failure log unavailable:[/] {event.error}")

    def action_live(self) -> None:
        self.push_screen(LiveScreen(self.cfg.live_connections, self._failure_rows),
                         self._live_chosen)

    def _failure_rows(self):
        return [dict(f) for f in self.failures]

    def _live_chosen(self, host) -> None:
        if host:
            self._request_add(host)

    def action_cursor_down(self) -> None:
        self.query_one(DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one(DataTable).action_cursor_up()

    def check_action(self, action: str, parameters: tuple):
        # A modal owns the keys while it is open; only quitting stays global.
        return len(self.screen_stack) == 1 or action == "quit"

    def _invalidate_audit(self) -> None:
        """Drop verdicts and make any in-flight verify result stale."""
        self._state_epoch += 1
        self.audit = {}

    def _verdict_text(self, domain: str) -> Text:
        v = self.audit.get(domain)
        if not v:
            return Text("", style="dim")
        return Text(v[0], style=VERDICT_STYLE.get(v[0], ""))

    def fill_table(self) -> None:
        table = self.query_one(DataTable)
        keep = table.cursor_row
        table.clear(columns=False)
        for row in self.rows:
            table.add_row(
                row["domain"],
                Text("y", style="green") if row["rule"] else Text("-", style="red"),
                Text("y", style="green") if row["filter"] else Text("-", style="red"),
                self._verdict_text(row["domain"]),
            )
        if self.rows:
            table.move_cursor(row=min(keep, len(self.rows) - 1))

    def selected_domain(self):
        table = self.query_one(DataTable)
        if not self.rows:
            return None
        idx = min(max(0, table.cursor_row), len(self.rows) - 1)
        return self.rows[idx]["domain"]

    # ---------- input ----------
    @on(Input.Submitted, "#add")
    def add_domain(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        self.query_one(Input).value = ""
        self.query_one(DataTable).focus()
        if raw:
            self._request_add(raw)

    def _request_add(self, raw: str) -> None:
        try:
            domain = norm(raw)
        except ValueError as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        parent = wildcard_parent(raw, domain)
        if parent is None:
            self._add_domain(domain)
            return
        self.push_screen(ScopeScreen(domain, parent), self._scope_chosen)

    def _scope_chosen(self, choice) -> None:
        if choice:
            self._add_domain(choice)

    def _add_domain(self, raw: str) -> None:
        try:
            d = norm(raw)
        except ValueError as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        try:
            new_text, changed = self.cfg.add(d, self.text)
            new_rows = self.cfg.rows(new_text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        self.text, self.rows = new_text, new_rows
        if changed:
            self._invalidate_audit()
        self.fill_table()
        self.refresh_status()
        self.log_write(f"{'[green]added[/]' if changed else '[yellow]present[/]'} {d}")

    @on(DataTable.RowSelected)
    def row_selected(self) -> None:
        self.query_one(Input).focus()

    # ---------- actions ----------
    def action_focus_add(self) -> None:
        self.query_one(Input).focus()

    def action_blur_input(self) -> None:
        inp = self.query_one(Input)
        if inp.has_focus:
            inp.value = ""
            self.query_one(DataTable).focus()

    def action_delete(self) -> None:
        d = self.selected_domain()
        if not d:
            return
        try:
            new_text, changed = self.cfg.remove(d, self.text)
            new_rows = self.cfg.rows(new_text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        self.text, self.rows = new_text, new_rows
        if changed:
            self._invalidate_audit()
        self.fill_table()
        self.refresh_status()
        self.log_write(f"[yellow]deleted[/] {d} (press w to apply)")

    def action_sync(self) -> None:
        try:
            new_text, added = self.cfg.sync(self.text)
            new_rows = self.cfg.rows(new_text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        if not added:
            self.log_write("[dim]already in sync: every rule has a filter and vice versa[/]")
            return
        self.text, self.rows = new_text, new_rows
        self._invalidate_audit()
        self.fill_table()
        self.refresh_status()
        for d, kind in added:
            self.log_write(f"[cyan]+{kind}[/] {d}   (press w to apply)")

    def action_test_dns(self) -> None:
        d = self.selected_domain()
        if not d:
            return
        try:
            ip, state = self.cfg.dns(d)
        except (OSError, ValueError) as e:
            self.log_write(f"[red]DNS check failed:[/] {e}")
            return
        style = "red" if state == "FAKE-IP" else "green" if state == "ok" else "yellow"
        hint = ""
        if state == "no-record":
            hint = " [dim](apex has no address record — a concrete host such as mp.<domain> may still resolve)[/]"
        self.log_write(f"{d} -> [{style}]{ip} {state}[/]{hint}")

    def action_save(self) -> None:
        if self.applying:
            self.log_write("[yellow]apply in progress — not saving; wait for it to finish[/]")
            return
        if not self.dirty:
            self.log_write("[dim]no unsaved changes; override and .bak left untouched[/]")
            return
        text = self.text
        try:
            self.cfg.save(text, expect=self._saved_text)
        except (ValueError, OSError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        self._saved_text = text
        self.refresh_status()
        self.log_write("[green]saved[/] override (backup .bak); press w to apply")

    def action_reload(self) -> None:
        if self.applying:
            self.log_write("[yellow]apply in progress — not reloading; wait for it to finish[/]")
            return
        try:
            text = self.cfg.read()
            rows = self.cfg.rows(text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]reload FAILED:[/] {e} (previous state kept)")
            return
        was_dirty = self.dirty
        self.text, self.rows = text, rows
        self._saved_text = text
        self._invalidate_audit()
        self.fill_table()
        self._request_status_refresh()
        if was_dirty:
            self.log_write("[dim]reloaded from disk (unsaved edits discarded)[/]")
        else:
            self.log_write("[dim]reloaded from disk[/]")

    def action_apply(self) -> None:
        if self.applying:
            self.log_write("[yellow]apply already running — wait for it to finish[/]")
            return
        # Snapshot on the UI thread: the worker never reads mutable editor state.
        text = self.text
        rows = [r["domain"] for r in self.rows]
        needs_save = text != self._saved_text
        self._apply_text = text
        self._invalidate_audit()
        self.fill_table()
        self.refresh_status()
        self._apply_worker(text, rows, needs_save, self._saved_text)

    # Own group: a verify worker must never cancel an apply mid-write.
    @work(thread=True, exclusive=True, group="apply")
    def _apply_worker(self, text: str, rows, needs_save: bool, expect: str) -> None:
        self.call_from_thread(self.log_write, "[b]applying[/] save -> reload -> dns")
        if needs_save:
            try:
                self.cfg.save(text, expect=expect)
            except Exception as e:  # the guard must never be stranded
                self.call_from_thread(self._apply_save_failed, str(e))
                return
            # Only the snapshot that actually reached disk becomes clean;
            # any edits made while applying stay dirty.
            self.call_from_thread(self._apply_mark_saved, text)
        else:
            self.call_from_thread(self.log_write,
                                  "[dim]no unsaved changes: override not rewritten[/]")
        try:
            ok = self.cfg.apply(log=lambda m: self.call_from_thread(self.log_write, m),
                                domains=rows)
        except Exception as e:
            self.call_from_thread(self._apply_finished, False, f"{type(e).__name__}: {e}")
            return
        self.call_from_thread(self._apply_finished, ok, None)

    def _apply_mark_saved(self, text: str) -> None:
        self._saved_text = text
        self.refresh_status()

    def _apply_save_failed(self, message: str) -> None:
        self._apply_text = None
        self.log_write(f"[red]apply FAILED:[/] override not saved: {message}")
        self.refresh_status()

    def _apply_finished(self, ok: bool, error) -> None:
        self._apply_text = None
        if error is not None:
            self.log_write(f"[red]apply FAILED:[/] {error} — override saved, but the "
                           "generated config may not reflect it")
        elif ok and self.cfg.flclash:
            self.audit = {}
            self.fill_table()
            self.log_write("[green]saved[/] — select the profile in FlClash and reapply "
                           "it, then press v to re-verify")
        elif ok:
            self.audit = {}
            self.fill_table()
            self.log_write("[green]applied[/] (press v to re-verify)")
        else:
            # The override was written before clashtui/mihomo ran, so it is
            # newer than the generated config even though apply failed.
            self.log_write("[red]apply FAILED[/] — override saved, but the generated "
                           "config may not reflect it (see log above)")
        self._request_status_refresh()

    def action_verify(self) -> None:
        if self.applying:
            self.log_write("[yellow]apply in progress — wait before verifying[/]")
            return
        self._invalidate_audit()
        token = self._state_epoch
        rows = [r["domain"] for r in self.rows]
        self.fill_table()
        self._request_status_refresh()
        self._verify_worker(rows, token)

    @work(thread=True, exclusive=True, group="verify")
    def _verify_worker(self, rows, token: int) -> None:
        self.call_from_thread(self.log_write,
                              "[b]verifying[/] one probe per domain, reading the rule actually used")
        try:
            results = self.cfg.audit(log=lambda m: self.call_from_thread(self.log_write, m),
                                     domains=rows)
        except Exception as e:
            self.call_from_thread(self._verify_failed, token, str(e))
            return
        self.call_from_thread(self._after_verify, results, token)

    def _after_verify(self, results, token: int) -> None:
        if token != self._state_epoch:
            self.log_write("[dim]ignored stale verify results[/]")
            return
        self.audit = {r["domain"]: (r["verdict"], r["detail"]) for r in results}
        self.fill_table()
        self.refresh_status()

    def _verify_failed(self, token: int, message: str) -> None:
        if token != self._state_epoch:
            return
        self.log_write(f"[red]verify FAILED:[/] {message}")

    def action_quit(self) -> None:
        if self.dirty:
            self.log_write("[yellow]unsaved edits discarded[/]")
        self.exit()


def run(cfg=None):
    try:
        app = LanlockApp(cfg)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    app.run()


def main(argv=None):
    p = argparse.ArgumentParser(prog="lanlock-tui")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config-dir", default=None,
                   help="ClashTUI mihomo directory, or the FlClash data directory "
                        "(default: detect one; error when both are installed)")
    p.add_argument("--backend", choices=("clashtui", "flclash"), default=None,
                   help="which configuration to edit (default: detect)")
    p.add_argument("--api", default=DEFAULT_API,
                   help="Mihomo controller URL (default: %(default)s)")
    p.add_argument("--profile", default=None,
                   help="clashtui profile name, or a FlClash profile name or id "
                        "(auto-detected)")
    p.add_argument("--resolver", default=DEFAULT_RESOLVER,
                   help="resolvers written to dns.nameserver-policy for each domain in "
                        "a FlClash profile (default: %(default)s); a configured "
                        "direct-nameserver can bypass it unless "
                        "direct-nameserver-follow-policy is on")
    a = p.parse_args(argv)
    try:
        cfg = MihomoConfig(config_dir=a.config_dir, api=a.api, profile=a.profile,
                           resolver=a.resolver, backend=a.backend)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return run(cfg)
