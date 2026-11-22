"""Textual UI for lanlock."""
import argparse
import ipaddress
import sys
import threading
import time

from rich.markup import escape
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from . import __version__
from . import cli
from .config import DEFAULT_API, DEFAULT_RESOLVER, MihomoConfig, norm

VERDICT_STYLE = {
    "ok": "green",
    "LEAK": "bold red",
    "MISMATCH": "bold red",
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


def domain_scopes(raw, domain):
    """Offer the host and its suffixes, without a bare top-level label."""
    if raw.strip().startswith(("*.", "+.", ".")):
        return [domain]
    labels = domain.split(".")
    return [domain, *(".".join(labels[i:]) for i in range(1, len(labels) - 1))]


def covering_domain(host, domains):
    """Closest registered suffix, matching only on label boundaries."""
    domain = host
    while domain:
        if domain in domains:
            return domain
        _, _, domain = domain.partition(".")
    return None


def _needs_sync(row):
    return not row.get("match_target") and row["rule"] != row["filter"]


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


class _RuleChoice(ModalScreen):
    """Common keyboard navigation for the two rule choices."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=False),
        Binding("tab", "next_scope", "next scope", show=False, priority=True),
        Binding("shift+tab", "previous_scope", "previous scope", show=False, priority=True),
    ]

    CSS = """
    ScopeScreen, RouteScreen { align: center middle; }
    #rule-choice { width: 72; max-width: 100%; height: auto; max-height: 100%;
                   background: $panel; border: thick $primary; padding: 1 2; }
    #rule-options { height: auto; max-height: 60vh; }
    """

    def __init__(self, prompt, choices, note=None) -> None:
        super().__init__()
        self.prompt = prompt
        self.choices = choices
        self.note = note

    def compose(self) -> ComposeResult:
        with Vertical(id="rule-choice"):
            yield Static(self.prompt, markup=False)
            yield OptionList(*self.choices, id="rule-options")
            yield Static("[dim]Tab / ↑↓ move · Enter select · Esc cancel[/]")
            if self.note:
                yield Static(Text(self.note, style="dim"))

    def on_mount(self) -> None:
        options = self.query_one(OptionList)
        options.highlighted = 0
        options.focus()

    def action_next_scope(self) -> None:
        self.query_one(OptionList).action_cursor_down()

    def action_previous_scope(self) -> None:
        self.query_one(OptionList).action_cursor_up()

    @on(OptionList.OptionSelected)
    def _selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(event.option_id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ScopeScreen(_RuleChoice):
    def __init__(self, scopes, managed) -> None:
        options = []
        for scope in scopes:
            cover = covering_domain(scope, managed)
            suffix = (" · already added" if cover == scope else
                      f" · covered by +.{cover}" if cover else "")
            options.append(Option(f"+.{scope}{suffix}", id=scope))
        super().__init__("Choose a domain suffix", options,
                         "Each option covers the named domain and its subdomains.")


class RouteScreen(_RuleChoice):
    def __init__(self, domain, target, *, current=None) -> None:
        self.highlight = 1 if target and current == target else 0
        choices = [Option("DIRECT", id="direct")]
        if target and target != "DIRECT":
            choices.append(Option(Text(f"{target} (MATCH target)"), id="match"))
        prompt = f"Choose the outbound for +.{domain}"
        if current is not None:
            prompt += f" (current: {current})"
        super().__init__(prompt, choices,
                         "The selected outbound is saved to the draft only.")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one(OptionList).highlighted = self.highlight


class ControllerScreen(ModalScreen):
    """Enter the controller URL and secret for the rest of the session."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=False)]

    CSS = """
    ControllerScreen { align: center middle; }
    #controller-box { width: 84; height: auto; background: $panel; border: thick $primary; padding: 1 2; }
    #controller-box Input { margin: 0 0 1 0; }
    #controller-state { margin-bottom: 1; }
    #controller-help { color: $text-muted; }
    """

    def __init__(self, api, secret, state) -> None:
        super().__init__()
        self._api = api
        self._secret = secret
        self._state = state

    def compose(self) -> ComposeResult:
        with Vertical(id="controller-box"):
            yield Static(f"controller: {self._state}", id="controller-state")
            yield Input(value=self._api, placeholder="http://127.0.0.1:9090", id="api")
            yield Input(value=self._secret, password=True,
                        placeholder="secret (blank keeps the current one)", id="secret")
            yield Static("Enter applies to this session · Esc cancels", id="controller-help")

    @on(Input.Submitted)
    def _submitted(self, event: Input.Submitted) -> None:
        self.dismiss({"api": self.query_one("#api", Input).value.strip(),
                      "secret": self.query_one("#secret", Input).value.strip()})

    def action_cancel(self) -> None:
        self.dismiss(None)


class LiveScreen(ModalScreen):
    """Open connections plus recorded failures, with a state filter.

    Opening connections come from the mihomo controller, so a controller-less
    backend shows only recorded failures; ``controller_hint`` explains that.
    """

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

    FILTERS = ("all", "fail", "live", "new", "unmanaged")
    FILTER_LABEL = {"all": "all", "fail": "failed only", "live": "open only",
                    "new": "new open only", "unmanaged": "open, not added"}

    def __init__(self, load_connections, failures, controller_hint=None, managed=()) -> None:
        super().__init__()
        self._load = load_connections
        self._failures = failures
        self._hint = controller_hint or (lambda: "")
        self._active = []
        self._baseline = None
        self._managed = frozenset(managed)
        self._rows = []
        self._last_g = None
        self._filter = "all"
        self._error = None
        self._help = None
        self._timer = None

    def compose(self) -> ComposeResult:
        with Vertical(id="live-box"):
            yield Static("open connections · failed dials (this run + recorded)",
                         id="live-title")
            yield DataTable(id="live-table")
            yield Static("Enter add · j/k move · gg/G jump · f filter · Esc close", id="live-help")

    def on_mount(self) -> None:
        table = self.query_one("#live-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("state", "host", "port", "rule", "out", "n", "when", "managed")
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
            if self._baseline is None:
                self._baseline = {conn.get("id") for conn in self._active
                                  if isinstance(conn, dict) and conn.get("id")}
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
        connections = self._active
        if self._filter == "new":
            baseline = self._baseline or set()
            connections = (conn for conn in connections if isinstance(conn, dict)
                           and conn.get("id") and conn["id"] not in baseline)
        elif self._filter == "unmanaged":
            connections = (conn for conn in connections if isinstance(conn, dict)
                           and self._unmanaged((conn.get("metadata") or {}).get("host")))
        if self._filter != "fail":
            rows.extend(self._active_rows(connections))
        self._rows = rows
        table.clear(columns=False)
        for row in rows:
            style = "bold red" if row["state"] == "FAIL" else "dim"
            cover = self._cover(row["host"])
            status = ("added" if cover and cover == row["host"].lower().rstrip(".") else
                      f"via +.{cover}" if cover else "")
            table.add_row(Text(row["state"], style=style), row["host"], row["port"],
                          row["rule"], row["out"], row["n"], row.get("when", ""), status)
        if rows:
            table.move_cursor(row=min(max(0, keep), len(rows) - 1))
        self._show_help()

    def _cover(self, host):
        return covering_domain(host.lower().rstrip("."), self._managed)

    def _unmanaged(self, host):
        return bool(host and host != "?" and not _is_ip(host) and not self._cover(host))

    def _show_help(self, text=None) -> None:
        if self._help is None:
            return
        if text is None:
            text = (f"Enter add · j/k move · gg/G jump · f filter: "
                    f"{self.FILTER_LABEL[self._filter]} · Esc close")
            if self._error:
                text = f"[red]{self._error}[/]"
            elif not self._active:
                # An empty panel otherwise reads as "no traffic", not "no data".
                hint = self._hint()
                if hint:
                    text = f"[yellow]{hint}[/]"
        self._help.update(text)

    def action_cycle_filter(self) -> None:
        index = (self.FILTERS.index(self._filter) + 1) % len(self.FILTERS)
        self._filter = self.FILTERS[index]
        self._fill()

    # ---------- actions ----------
    def on_key(self, event) -> None:
        previous_g, self._last_g = self._last_g, None
        if event.key not in ("g", "G", "shift+g"):
            return
        event.stop()
        event.prevent_default()
        if not self._rows:
            return
        table = self.query_one("#live-table", DataTable)
        if event.key != "g":
            table.move_cursor(row=len(self._rows) - 1)
        else:
            now = time.monotonic()
            if previous_g is not None and now - previous_g < 1.0:
                table.move_cursor(row=0)
            else:
                self._last_g = now

    @on(DataTable.RowSelected)
    def _selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
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
    SUB_TITLE = "domain routing"

    CSS = """
    #status { height: 1; padding: 0 1; background: $panel; }
    #table { height: 1fr; }
    #add { height: 3; }
    #log { height: 10; border-top: solid $primary; }
    """

    BINDINGS = [
        Binding("a", "focus_add", "add"),
        Binding("e", "edit_route", "edit"),
        Binding("d", "delete", "delete"),
        Binding("s", "sync", "sync"),
        Binding("v", "verify", "verify"),
        Binding("t", "test_dns", "test"),
        Binding("w", "apply", "apply"),
        Binding("ctrl+s", "save", "save only", show=False),
        Binding("r", "reload", "reload"),
        Binding("c", "controller", "controller"),
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
        self.rules_total = None
        self.audit = {}
        # UI-thread state: the buffer, the last text known to be on disk, and
        # the snapshot of the one in-flight apply (None when idle).
        self._saved_text = self.text
        # The last editor snapshot accepted by apply, initialized from disk.
        self._submitted_text = self.text
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

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if len(self.screen_stack) > 1 and action != "quit":
            return False
        if action == "apply":
            return not self.applying and (self.dirty or self.text != self._submitted_text)
        if action == "sync":
            return any(_needs_sync(row) for row in self.rows)
        if action == "edit_route":
            return bool(self.rows) and isinstance(self.screen.focused, DataTable) and bool(
                (self._selected_row() or {}).get("rule"))
        if action == "save":
            return self.dirty and not self.applying
        return super().check_action(action, parameters)

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
        table.add_columns("domain", "outbound", "fake-ip-filter", "live")
        self.fill_table()
        table.focus()
        if not self.rows:
            self.log_write(f"[dim]no managed domains in {self.cfg.override} yet "
                           f"({self.rules_total} rules loaded); press a to add one[/]")
        self._load_history()
        self._request_status_refresh()
        self._watch_logs()

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
        errors = sum(1 for v in self.audit.values() if v[0] in ("LEAK", "MISMATCH"))
        verified = f"   route warnings: [bold red]{errors}[/]" if errors else ""
        unsynced = sum(_needs_sync(r) for r in self.rows)
        synced = f"   unsynced: [yellow]{unsynced}[/]" if unsynced else ""
        failed = "   status: [yellow]lookup failed[/]" if self._status_error else ""
        rules = f"   rules: {self.rules_total}" if self.rules_total is not None else ""
        self._status_line.update(
            f"profile: {prof}   controller: {controller}   "
            f"file: {self.cfg.override}   {state}{rules}{verified}{synced}{failed}")
        self.screen_stack[0].refresh_bindings()

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

    def action_controller(self) -> None:
        self.push_screen(
            ControllerScreen(self.cfg.api, self.cfg.secret, self.cfg.controller_state()),
            self._controller_chosen)

    def _controller_chosen(self, values) -> None:
        if not values or not self.is_running:
            return
        api = values.get("api") or self.cfg.api
        if not api.startswith(("http://", "https://")):
            self.log_write("[red]controller URL must start with http:// or https://[/]")
            return
        self.cfg.api = api
        if values.get("secret"):
            self.cfg.secret = values["secret"]
        self._request_status_refresh()
        self.log_write(f"[dim]controller: {api}[/]")

    def action_live(self) -> None:
        hint = self.cfg.controller_hint
        if self.cfg.controller_state() != "ready":
            self.log_write(f"[yellow]no live controller:[/] {hint()}")
        self.push_screen(LiveScreen(self.cfg.live_connections, self._failure_rows,
                                    controller_hint=hint, managed=self._managed_domains()),
                         self._live_chosen)

    def _failure_rows(self):
        return [dict(f) for f in self.failures]

    def _managed_domains(self):
        return {row["domain"] for row in self.rows if row["rule"]}

    def _live_chosen(self, host) -> None:
        if host:
            self._request_add(host)

    def action_cursor_down(self) -> None:
        self.query_one(DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one(DataTable).action_cursor_up()

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
        try:
            self.rules_total = self.cfg.rule_count(self.text)
        except (OSError, ValueError):
            self.rules_total = None
        table = self.query_one(DataTable)
        keep = table.cursor_row
        table.clear(columns=False)
        for row in self.rows:
            table.add_row(
                f"+.{row['domain']}",
                Text(row["match_target"], style="cyan") if row.get("match_target") else
                Text("DIRECT", style="green") if row["rule"] else Text("-", style="red"),
                Text("y", style="green") if row["filter"] else Text("-", style="red"),
                self._verdict_text(row["domain"]),
            )
        if self.rows:
            table.move_cursor(row=min(keep, len(self.rows) - 1))

    def _selected_row(self):
        table = self.query_one(DataTable)
        if not self.rows:
            return None
        idx = min(max(0, table.cursor_row), len(self.rows) - 1)
        return self.rows[idx]

    def selected_domain(self):
        row = self._selected_row()
        return row["domain"] if row else None

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
        managed = self._managed_domains()
        scopes = domain_scopes(raw, domain)
        if len(scopes) == 1:
            self._scope_chosen(domain)
            return
        self.push_screen(ScopeScreen(scopes, managed), self._scope_chosen)

    def _scope_chosen(self, choice) -> None:
        if not choice:
            return
        if any(r["domain"] == choice and r.get("match_target") for r in self.rows):
            self.log_write(f"[yellow]already added[/] +.{choice}")
            return
        try:
            target = self.cfg.match_target(self.text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        if target and target != "DIRECT" and choice not in self._managed_domains():
            self.push_screen(RouteScreen(choice, target),
                             lambda route: self._route_chosen(choice, route, target))
        else:
            self._route_chosen(choice, "direct", None)

    def _route_chosen(self, domain, route, target) -> None:
        if route is None:
            return
        cover = covering_domain(domain, self._managed_domains())
        if cover and cover != domain:
            row = next(row for row in self.rows if row["domain"] == cover)
            if row.get("match_target") == (target if route == "match" else None):
                self.log_write(f"[yellow]+.{domain} is already covered by +.{cover}[/]")
                return
        self._add_domain(domain, match_target=target if route == "match" else None)

    def _add_domain(self, raw: str, *, match_target=None) -> None:
        try:
            d = norm(raw)
        except ValueError as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        try:
            if match_target:
                new_text, changed = self.cfg.add_match(d, self.text, target=match_target)
            else:
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
        self.log_write(f"{'[green]added[/]' if changed else '[yellow]already added[/]'} "
                       f"+.{d} → {escape(match_target or 'DIRECT')}")

    @on(DataTable.RowHighlighted, "#table")
    def _refresh_edit_binding(self) -> None:
        self.screen_stack[0].refresh_bindings()

    @on(DataTable.RowSelected, "#table")
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

    def action_edit_route(self) -> None:
        row = self._selected_row()
        if not row or not row["rule"]:
            return
        domain = row["domain"]
        current = row.get("match_target", "DIRECT")
        try:
            target = self.cfg.match_target(self.text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        if not target or target == "DIRECT":
            if current == "DIRECT":
                self.log_write("[dim]No non-DIRECT MATCH target in the editable rules.[/]")
                return
        self.push_screen(RouteScreen(domain, target, current=current),
                         lambda choice: self._edit_route_chosen(domain, choice, target))

    def _edit_route_chosen(self, domain, choice, target) -> None:
        if choice is None:
            return
        outbound = target if choice == "match" else "DIRECT"
        try:
            text, changed = self.cfg.set_outbound(domain, self.text, target=outbound)
            if not changed:
                return
            rows = self.cfg.rows(text)
        except (ValueError, OSError, RuntimeError) as e:
            self.log_write(f"[red]error:[/] {e}")
            return
        self.text, self.rows = text, rows
        self._invalidate_audit()
        self.fill_table()
        self.refresh_status()
        self.log_write(f"[green]updated[/] +.{domain} → {escape(outbound)}")

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
        self.log_write(f"[yellow]deleted[/] +.{d}")

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
            self.log_write(f"[cyan]+{kind}[/] +.{d}")

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
        self.log_write("[green]saved[/] override (backup .bak)")

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
        if ok:
            self._submitted_text = self._apply_text
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
        self._verify_worker(rows, token, self.text)

    @work(thread=True, exclusive=True, group="verify")
    def _verify_worker(self, rows, token: int, text: str) -> None:
        self.call_from_thread(self.log_write,
                              "[b]verifying[/] one probe per domain, reading the rule actually used")
        try:
            results = self.cfg.audit(log=lambda m: self.call_from_thread(self.log_write, m),
                                     domains=rows, text=text)
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
    cli._tolerant_stdio()
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
    p.add_argument("--secret", default=None,
                   help="controller secret (default: $LANLOCK_API_SECRET, then the "
                        "secret stored in FlClash's External Controller settings)")
    p.add_argument("--resolver", default=DEFAULT_RESOLVER,
                   help="resolvers written to dns.nameserver-policy for each domain in "
                        "a FlClash profile (default: %(default)s); a configured "
                        "direct-nameserver can bypass it unless "
                        "direct-nameserver-follow-policy is on")
    a = p.parse_args(argv)
    try:
        cfg = MihomoConfig(config_dir=a.config_dir, api=a.api, profile=a.profile,
                           resolver=a.resolver, backend=a.backend, secret=a.secret)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return run(cfg)
