"""Textual UI for lanlock."""
import argparse
import threading

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widgets import DataTable, Footer, Header, Input, RichLog, Static

from .config import DEFAULT_API, DEFAULT_CONFIG_DIR, MihomoConfig, norm

VERDICT_STYLE = {
    "ok": "green",
    "LEAK": "bold red",
    "FAKE-IP": "yellow",
    "skip": "dim",
    "unknown": "dim yellow",
}


class StatusLoaded(Message):
    """Off-thread result of the clashtui/controller status lookup."""

    def __init__(self, request_id: int, snapshot, error) -> None:
        super().__init__()
        self.request_id = request_id
        self.snapshot = snapshot
        self.error = error


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
        self._request_status_refresh()
        self.log_write("[dim]a add · d delete · y sync rule/filter · v verify · t dns · "
                       "w apply · s save · r reload · q quit[/]")

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
            self._add_domain(raw)

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
            self.cfg.save(text)
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
        self._apply_worker(text, rows, needs_save)

    # Own group: a verify worker must never cancel an apply mid-write.
    @work(thread=True, exclusive=True, group="apply")
    def _apply_worker(self, text: str, rows, needs_save: bool) -> None:
        self.call_from_thread(self.log_write, "[b]applying[/] save -> clashtui reload -> dns")
        if needs_save:
            try:
                self.cfg.save(text)
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
    LanlockApp(cfg).run()


def main(argv=None):
    p = argparse.ArgumentParser(prog="lanlock-tui")
    p.add_argument("--config-dir", default=DEFAULT_CONFIG_DIR)
    p.add_argument("--api", default=DEFAULT_API,
                   help="Mihomo controller URL (default: %(default)s)")
    p.add_argument("--profile", default=None, help="clashtui profile (auto-detected)")
    a = p.parse_args(argv)
    run(MihomoConfig(config_dir=a.config_dir, api=a.api, profile=a.profile))
