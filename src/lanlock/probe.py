"""Probe what mihomo actually does with a domain.

TCP to a TUN address "connects" even when the far side is unreachable, so the
verdict comes from mihomo itself: the fast path reads /connections, the
fallback reads the controller's /logs stream (a failed DIRECT dial only shows
up there).

Neither source gives strict per-connection attribution: /connections entries
are matched by host and port, log lines by the exact destination token
``domain:port``. A concurrent probe of the same domain can therefore contribute
evidence; only a nonempty outbound chain or a parsed rule decision is treated
as evidence, and a FAKE-IP DNS answer with no evidence is still reported as
FAKE-IP rather than guessed at.
"""
import http.client
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .config import DEFAULT_API, dns_check

MATCH_USING = re.compile(r"match (.+?) using (.+)$")
DIAL_FAILED = re.compile(r"dial (.+?) \(match ([^)]+)\)")
# The destination token after the connection arrow: host:port, and not a
# port-prefix of a longer number.
DESTINATION = re.compile(r"-->\s*([A-Za-z0-9_.-]+):(\d+)(?![\w.:-])")

API_TIMEOUT = 2.0
CONNECTION_WINDOW = 2.0
CONNECTION_POLL = 0.15
LOG_WINDOW = 3.0
LOG_STREAM_TIMEOUT = 0.5
LOG_START_GRACE = 0.05
LOG_BUFFER_MAX = 65536
WATCH_TIMEOUT = 1.0
WATCH_RETRY_DELAY = 0.5


def _log_remaining(deadline):
    """Seconds left before ``deadline``, never 0 (0 makes a socket non-blocking)."""
    return max(deadline - time.monotonic(), 0.001)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject controller redirects instead of forwarding credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    # An empty proxy map keeps local controller calls off any ambient HTTP_PROXY.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       _NoRedirect())


def _auth_headers(secret=None):
    """Bearer header for the controller: the explicit secret, else the env var."""
    token = secret or os.environ.get("LANLOCK_API_SECRET")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _api_request(path, api=DEFAULT_API, timeout=API_TIMEOUT, secret=None):
    url = api.rstrip("/") + path
    request = urllib.request.Request(url, headers=_auth_headers(secret), method="GET")
    return _opener().open(request, timeout=timeout)


def _api_json(path, api=DEFAULT_API, timeout=API_TIMEOUT, secret=None):
    with _api_request(path, api, timeout, secret) as response:
        return json.load(response)


def controller_state(api=DEFAULT_API, timeout=1.0, secret=None):
    """Return ``ready``, ``unauthorized`` or ``unavailable`` for the controller."""
    try:
        info = _api_json("/version", api, timeout, secret)
    except urllib.error.HTTPError as exc:
        return "unauthorized" if exc.code in (401, 403) else "unavailable"
    except (OSError, http.client.HTTPException, ValueError):
        return "unavailable"
    if not isinstance(info, dict):
        return "unavailable"
    version = info.get("version")
    if info.get("meta") is True and isinstance(version, str) and version.strip():
        return "ready"
    return "unavailable"


def live_connections(api=DEFAULT_API, secret=None):
    try:
        body = _api_json("/connections", api, API_TIMEOUT, secret)
    except (OSError, http.client.HTTPException, ValueError):
        return []
    connections = body.get("connections") if isinstance(body, dict) else None
    return connections if isinstance(connections, list) else []


def _log_payload(raw):
    """Return the text payload of one /logs NDJSON entry, or ""."""
    try:
        entry = json.loads(raw)
    except (TypeError, ValueError):
        return ""
    payload = entry.get("payload") if isinstance(entry, dict) else None
    return payload if isinstance(payload, str) else ""


def _log_connection(api, secret=None):
    """Send the /logs subscription request; its body is read after the dial."""
    parts = urllib.parse.urlsplit(api)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("unsupported controller URL")
    cls = (http.client.HTTPSConnection if parts.scheme == "https"
           else http.client.HTTPConnection)
    connection = cls(parts.hostname, parts.port, timeout=LOG_STREAM_TIMEOUT)
    try:
        path = parts.path.rstrip("/") + "/logs?level=info"
        connection.request("GET", path, headers=_auth_headers(secret))
    except (OSError, http.client.HTTPException, ValueError):
        connection.close()
        raise
    return connection


class _LogStream:
    """A /logs subscription opened before the dial and read afterwards.

    ClashTUI's server does not flush response headers until the first log line,
    so waiting for headers before the dial would deadlock; the request is sent
    up front and the response is collected only after the connection attempt.
    """

    def __init__(self, api, domain, port, secret=None):
        self._domain = domain
        self._port = port
        self._connection = None
        try:
            self._connection = _log_connection(api, secret)
        except (OSError, http.client.HTTPException, ValueError):
            self.close()

    def evidence(self, deadline):
        """Read the stream until ``deadline`` and return a decision or None.

        The subscription is opened with the short connect/request timeout, but
        headers may not flush until the first log line and the body then
        streams. Both waits get what remains of the fallback window instead of
        that short timeout.
        """
        connection = self._connection
        if connection is None:
            return None
        # getresponse() passes the socket to the response when the controller
        # will close the connection, so keep our own reference for timeouts.
        sock = connection.sock
        response = None
        buffer = b""
        try:
            if time.monotonic() >= deadline:
                return None
            sock.settimeout(_log_remaining(deadline))
            response = connection.getresponse()
            while response.status == 200 and time.monotonic() < deadline:
                sock.settimeout(_log_remaining(deadline))
                try:
                    chunk = response.read1(4096)
                except (OSError, http.client.HTTPException, ValueError):
                    # A response whose socket read timed out cannot be reused.
                    return None
                if not chunk:
                    return None
                buffer += chunk
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    decision = _decision(_log_payload(raw), self._domain, self._port)
                    if decision:
                        return decision
                if len(buffer) > LOG_BUFFER_MAX:
                    return None
            return None
        except (OSError, http.client.HTTPException, ValueError):
            return None
        finally:
            if response is not None:
                try:
                    response.close()
                except OSError:
                    pass
            self.close()

    def close(self):
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


def _parse_log_line(line):
    m = MATCH_USING.search(line)
    if m:
        rule, outbound = m.group(1), m.group(2)
        kind, sep, payload = rule.partition("(")
        if sep and payload.endswith(")"):
            return kind, payload[:-1], outbound
    else:
        m = DIAL_FAILED.search(line)
        if not m:
            return None
        outbound, rule = m.group(1), m.group(2)
    rule, _, payload = rule.partition("/")
    return rule, payload, outbound


def _matches_destination(line, domain, port):
    """True only when ``line`` carries the exact ``domain:port`` token.

    ``domain:4433`` must not count as evidence for port 443.
    """
    domain, port = domain.lower(), str(port)
    return any(host.lower() == domain and number == port
               for host, number in DESTINATION.findall(line))


def parse_failure(payload):
    """Return the failed dial described by one log payload, or None.

    Only lines that carry a rule decision and an ``error:`` are kept; DNS and
    other warnings have no destination token to offer as a domain.
    """
    if not isinstance(payload, str) or " error:" not in payload:
        return None
    decision = _parse_log_line(payload)
    arrow = payload.find("-->")
    destination = (DESTINATION.search(payload, arrow)
                   if arrow != -1 else None)
    if decision is None or destination is None:
        return None
    rule, rule_payload, outbound = decision
    return {"host": destination.group(1), "port": int(destination.group(2)),
            "rule": rule, "payload": rule_payload, "outbound": outbound,
            "detail": payload}


def _watch_once(api, stop, secret=None):
    """Yield failures until the stream idles, drops, or ``stop`` is set.

    mihomo sends no response headers until the first log line, so the short
    socket timeout is also the idle reconnect period; closing and reopening is
    cheaper for the caller than a blocked read that cannot observe ``stop``.
    """
    parts = urllib.parse.urlsplit(api)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("unsupported controller URL")
    cls = (http.client.HTTPSConnection if parts.scheme == "https"
           else http.client.HTTPConnection)
    connection = cls(parts.hostname, parts.port, timeout=WATCH_TIMEOUT)
    try:
        connection.request("GET", parts.path.rstrip("/") + "/logs?level=warning",
                           headers=_auth_headers())
        sock = connection.sock
        try:
            response = connection.getresponse()
        except TimeoutError:
            return
        if response.status in (401, 403):
            # A wrong or missing secret will not fix itself; let the caller say so.
            raise ValueError(f"controller /logs returned HTTP {response.status} "
                             "(check LANLOCK_API_SECRET)")
        if response.status != 200:
            raise OSError(f"controller /logs returned HTTP {response.status}")
        buffer = b""
        while stop is None or not stop.is_set():
            try:
                sock.settimeout(WATCH_TIMEOUT)
                chunk = response.read1(4096)
            except TimeoutError:
                return
            except (OSError, http.client.HTTPException):
                return
            if not chunk:
                # A closed stream must back off; a timeout only reconnects.
                raise OSError("controller closed the log stream")
            buffer += chunk
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                payload = _log_payload(raw)
                failure = parse_failure(payload) if payload else None
                if failure is not None:
                    yield failure
            if len(buffer) > LOG_BUFFER_MAX:
                return
    finally:
        try:
            connection.close()
        except OSError:
            pass


def watch_failures(api=DEFAULT_API, stop=None, secret=None):
    """Yield failed dials from the controller's /logs stream until ``stop`` is set.

    The stream is reopened after idle timeouts so a TUI can shut down promptly;
    a controller that refuses the subscription backs off instead of spinning.
    """
    while stop is None or not stop.is_set():
        try:
            yield from _watch_once(api, stop, secret)
        except (OSError, http.client.HTTPException):
            if stop is not None:
                if stop.wait(WATCH_RETRY_DELAY):
                    return
            else:
                time.sleep(WATCH_RETRY_DELAY)


def _decision(line, domain, port):
    """Return (rule, payload, outbound) for ``domain:port`` in ``line``, or None."""
    if not _matches_destination(line, domain, port):
        return None
    return _parse_log_line(line)


def _api_evidence(domain, port, api=DEFAULT_API, secret=None, *, with_target=False):
    """Read the rule and leaf outbound; optionally return the outermost target.

    An empty chain is not evidence; fall back to the log stream.
    """
    for conn in live_connections(api, secret):
        md = conn.get("metadata") or {}
        if md.get("host") != domain or str(md.get("destinationPort")) != str(port):
            continue
        chains = conn.get("chains") or []
        outbound = chains[0] if chains else ""
        if not outbound:
            continue
        evidence = (conn.get("rule") or "?", conn.get("rulePayload") or "", outbound)
        return (*evidence, chains[-1]) if with_target else evidence
    return None


def _result(domain, dns_state, ip, rule, payload, outbound, observed_target=None, *,
            match_target=None):
    direct = outbound.split("[")[0] == "DIRECT"
    verdict = "ok" if direct else "LEAK"
    if direct and dns_state == "FAKE-IP":
        verdict = "FAKE-IP"
    detail = (f"{rule}({payload})" if payload else str(rule)) + f" -> {outbound}"
    if match_target:
        suffix_matched = (rule.lower().replace("-", "") == "domainsuffix"
                          and payload.lower().rstrip(".") == domain)
        if not suffix_matched or observed_target is not None and observed_target != match_target:
            verdict = "MISMATCH"
        elif observed_target or outbound == match_target or outbound.startswith(match_target + "["):
            verdict = "ok"
        else:
            verdict = "unknown"  # a log entry may show only the selected node
        detail += f" (expected +.{domain} -> {match_target}"
        if observed_target and observed_target != outbound:
            detail += f"; observed target {observed_target}"
        detail += ")"
    return {"domain": domain, "dns": dns_state, "ip": ip, "verdict": verdict,
            "detail": detail, "rule": rule, "outbound": outbound}


def probe(domain, api=DEFAULT_API, port=443, *, networks=None, secret=None, match_target=None):
    """Open one connection and report the newest observed rule decision for it."""
    ip, dns_state = dns_check(domain, networks=networks)
    if dns_state == "no-record":
        return {"domain": domain, "dns": dns_state, "ip": ip, "verdict": "skip",
                "detail": "no address record", "rule": "-", "outbound": "-"}
    logs = _LogStream(api, domain, port, secret)
    sock = None
    try:
        # Let the controller register the already-sent /logs subscription.
        time.sleep(LOG_START_GRACE)
        try:
            sock = socket.create_connection((domain, port), timeout=3)
        except OSError:
            pass
        deadline = time.monotonic() + CONNECTION_WINDOW
        while time.monotonic() < deadline:
            evidence = _api_evidence(domain, port, api, secret, with_target=bool(match_target))
            if evidence:
                return _result(domain, dns_state, ip, *evidence, match_target=match_target)
            time.sleep(CONNECTION_POLL)
        evidence = logs.evidence(time.monotonic() + LOG_WINDOW)
        if evidence:
            return _result(domain, dns_state, ip, *evidence, match_target=match_target)
    finally:
        logs.close()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    verdict = "FAKE-IP" if not match_target and dns_state == "FAKE-IP" else "unknown"
    return {"domain": domain, "dns": dns_state, "ip": ip, "verdict": verdict,
            "detail": "no rule decision observed", "rule": "-", "outbound": "-"}


def audit(domains, api=DEFAULT_API, log=print, *, networks=None, secret=None, match_targets=None):
    """Probe every domain in parallel; log one line each and a summary."""
    workers = min(8, max(1, len(domains)))
    match_targets = match_targets or {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(
            lambda d: probe(d, api, networks=networks, secret=secret,
                            match_target=match_targets.get(d)), domains))
    for r in results:
        log("  %-36s %-8s dns=%-9s %s" % (r["domain"], r["verdict"], r["dns"], r["detail"]))
    leaks = sum(r["verdict"] == "LEAK" for r in results)
    mismatches = sum(r["verdict"] == "MISMATCH" for r in results)
    fake = [r for r in results if r["verdict"] == "FAKE-IP"]
    skipped = [r for r in results if r["verdict"] in ("skip", "unknown")]
    summary = f"audit: {len(results)} checked, {leaks} leak, {len(fake)} fake-ip, "
    if mismatches:
        summary += f"{mismatches} route mismatch, "
    log(summary + f"{len(skipped)} skip/unknown")
    return results
