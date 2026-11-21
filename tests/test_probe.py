"""Deterministic probe tests using mocks or a loopback HTTP server."""
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import import_module
from pathlib import Path
from threading import Event, Thread
from time import sleep as real_sleep
from types import SimpleNamespace

import pytest

from lanlock import MihomoConfig, cli
from lanlock import config as config_mod

probe_mod = import_module("lanlock.probe")
RealLogStream = probe_mod._LogStream

DOMAIN = "internal.example"
KEYS = {"domain", "dns", "ip", "verdict", "detail", "rule", "outbound"}


class _Sock:
    def __init__(self, timeout=0.0):
        self.timeout = timeout
        self.closed = False

    def settimeout(self, seconds):
        self.timeout = seconds

    def close(self):
        self.closed = True


class _Response:
    def __init__(self, body=b"", lines=(), status=200):
        self.body = body
        self.lines = list(lines)
        self.status = status
        self.closed = False
        self.reads = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self):
        return self.body

    def read1(self, size=-1):
        self.reads += 1
        if self.closed:
            raise ValueError("read of closed file")
        return self.lines.pop(0) if self.lines else b""

    def close(self):
        self.closed = True


class _Connection:
    def __init__(self, response, sock=None):
        self.response = response
        self.sock = (sock if sock is not None
                     else _Sock(probe_mod.LOG_STREAM_TIMEOUT))
        self.closed = False

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class _NoLogs:
    """Stand-in for the /logs subscription when no evidence is expected."""

    def __init__(self, api, domain, port):
        pass

    def evidence(self, deadline=None):
        return None

    def close(self):
        pass


@pytest.fixture
def isolated(monkeypatch):
    """No sockets, waiting, or controller log streams; windows set per test."""
    monkeypatch.setattr(probe_mod, "socket",
                        SimpleNamespace(create_connection=lambda *a, **k: _Sock()))
    monkeypatch.setattr(probe_mod.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(probe_mod, "CONNECTION_WINDOW", 0.0)
    monkeypatch.setattr(probe_mod, "LOG_WINDOW", 0.0)
    monkeypatch.setattr(probe_mod, "_LogStream", _NoLogs)
    return monkeypatch


def dns(monkeypatch, state, ip="203.0.113.7"):
    monkeypatch.setattr(probe_mod, "dns_check",
                        lambda _domain, *, networks=None: (ip, state))


def generated(cfg, text):
    """Write a generated mihomo config at MihomoConfig's resolved path."""
    path = Path(cfg.generated)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def resolver(monkeypatch, address, family=socket.AF_INET):
    """Make config.dns_check see one address without a real lookup."""
    sockaddr = (address, 0) if family == socket.AF_INET else (address, 0, 0, 0)
    monkeypatch.setattr(
        config_mod.socket, "getaddrinfo",
        lambda host, port, *, type: [(family, type, 0, "", sockaddr)])


def line(domain, port, outbound, rule=None):
    rule = f"DomainSuffix({domain})" if rule is None else rule
    return f"[TCP] 127.0.0.1:5555 --> {domain}:{port} match {rule} using {outbound}"


def logs(monkeypatch, evidence):
    class Logs(_NoLogs):
        def evidence(self, deadline=None):
            return evidence

    monkeypatch.setattr(probe_mod, "_LogStream", Logs)


def ndjson(payload):
    return json.dumps({"type": "info", "payload": payload}).encode()


def test_api_entry_without_chain_falls_through_to_logs(isolated, monkeypatch):
    dns(monkeypatch, "ok")
    calls = []

    def connections(api):
        calls.append(api)
        return [
            {"metadata": {"host": DOMAIN, "destinationPort": 443},
             "rule": "MATCH", "rulePayload": "", "chains": []},
            {"metadata": {"host": DOMAIN, "destinationPort": 443},
             "rule": "MATCH", "rulePayload": ""},
        ]

    monkeypatch.setattr(probe_mod, "live_connections", connections)
    logs(monkeypatch, ("DomainSuffix", DOMAIN, "DIRECT"))
    # Let the API window really run, without busy-spinning on a no-op sleep.
    monkeypatch.setattr(probe_mod.time, "sleep", lambda seconds: real_sleep(0.005))
    monkeypatch.setattr(probe_mod, "CONNECTION_WINDOW", 0.03)
    monkeypatch.setattr(probe_mod, "LOG_WINDOW", 0.2)

    assert probe_mod._api_evidence(DOMAIN, 443) is None
    calls.clear()
    result = probe_mod.probe(DOMAIN)
    assert calls
    assert set(result) == KEYS
    assert result["verdict"] == "ok"
    assert result["outbound"] == "DIRECT"
    assert result["rule"] == "DomainSuffix"
    assert result["detail"] == f"DomainSuffix({DOMAIN}) -> DIRECT"


def test_api_entry_with_chain_is_used_and_leak_wins(isolated):
    monkeypatch = isolated
    dns(monkeypatch, "FAKE-IP", "198.18.0.9")
    monkeypatch.setattr(probe_mod, "live_connections", lambda api: [
        {"metadata": {"host": DOMAIN, "destinationPort": 443},
         "rule": "MATCH", "rulePayload": "", "chains": ["PROXY"]},
    ])
    monkeypatch.setattr(probe_mod, "CONNECTION_WINDOW", 0.2)

    assert probe_mod._api_evidence(DOMAIN, 443) == ("MATCH", "", "PROXY")
    result = probe_mod.probe(DOMAIN)
    assert result["verdict"] == "LEAK"
    assert result["outbound"] == "PROXY"


def test_similar_port_line_is_not_evidence():
    older = line(DOMAIN, 443, "PROXY")
    new_similar = line(DOMAIN, 4433, "DIRECT")

    assert not probe_mod._matches_destination(new_similar, DOMAIN, 443)
    assert probe_mod._matches_destination(new_similar, DOMAIN, 4433)
    assert not probe_mod._matches_destination(line(DOMAIN, 4430, "DIRECT"),
                                              DOMAIN, 443)
    assert probe_mod._decision(new_similar, DOMAIN, 443) is None
    assert probe_mod._decision(older, DOMAIN, 443) == (
        "DomainSuffix", DOMAIN, "PROXY")


def test_connecting_line_is_not_evidence():
    connecting = f"[TCP] 127.0.0.1:5555 --> {DOMAIN}:443 connecting"
    assert probe_mod._decision(connecting, DOMAIN, 443) is None


def test_failed_dial_preserves_rule_payload_with_slash():
    line = (f"[TCP] dial DIRECT (match IPCIDR/192.0.2.0/24) "
            f"127.0.0.1:5555 --> {DOMAIN}:443 error: timeout")
    assert probe_mod._decision(line, DOMAIN, 443) == (
        "IPCIDR", "192.0.2.0/24", "DIRECT")


def test_log_payload_is_extracted_from_ndjson():
    payload = line(DOMAIN, 443, "DIRECT")
    assert probe_mod._log_payload(ndjson(payload)) == payload
    assert probe_mod._log_payload(b"not json") == ""
    assert probe_mod._log_payload(b'["not", "an", "object"]') == ""
    assert probe_mod._log_payload(b'{"type": "info"}') == ""


def test_log_stream_captures_matching_decision(monkeypatch):
    response = _Response(lines=[
        b"not json\n",
        ndjson(line(DOMAIN, 4433, "PROXY")) + b"\n",
        ndjson(f"[TCP] 127.0.0.1:5555 --> {DOMAIN}:443 connecting") + b"\n",
        ndjson(line(DOMAIN, 443, "DIRECT")) + b"\n",
    ])
    connection = _Connection(response)
    monkeypatch.setattr(probe_mod, "_log_connection", lambda api: connection)

    stream = probe_mod._LogStream(probe_mod.DEFAULT_API, DOMAIN, 443)
    assert stream.evidence(time.monotonic() + 1.0) == (
        "DomainSuffix", DOMAIN, "DIRECT")
    assert response.closed
    assert connection.closed


def test_log_stream_subscription_failure_is_bounded(monkeypatch):
    def unavailable(api):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(probe_mod, "_log_connection", unavailable)
    stream = probe_mod._LogStream(probe_mod.DEFAULT_API, DOMAIN, 443)
    assert stream.evidence(time.monotonic() + 1.0) is None


def test_log_stream_rejects_non_200_and_closes(monkeypatch):
    response = _Response(status=302)
    connection = _Connection(response)
    monkeypatch.setattr(probe_mod, "_log_connection", lambda api: connection)

    stream = probe_mod._LogStream(probe_mod.DEFAULT_API, DOMAIN, 443)
    assert stream.evidence(time.monotonic() + 1.0) is None
    assert response.closed
    assert connection.closed


def test_log_stream_body_read_uses_remaining_window(monkeypatch):
    """The 0.5 s subscription timeout must not cap the body read."""
    sock = _Sock(timeout=probe_mod.LOG_STREAM_TIMEOUT)

    class Body(_Response):
        def read1(self, size=-1):
            # Fail the way http.client does when the subscription timeout is
            # still in effect: a later decision must still be accepted.
            if sock.timeout <= probe_mod.LOG_STREAM_TIMEOUT:
                raise TimeoutError("socket read timed out")
            return super().read1(size)

    response = Body(lines=[ndjson(line(DOMAIN, 443, "DIRECT")) + b"\n"])
    connection = _Connection(response, sock=sock)
    monkeypatch.setattr(probe_mod, "_log_connection", lambda api: connection)

    stream = probe_mod._LogStream(probe_mod.DEFAULT_API, DOMAIN, 443)
    assert stream.evidence(time.monotonic() + 1.0) == (
        "DomainSuffix", DOMAIN, "DIRECT")
    assert sock.timeout > probe_mod.LOG_STREAM_TIMEOUT
    assert response.closed
    assert connection.closed


def test_log_stream_exhausted_deadline_does_not_wait_for_headers(monkeypatch):
    response = _Response(lines=[ndjson(line(DOMAIN, 443, "DIRECT")) + b"\n"])
    connection = _Connection(response)
    monkeypatch.setattr(probe_mod, "_log_connection", lambda api: connection)
    monkeypatch.setattr(connection, "getresponse",
                        lambda: pytest.fail("deadline already exhausted"))

    stream = probe_mod._LogStream(probe_mod.DEFAULT_API, DOMAIN, 443)
    assert stream.evidence(time.monotonic() - 1.0) is None
    assert connection.closed


def test_log_stream_abandons_response_after_read_timeout(monkeypatch):
    class TimedOut(_Response):
        def read1(self, size=-1):
            self.reads += 1
            raise TimeoutError("socket read timed out")

    response = TimedOut()
    connection = _Connection(response)
    monkeypatch.setattr(probe_mod, "_log_connection", lambda api: connection)

    stream = probe_mod._LogStream(probe_mod.DEFAULT_API, DOMAIN, 443)
    assert stream.evidence(time.monotonic() + 1.0) is None
    assert response.reads == 1
    assert response.closed
    assert connection.closed


def test_probe_accepts_log_decision_after_subscription_timeout(isolated,
                                                               monkeypatch):
    """A line arriving after the subscription timeout is still evidence."""
    dns(monkeypatch, "ok")
    monkeypatch.setattr(probe_mod, "_LogStream", RealLogStream)
    monkeypatch.setattr(probe_mod, "CONNECTION_WINDOW", 0.0)
    monkeypatch.setattr(probe_mod, "LOG_WINDOW", 3.0)
    monkeypatch.setattr(probe_mod, "LOG_STREAM_TIMEOUT", 0.25)

    class Controller(BaseHTTPRequestHandler):
        def do_GET(self):
            if not self.path.startswith("/logs"):
                self.send_error(404)
                return
            # ClashTUI flushes headers only with the first log line: later
            # than the subscription timeout, inside the fallback window.
            real_sleep(0.6)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(ndjson(line(DOMAIN, 443, "DIRECT")) + b"\n")

        def log_message(self, *args):
            pass

    with HTTPServer(("127.0.0.1", 0), Controller) as server:
        api = f"http://127.0.0.1:{server.server_port}"
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            result = probe_mod.probe(DOMAIN, api=api)
        finally:
            server.shutdown()
            thread.join()

    assert result["verdict"] == "ok"
    assert result["detail"] == f"DomainSuffix({DOMAIN}) -> DIRECT"
    assert result["outbound"] == "DIRECT"


def test_log_connection_subscribes_before_reading(monkeypatch):
    seen = {}

    class Connection:
        def __init__(self, host, port, timeout=None):
            seen.update(host=host, port=port, timeout=timeout)

        def request(self, method, path, headers=None):
            seen.update(method=method, path=path, headers=headers)

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(probe_mod.http.client, "HTTPConnection", Connection)
    monkeypatch.setenv("LANLOCK_API_SECRET", "s3cret")

    assert probe_mod._log_connection("http://127.0.0.1:9090/base/")
    assert seen == {
        "host": "127.0.0.1", "port": 9090,
        "timeout": probe_mod.LOG_STREAM_TIMEOUT,
        "method": "GET", "path": "/base/logs?level=info",
        "headers": {"Authorization": "Bearer s3cret"},
    }


def test_log_connection_closes_on_request_failure(monkeypatch):
    closed = []

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, headers=None):
            raise OSError("no controller")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(probe_mod.http.client, "HTTPConnection", Connection)
    with pytest.raises(OSError):
        probe_mod._log_connection("http://127.0.0.1:9090")
    assert closed


def test_probe_subscribes_to_logs_before_dialing(isolated, monkeypatch):
    dns(monkeypatch, "ok")
    order = []

    class Logs:
        def __init__(self, api, domain, port):
            order.append("logs")

        def evidence(self, deadline=None):
            return ("MATCH", "", "DIRECT")

        def close(self):
            pass

    def connect(*args, **kwargs):
        order.append("dial")
        return _Sock()

    monkeypatch.setattr(probe_mod, "_LogStream", Logs)
    monkeypatch.setattr(probe_mod, "socket",
                        SimpleNamespace(create_connection=connect))
    monkeypatch.setattr(probe_mod, "LOG_WINDOW", 0.2)

    result = probe_mod.probe(DOMAIN)
    assert order[:2] == ["logs", "dial"]
    assert result["outbound"] == "DIRECT"


def test_probe_has_no_os_service_fallback():
    assert not hasattr(probe_mod, "journal_since")
    assert not hasattr(probe_mod, "DEFAULT_SERVICE")
    assert "subprocess" not in vars(probe_mod)


def test_no_address_record_skips_controller(isolated, monkeypatch):
    dns(monkeypatch, "no-record", "-")
    monkeypatch.setattr(probe_mod, "_LogStream",
                        lambda *a: pytest.fail("controller must not be contacted"))

    result = probe_mod.probe(DOMAIN)
    assert set(result) == KEYS
    assert result["verdict"] == "skip"
    assert result["detail"] == "no address record"


def test_fake_ip_without_evidence_stays_fake_ip(isolated):
    monkeypatch = isolated
    dns(monkeypatch, "FAKE-IP", "198.18.0.9")
    monkeypatch.setattr(probe_mod, "live_connections", lambda api: [])

    result = probe_mod.probe(DOMAIN)
    assert set(result) == KEYS
    assert result["verdict"] == "FAKE-IP"
    assert result["detail"] == "no rule decision observed"
    assert result["rule"] == "-"
    assert result["outbound"] == "-"


@pytest.mark.parametrize("dns_block, address, family", [
    ("fake-ip-range: 203.0.113.1/24", "203.0.113.9", socket.AF_INET),
    ('fake-ip-range6: "2001:db8:99::/64"', "2001:db8:99::9", socket.AF_INET6),
])
def test_cli_check_exits_one_for_fake_ip_without_evidence(
        isolated, monkeypatch, capsys, tmp_path, dns_block, address, family):
    core = tmp_path / "mihomo"
    core.mkdir()
    cfg = MihomoConfig(core)
    Path(cfg.override).write_text(
        f"rules:\n  - DOMAIN-SUFFIX,{DOMAIN},DIRECT\n"
        f"dns:\n  fake-ip-filter: ['+.{DOMAIN}']\n",
        encoding="utf-8")
    generated(cfg, f"rules: []\ndns:\n  {dns_block}\n")
    resolver(monkeypatch, address, family)
    monkeypatch.setattr(probe_mod, "live_connections", lambda api: [])

    assert cli.main(["--config-dir", str(core), "check"]) == 1
    out = capsys.readouterr().out
    assert "dns=FAKE-IP" in out
    assert "0 leak, 1 fake-ip" in out


def test_missing_generated_configuration_uses_default_fake_ip_range(tmp_path):
    cfg = MihomoConfig(tmp_path / "mihomo")
    assert cfg.fake_ip_networks() == (
        ipaddress.ip_network("198.18.0.0/16"), None)


def test_fake_ip_ranges_follow_custom_generated_path(tmp_path):
    core = tmp_path / "mihomo"
    core.mkdir()
    cfg = MihomoConfig(core)
    custom = tmp_path / "runtime" / "config.yaml"
    custom.parent.mkdir()
    custom.write_text("dns:\n  fake-ip-range: 203.0.113.1/24\n",
                      encoding="utf-8")
    (tmp_path / "config.yaml").write_text(
        f"mihomo:\n  core:\n    config_path: {custom}\n", encoding="utf-8")

    assert cfg.fake_ip_networks()[0] == ipaddress.ip_network("203.0.113.0/24")


@pytest.mark.parametrize("dns_yaml, address, family, state", [
    ("{fake-ip-range: null}", "198.18.0.9", socket.AF_INET, "FAKE-IP"),
    ("{fake-ip-range: ''}", "198.18.0.9", socket.AF_INET, "ok"),
    ("{fake-ip-range: 10.0.0.1/8}", "10.1.2.3", socket.AF_INET, "FAKE-IP"),
    ("{fake-ip-range: 10.0.0.1/8}", "198.18.0.9", socket.AF_INET, "ok"),
    ("{fake-ip-range6: '2001:db8::/32'}", "2001:db8::5",
     socket.AF_INET6, "FAKE-IP"),
    ("{fake-ip-range6: '2001:db8::/32'}", "2001:db9::5",
     socket.AF_INET6, "ok"),
    ("{fake-ip-range6: null}", "2001:db8::5", socket.AF_INET6, "ok"),
    ("{fake-ip-range6: ''}", "2001:db8::5", socket.AF_INET6, "ok"),
    # Range matching is independent of dns.enable: cached synthetic answers
    # must still be identifiable when mihomo's resolver is switched off.
    ("{enable: false}", "198.18.0.9", socket.AF_INET, "FAKE-IP"),
])
def test_dns_check_uses_generated_fake_ip_ranges(tmp_path, monkeypatch,
                                                 dns_yaml, address, family,
                                                 state):
    cfg = MihomoConfig(tmp_path / "mihomo")
    generated(cfg, f"dns: {dns_yaml}\n")
    resolver(monkeypatch, address, family)

    assert config_mod.dns_check(
        DOMAIN, networks=cfg.fake_ip_networks()) == (address, state)


@pytest.mark.parametrize("dns_yaml, message", [
    ("{fake-ip-range: 'fd00::/8'}", "must be an IPv4 CIDR"),
    ("{fake-ip-range6: 198.18.0.1/16}", "must be an IPv6 CIDR"),
    ("{fake-ip-range: nope}", "must be a valid CIDR"),
    ("{fake-ip-range: [198.18.0.1/16]}", "must be a CIDR string"),
])
def test_bad_generated_fake_ip_range_is_actionable(tmp_path, dns_yaml, message):
    cfg = MihomoConfig(tmp_path / "mihomo")
    generated(cfg, f"dns: {dns_yaml}\n")
    with pytest.raises(ValueError, match=message):
        cfg.fake_ip_networks()


def test_malformed_generated_configuration_is_reported(tmp_path):
    cfg = MihomoConfig(tmp_path / "mihomo")
    path = generated(cfg, "dns: [\n")
    with pytest.raises(ValueError, match="invalid generated configuration") as exc:
        cfg.fake_ip_networks()
    assert str(path) in str(exc.value)


def test_unreadable_generated_configuration_is_reported(tmp_path):
    cfg = MihomoConfig(tmp_path / "mihomo")
    Path(cfg.generated).mkdir(parents=True)
    with pytest.raises(OSError, match="cannot read generated configuration"):
        cfg.fake_ip_networks()


def test_mihomo_audit_snapshots_configured_ranges(tmp_path, monkeypatch):
    core = tmp_path / "mihomo"
    core.mkdir()
    cfg = MihomoConfig(core)
    Path(cfg.override).write_text(
        f"rules:\n  - DOMAIN-SUFFIX,{DOMAIN},DIRECT\n"
        "dns:\n  fake-ip-filter: []\n",
        encoding="utf-8")
    networks = (ipaddress.ip_network("203.0.113.0/24"), None)
    loads = []

    def configured(document=None):
        loads.append(document)
        return networks

    calls = []

    def fake_audit(domains, api=None, log=print, *, networks=None):
        calls.append((list(domains), networks))
        return []

    monkeypatch.setattr(cfg, "fake_ip_networks", configured)
    monkeypatch.setattr(probe_mod, "audit", fake_audit)

    assert cfg.audit(log=lambda _line: None) == []
    assert loads == [None]
    assert calls[0][0] == [DOMAIN]
    assert calls[0][1] is networks


def test_controller_state_is_ready(monkeypatch):
    seen = {}

    def api_json(path, api=probe_mod.DEFAULT_API, timeout=probe_mod.API_TIMEOUT):
        seen.update(path=path, api=api, timeout=timeout)
        return {"meta": True, "version": "1.19.0"}

    monkeypatch.setattr(probe_mod, "_api_json", api_json)
    assert probe_mod.controller_state(timeout=0.25) == "ready"
    assert seen == {"path": "/version", "api": probe_mod.DEFAULT_API,
                    "timeout": 0.25}


@pytest.mark.parametrize("code", [401, 403])
def test_controller_state_unauthorized(monkeypatch, code):
    def api_json(*args, **kwargs):
        raise urllib.error.HTTPError("http://127.0.0.1:9090/version", code,
                                     "denied", {}, None)

    monkeypatch.setattr(probe_mod, "_api_json", api_json)
    assert probe_mod.controller_state() == "unauthorized"


@pytest.mark.parametrize("info", [
    None,
    [],
    {},
    {"meta": True},
    {"meta": False, "version": "1.19.0"},
    {"meta": True, "version": ""},
    {"meta": True, "version": "   "},
    {"meta": True, "version": 19},
])
def test_controller_state_invalid_version_is_unavailable(monkeypatch, info):
    monkeypatch.setattr(probe_mod, "_api_json", lambda *a, **k: info)
    assert probe_mod.controller_state() == "unavailable"


@pytest.mark.parametrize("error", [
    urllib.error.URLError("down"),
    TimeoutError("slow"),
    urllib.error.HTTPError("http://127.0.0.1:9090/version", 500, "boom", {}, None),
])
def test_controller_state_transport_errors_are_unavailable(monkeypatch, error):
    def api_json(*args, **kwargs):
        raise error

    monkeypatch.setattr(probe_mod, "_api_json", api_json)
    assert probe_mod.controller_state() == "unavailable"


def test_api_request_uses_bearer_secret_and_no_double_slash(monkeypatch):
    class Opener:
        def __init__(self):
            self.seen = {}

        def open(self, request, timeout=None):
            self.seen.update(request=request, timeout=timeout)
            return _Response()

    opener = Opener()
    monkeypatch.setattr(probe_mod, "_opener", lambda: opener)
    monkeypatch.setenv("LANLOCK_API_SECRET", "s3cret")

    response = probe_mod._api_request("/version", "http://127.0.0.1:9090/",
                                      timeout=1.25)
    assert response.body == b""
    request = opener.seen["request"]
    assert request.full_url == "http://127.0.0.1:9090/version"
    assert request.get_header("Authorization") == "Bearer s3cret"
    assert opener.seen["timeout"] == 1.25


def test_api_request_without_secret_has_no_authorization(monkeypatch):
    class Opener:
        def open(self, request, timeout=None):
            request.get_header("Authorization")
            assert request.get_header("Authorization") is None
            return _Response()

    monkeypatch.setattr(probe_mod, "_opener", lambda: Opener())
    monkeypatch.delenv("LANLOCK_API_SECRET", raising=False)
    probe_mod._api_request("/version")


def test_api_json_parses_response_body(monkeypatch):
    body = json.dumps({"meta": True, "version": "1.19.0"}).encode()
    monkeypatch.setattr(probe_mod, "_api_request",
                        lambda *args, **kwargs: _Response(body=body))
    assert probe_mod._api_json("/version") == {"meta": True, "version": "1.19.0"}


def test_live_connections_uses_shared_json_helper(monkeypatch):
    seen = []

    def api_json(path, api=probe_mod.DEFAULT_API, timeout=probe_mod.API_TIMEOUT):
        seen.append((path, api, timeout))
        return {"connections": [{"id": "one"}]}

    monkeypatch.setattr(probe_mod, "_api_json", api_json)
    assert probe_mod.live_connections("http://127.0.0.1:9090") == [{"id": "one"}]
    assert seen == [("/connections", "http://127.0.0.1:9090",
                     probe_mod.API_TIMEOUT)]


@pytest.mark.parametrize("failure", [
    urllib.error.URLError("down"),
    lambda *a, **k: [],
])
def test_live_connections_without_valid_body_is_empty(monkeypatch, failure):
    if isinstance(failure, Exception):
        error = failure

        def api_json(*args, **kwargs):
            raise error

    else:
        api_json = failure
    monkeypatch.setattr(probe_mod, "_api_json", api_json)
    assert probe_mod.live_connections() == []


def test_api_request_ignores_ambient_proxy(monkeypatch):
    class Controller(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/version":
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"meta": true, "version": "1.19.0"}')

    monkeypatch.delenv("LANLOCK_API_SECRET", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setenv("no_proxy", "example.invalid")
    with HTTPServer(("127.0.0.1", 0), Controller) as server:
        api = f"http://127.0.0.1:{server.server_port}"
        # A proxied request sends an absolute URL, which the controller rejects.
        monkeypatch.setenv("http_proxy", api)
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            assert probe_mod.controller_state(api) == "ready"
        finally:
            server.shutdown()
            thread.join()


def test_redirect_is_rejected():
    request = urllib.request.Request("http://127.0.0.1:9090/version",
                                     headers={"Authorization": "Bearer s3cret"})
    assert probe_mod._NoRedirect().redirect_request(
        request, None, 302, "Found", {}, "http://198.51.100.1/version") is None


FAILED_DIAL = ("[TCP] dial DIRECT (match DomainSuffix/corp.example) "
               "198.18.0.1:5555(curl, uid=1000) --> bad.corp.example:443 "
               "error: dial tcp 10.0.0.1:443: i/o timeout")


def test_parse_failure_extracts_destination_and_rule():
    assert probe_mod.parse_failure(FAILED_DIAL) == {
        "host": "bad.corp.example", "port": 443, "rule": "DomainSuffix",
        "payload": "corp.example", "outbound": "DIRECT", "detail": FAILED_DIAL}


def test_parse_failure_ignores_lines_without_a_rule_or_error():
    assert probe_mod.parse_failure(line(DOMAIN, 443, "DIRECT")) is None
    assert probe_mod.parse_failure("[DNS] resolve bad.example error: timeout") is None
    assert probe_mod.parse_failure("") is None
    assert probe_mod.parse_failure(None) is None


def test_parse_failure_keeps_ip_destinations():
    failure = probe_mod.parse_failure(
        "[TCP] dial DIRECT (match IPCIDR/10.0.0.0/8) 198.18.0.1:1 --> 10.1.2.3:443 "
        "error: dial tcp 10.1.2.3:443: i/o timeout")
    assert failure["host"] == "10.1.2.3"
    assert failure["rule"] == "IPCIDR"


def test_watch_once_reads_ndjson_until_idle(monkeypatch):
    class Response:
        status = 200

        def __init__(self):
            self.lines = [ndjson(FAILED_DIAL) + b"\n"]

        def read1(self, size):
            if self.lines:
                return self.lines.pop(0)
            raise TimeoutError

    class Connection:
        def __init__(self):
            self.sock = _Sock()
            self.response = Response()
            self.path = None
            self.closed = False

        def request(self, method, path, headers=None):
            self.path = path

        def getresponse(self):
            return self.response

        def close(self):
            self.closed = True

    made = []

    def factory(host, port, timeout=None):
        connection = Connection()
        made.append(connection)
        return connection

    monkeypatch.setattr(probe_mod.http.client, "HTTPConnection", factory)
    failures = list(probe_mod._watch_once("http://127.0.0.1:9090", None))
    assert [f["host"] for f in failures] == ["bad.corp.example"]
    assert made[0].path == "/logs?level=warning"
    assert made[0].closed


def _watch_connection(status=200, chunks=(), on_empty=None):
    class Response:
        def __init__(self):
            self.status = status
            self.chunks = list(chunks)

        def read1(self, size):
            if self.chunks:
                return self.chunks.pop(0)
            if on_empty is not None:
                raise on_empty
            return b""

    class Connection:
        def __init__(self, *args, **kwargs):
            self.sock = _Sock()
            self.response = Response()
            self.closed = False

        def request(self, method, path, headers=None):
            pass

        def getresponse(self):
            return self.response

        def close(self):
            self.closed = True

    return Connection


def test_watch_once_raises_when_the_stream_closes(monkeypatch):
    monkeypatch.setattr(probe_mod.http.client, "HTTPConnection", _watch_connection())
    with pytest.raises(OSError, match="closed the log stream"):
        list(probe_mod._watch_once("http://127.0.0.1:9090", None))


def test_watch_once_surfaces_unauthorized(monkeypatch):
    monkeypatch.setattr(probe_mod.http.client, "HTTPConnection",
                        _watch_connection(status=401))
    with pytest.raises(ValueError, match="HTTP 401"):
        list(probe_mod._watch_once("http://127.0.0.1:9090", None))


def test_watch_failures_stops_during_backoff(monkeypatch):
    stop = Event()
    attempts = []

    def factory(*args, **kwargs):
        attempts.append(args)
        stop.set()
        raise ConnectionRefusedError

    monkeypatch.setattr(probe_mod.http.client, "HTTPConnection", factory)
    started = time.monotonic()
    assert list(probe_mod.watch_failures("http://127.0.0.1:9090", stop)) == []
    assert attempts
    assert time.monotonic() - started < probe_mod.WATCH_RETRY_DELAY
