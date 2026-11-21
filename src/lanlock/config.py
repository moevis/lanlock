"""Static config editing for the clashtui-managed mihomo.

The override file is the source of truth; clashtui regenerates ``config.yaml``
from it (profile + override merge), so nothing here ever edits the artifact.
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Mapping
from io import StringIO
from stat import S_IMODE
from tempfile import NamedTemporaryFile

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarstring import SingleQuotedScalarString

def _default_config_dir():
    if sys.platform == "win32":
        directory = os.environ.get("APPDATA") or "~/AppData/Roaming"
    elif sys.platform == "linux":
        directory = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    else:
        directory = "~/.config"
    return os.path.join(directory, "clashtui", "mihomo")


def _default_state_dir():
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or "~/AppData/Local"
    elif sys.platform == "darwin":
        base = "~/Library/Application Support"
    else:
        base = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return os.path.join(base, "mihomo-internal")


DEFAULT_CONFIG_DIR = _default_config_dir()
DEFAULT_STATE_DIR = _default_state_dir()
DEFAULT_API = "http://127.0.0.1:9090"
FAILURE_HISTORY_MAX = 200
_FAILURE_DETAIL_MAX = 2000
# Mihomo's standard fake-IP range; strict=False masks the host bits to /16.
DEFAULT_FAKE_IP_RANGE = "198.18.0.1/16"
_DEFAULT_FAKE_IP_NETWORKS = (ipaddress.ip_network(DEFAULT_FAKE_IP_RANGE, strict=False), None)

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_LATE_RULES = {"IP-CIDR", "IP-CIDR6", "GEOIP", "GEOSITE", "MATCH"}


def norm(raw):
    """Normalise user input to a bare domain, raising ValueError otherwise."""
    domain = _suffix(re.sub(r"^(\+\.|\*\.|\.)", "", raw.strip()))
    if domain is None:
        raise ValueError(f"not a domain: {raw!r}")
    return domain


def _rule_domain(entry):
    parts = [part.strip() for part in entry.split(",")]
    if len(parts) in (3, 4) and parts[0] == "DOMAIN-SUFFIX" and parts[2] == "DIRECT":
        if len(parts) == 3 or parts[3] == "no-resolve":
            return _suffix(parts[1])
    return None


def _filter_domain(entry):
    return _suffix(entry[2:]) if entry.startswith("+.") else None


def _suffix(value):
    # Other mihomo patterns (wildcards, geosite, rule-set) are not domain suffixes.
    value = value.lower().removesuffix(".")
    return value if len(value) <= 253 and _DOMAIN_RE.fullmatch(value) else None


def _failure_entry(raw):
    """Return the history record stored for one failure, or None when unusable."""
    if not isinstance(raw, dict):
        return None
    host, port = raw.get("host"), raw.get("port")
    if not isinstance(host, str) or not host or not isinstance(port, int):
        return None
    return {"host": host, "port": port,
            "rule": str(raw.get("rule") or "?"),
            "payload": str(raw.get("payload") or ""),
            "outbound": str(raw.get("outbound") or "-"),
            "detail": str(raw.get("detail") or "")[:_FAILURE_DETAIL_MAX],
            "time": str(raw.get("time") or ""),
            "api": str(raw.get("api") or "")}


def _fake_ip_network(value, version, key):
    """Parse one configured fake-IP CIDR, or None when explicitly disabled."""
    if value is None:
        value = DEFAULT_FAKE_IP_RANGE if version == 4 else ""
    if not isinstance(value, str):
        raise ValueError(f"dns.{key} must be a CIDR string, got {value!r}")
    value = value.strip()
    if not value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ValueError(f"dns.{key} must be a valid CIDR: {value!r}") from e
    if network.version != version:
        raise ValueError(f"dns.{key} must be an IPv{version} CIDR: {value!r}")
    return network


def fake_ip_networks(dns=None):
    """Return configured fake-IP ranges as ``(IPv4 network, IPv6 network)``.

    An omitted or null IPv4 range uses mihomo's 198.18.0.1/16 default; an
    omitted or null IPv6 range means no IPv6 range. An explicit empty string
    disables that address family.
    """
    if dns is None:
        dns = {}
    elif not isinstance(dns, Mapping):
        raise ValueError("generated dns must be a YAML mapping")
    return (_fake_ip_network(dns.get("fake-ip-range"), 4, "fake-ip-range"),
            _fake_ip_network(dns.get("fake-ip-range6"), 6, "fake-ip-range6"))


def _is_fake_ip(ip, networks):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(network is not None and network.version == address.version
               and address in network for network in networks)


def _section(parent, key, kind):
    value = parent.get(key)
    if value is None:
        return kind()
    if not isinstance(value, kind):
        expected = "mapping" if kind is CommentedMap else "list"
        raise ValueError(f"{key} must be a YAML {expected}")
    if kind is CommentedSeq and any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key} must contain only strings")
    return value


def _require_editable(*nodes):
    if any(node.anchor.value or getattr(node, "merge", None) for node in nodes):
        raise ValueError("cannot edit a rules or DNS section that uses YAML anchors or merges")


class _Override:
    def __init__(self, text):
        self.text = text
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        try:
            root = self.yaml.load(text)
        except YAMLError as e:
            raise ValueError(f"invalid YAML: {e}") from e
        self.root = CommentedMap() if root is None else root
        if not isinstance(self.root, CommentedMap):
            raise ValueError("configuration must be a YAML mapping")
        self.rules = _section(self.root, "rules", CommentedSeq)
        self.dns = _section(self.root, "dns", CommentedMap)
        self.filters = _section(self.dns, "fake-ip-filter", CommentedSeq)
        self.rule_domains = self._domains(self.rules, _rule_domain)
        mode = self.dns.get("fake-ip-filter-mode", "blacklist")
        self.filter_domains = self._domains(self.filters, _filter_domain) if mode == "blacklist" else set()

    @staticmethod
    def _domains(entries, parse):
        return {domain for entry in entries if (domain := parse(entry)) is not None}

    def rows(self):
        return [{"domain": d, "rule": d in self.rule_domains, "filter": d in self.filter_domains}
                for d in sorted(self.rule_domains | self.filter_domains)]

    def _edit_filters(self):
        if self.dns.get("fake-ip-filter-mode", "blacklist") != "blacklist":
            raise ValueError("editing fake-ip-filter requires blacklist mode")
        _require_editable(self.root, self.dns, self.filters)

    def add_rule(self, domain):
        if domain in self.rule_domains:
            return False
        self._require_section("rules")
        _require_editable(self.root, self.rules)
        position = next((i for i, entry in enumerate(self.rules)
                         if entry.split(",", 1)[0].strip() in _LATE_RULES), len(self.rules))
        self.rules.insert(position, f"DOMAIN-SUFFIX,{domain},DIRECT")
        self.root["rules"] = self.rules
        self.rule_domains.add(domain)
        return True

    def add_filter(self, domain):
        self._edit_filters()
        if domain in self.filter_domains:
            return False
        self._require_section("dns")
        self.filters.append(SingleQuotedScalarString(f"+.{domain}"))
        self.dns["fake-ip-filter"] = self.filters
        self.root["dns"] = self.dns
        self.filter_domains.add(domain)
        return True

    def _require_section(self, key):
        # ClashTUI replaces entire top-level sections in the selected profile.
        if self.root.get(key) is None:
            raise ValueError(f"copy the profile's {key} section into the override first; "
                             f"adding it would replace the profile's {key} settings")

    def remove(self, domain):
        changed = False
        if domain in self.rule_domains:
            _require_editable(self.root, self.rules)
            self._remove_matching(self.rules, _rule_domain, domain)
            changed = True
        if domain in self.filter_domains:
            self._edit_filters()
            self._remove_matching(self.filters, _filter_domain, domain)
            changed = True
        return changed

    @staticmethod
    def _remove_matching(entries, parse, domain):
        for i in reversed(range(len(entries))):
            if parse(entries[i]) == domain:
                del entries[i]

    def render(self, changed):
        if not changed:
            return self.text
        stream = StringIO()
        self.yaml.dump(self.root, stream)
        return stream.getvalue()


def _atomic_write(path, text, mode):
    with NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=os.path.dirname(path),
                            delete=False) as temp:
        try:
            temp.write(text)
            temp.flush()
            os.chmod(temp.name, mode)
            os.fsync(temp.fileno())
            temp.close()
            os.replace(temp.name, path)
        finally:
            if os.path.exists(temp.name):
                os.unlink(temp.name)


class MihomoConfig:
    def __init__(self, config_dir=DEFAULT_CONFIG_DIR, api=DEFAULT_API, profile=None,
                 state_dir=None):
        self.config_dir = os.path.expanduser(config_dir)
        self.api = api
        self.profile_override = profile
        self.state_dir = os.path.expanduser(state_dir or DEFAULT_STATE_DIR)

    # ---------- paths ----------
    @property
    def override(self):
        return os.path.join(self.config_dir, "core_override_config.yaml")

    @property
    def generated(self):
        settings = os.path.join(os.path.dirname(os.path.abspath(self.config_dir)), "config.yaml")
        try:
            config = YAML(typ="safe").load(self.read(settings)) or {}
            path = config.get("mihomo", {}).get("core", {}).get("config_path")
        except FileNotFoundError:
            path = None
        except (YAMLError, AttributeError) as e:
            raise ValueError(f"invalid ClashTUI settings: {settings}") from e
        if path is not None and not isinstance(path, str):
            raise ValueError(f"invalid Mihomo config_path in {settings}")
        return path or os.path.join(self.config_dir, "config", "config.yaml")

    def _generated_override(self):
        """Load the generated config, or None when it has not been written yet."""
        path = self.generated
        try:
            text = self.read(path)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise OSError(f"cannot read generated configuration {path}: {e}") from e
        try:
            return _Override(text)
        except ValueError as e:
            raise ValueError(f"invalid generated configuration {path}: {e}") from e

    def fake_ip_networks(self, document=None):
        """Return the generated fake-IP ``(IPv4, IPv6)`` networks.

        ``document`` may be an already loaded ``_Override`` so apply reuses
        the generated config it just read. A missing generated file falls back
        to mihomo's defaults; unreadable or malformed configuration is raised
        with the path instead of silently matching nothing.
        """
        if document is None:
            document = self._generated_override()
            if document is None:
                return fake_ip_networks()
        return fake_ip_networks(document.dns)

    @property
    def profiles_dir(self):
        return os.path.join(self.config_dir, "profiles")

    # ---------- yaml ----------
    def read(self, path=None):
        """Return the file as ``\\n``-separated text, whatever its line endings."""
        with open(path or self.override, encoding="utf-8") as f:
            return f.read()

    def save(self, text):
        """Validate first, then replace the override atomically and keep one backup.

        ``text`` is treated as ``\\n``-separated and written with the newline style
        the file already uses, so a CRLF override stays CRLF and a no-op save does
        not rewrite the file.
        """
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        _Override(text)
        path = os.path.realpath(self.override)
        with open(path, encoding="utf-8", newline="") as f:
            before = f.read()
            mode = S_IMODE(os.fstat(f.fileno()).st_mode)
        newline = "\r\n" if "\r\n" in before else "\n"
        updated = text.replace("\n", newline)
        if before != updated:
            _atomic_write(os.path.abspath(self.override + ".bak"), before, mode)
            _atomic_write(path, updated, mode)

    # ---------- entries ----------
    def rows(self, text=None):
        return self._override(text).rows()

    def _override(self, text):
        return _Override(self.read() if text is None else text)

    def add_rule_only(self, text, domain):
        config = self._override(text)
        changed = config.add_rule(norm(domain))
        return config.render(changed), changed

    def add_filter_only(self, text, domain):
        config = self._override(text)
        changed = config.add_filter(norm(domain))
        return config.render(changed), changed

    def add(self, domain, text=None):
        """Add rule + fake-ip-filter entry. Returns (text, changed)."""
        domain = norm(domain)
        config = self._override(text)
        rule = config.add_rule(domain)
        filtered = config.add_filter(domain)
        changed = rule or filtered
        return config.render(changed), changed

    def remove(self, domain, text=None):
        config = self._override(text)
        changed = config.remove(norm(domain))
        return config.render(changed), changed

    def sync(self, text=None):
        """Make rules and fake-ip-filter agree in both directions.

        Returns (text, [(domain, "rule"|"filter"), ...]).
        """
        config = self._override(text)
        added = []
        for row in config.rows():
            domain = row["domain"]
            if not row["filter"]:
                config.add_filter(domain)
                added.append((domain, "filter"))
            elif not row["rule"]:
                config.add_rule(domain)
                added.append((domain, "rule"))
        return config.render(added), added

    # ---------- ClashTUI / Mihomo controller ----------
    def profiles(self):
        try:
            result = self._clashtui("profile", "list", "--name-only")
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode or result.stdout.strip() == "No profiles found.":
            return []
        return [name.strip() for name in result.stdout.splitlines() if name.strip()]

    def active_profile(self):
        if self.profile_override:
            return self.profile_override
        try:
            result = self._clashtui("profile", "select")
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode:
            return None
        prefix = "Current Profile: "
        for line in result.stdout.splitlines():
            if line.startswith(prefix):
                name = line.removeprefix(prefix).strip()
                return name if name and name != "Unknown" else None
        return None

    def _clashtui(self, *args, timeout=5):
        directory = os.path.abspath(self.config_dir)
        root, name = os.path.split(directory)
        if name != "mihomo":
            raise OSError("--config-dir must point to the mihomo subdirectory of a ClashTUI root")
        return subprocess.run(["clashtui", f"--config-dir={root}", *args],
                              capture_output=True, text=True, timeout=timeout)

    def controller_state(self):
        from .probe import controller_state
        return controller_state(self.api)

    def live_connections(self):
        """Return the controller's currently open connections."""
        from .probe import live_connections
        return live_connections(self.api)

    def failure_stream(self, stop=None):
        """Yield failed dials from the controller log stream until ``stop`` is set."""
        from .probe import watch_failures
        return watch_failures(self.api, stop=stop)

    @property
    def failure_log(self):
        return os.path.join(self.state_dir, "failures.json")

    def _stored_failures(self):
        try:
            with open(self.failure_log, encoding="utf-8") as f:
                entries = json.load(f)
        except (OSError, ValueError):
            return []
        if not isinstance(entries, list):
            return []
        return [entry for entry in map(_failure_entry, entries) if entry is not None]

    def failure_history(self):
        """Return the newest-first failed dials recorded for this controller."""
        history = [e for e in self._stored_failures() if e["api"] == self.api]
        return history[:FAILURE_HISTORY_MAX]

    def record_failure(self, failure):
        """Persist one failed dial for this controller, replacing the same host:port."""
        entry = _failure_entry(dict(failure, time=time.strftime("%Y-%m-%d %H:%M:%S"),
                                    api=self.api))
        if entry is None:
            return
        entries = [e for e in self._stored_failures()
                   if (e["api"], e["host"], e["port"])
                   != (entry["api"], entry["host"], entry["port"])]
        entries.insert(0, entry)
        # Bound each controller separately so one busy profile cannot evict another.
        kept, seen = [], {}
        for e in entries:
            seen[e["api"]] = seen.get(e["api"], 0) + 1
            if seen[e["api"]] <= FAILURE_HISTORY_MAX:
                kept.append(e)
        os.makedirs(self.state_dir, exist_ok=True)
        _atomic_write(self.failure_log,
                      json.dumps(kept, ensure_ascii=False), 0o600)

    def apply(self, log=print, domains=None):
        """Ask ClashTUI to regenerate and reload via the Mihomo API, then check DNS."""
        state = self.controller_state()
        if state != "ready":
            hint = " (check LANLOCK_API_SECRET)" if state == "unauthorized" else ""
            log(f"error: Mihomo controller {state}{hint}")
            return False
        prof = self.active_profile()
        if not prof:
            log("error: cannot determine current profile (pass --profile or set one in ClashTUI)")
            return False
        log(f"profile: {prof}")
        try:
            r = self._clashtui("profile", "select", f"--name={prof}", timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            log(f"error: clashtui: {e}")
            return False
        # Some ClashTUI versions report initialization errors but exit zero.
        if r.returncode or f"Profile selected: {prof}" not in r.stdout.splitlines():
            detail = (r.stderr or r.stdout).strip() or "profile selection was not confirmed"
            log(f"error: clashtui: {detail}")
            return False
        try:
            generated = self._generated_override()
            if generated is None:
                raise OSError(f"generated configuration not found: {self.generated}")
            networks = self.fake_ip_networks(generated)
            domains = [r["domain"] for r in self.rows()] if domains is None else domains
        except (OSError, ValueError) as e:
            log(f"error: cannot read configuration: {e}")
            return False
        log("config: reloaded via Mihomo API")
        for d in domains:
            ip, state = dns_check_retry(d, networks=networks)
            has_rule = d in generated.rule_domains
            has_filter = d in generated.filter_domains
            log("  %-36s rule=%s filter=%s dns=%s %s" % (
                d, "y" if has_rule else "n", "y" if has_filter else "n", ip, state))
        return True

    # ---------- probing ----------
    def dns(self, domain):
        return dns_check(domain, networks=self.fake_ip_networks())

    def probe(self, domain, port=443):
        from .probe import probe
        return probe(domain, api=self.api, port=port,
                     networks=self.fake_ip_networks())

    def audit(self, log=print, domains=None):
        from .probe import audit
        domains = [r["domain"] for r in self.rows()] if domains is None else domains
        return audit(domains, api=self.api, log=log,
                     networks=self.fake_ip_networks())


def dns_check(domain, *, networks=None):
    networks = _DEFAULT_FAKE_IP_NETWORKS if networks is None else networks
    try:
        addresses = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "-", "no-record"
    if not addresses:
        return "-", "no-record"
    for address in addresses:
        ip = address[4][0]
        if _is_fake_ip(ip, networks):
            return ip, "FAKE-IP"
    return addresses[0][4][0], "ok"


def dns_check_retry(domain, tries=2, *, networks=None):
    last = ("-", "no-record")
    for i in range(tries):
        last = dns_check(domain, networks=networks)
        if last[1] != "no-record":
            return last
        if i + 1 < tries:
            time.sleep(0.25)
    return last
