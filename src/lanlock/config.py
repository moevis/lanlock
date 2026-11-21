"""Static config editing for the clashtui-managed mihomo, or for FlClash.

ClashTUI: the override file is the source of truth; clashtui regenerates
``config.yaml`` from it (profile + override merge), so nothing here ever edits
the artifact.

FlClash: the selected profile YAML is the source of truth; FlClash regenerates
``config.yaml`` from it whenever it starts the core, so the profile is edited
and the core has to be restarted by hand.
"""
import ipaddress
import json
import os
import plistlib
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from collections.abc import Mapping
from contextlib import closing
from io import StringIO
from pathlib import Path
from stat import S_IMODE
from tempfile import NamedTemporaryFile

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarstring import SingleQuotedScalarString

_OVERRIDE_FILE = "core_override_config.yaml"
_FLCLASH_APP_ID = "com.follow.clash"
_FLCLASH_DIR_ENV = "LANLOCK_FLCLASH_DIR"
# FlClash's compiled-in DNS defaults (defaultDns in the app bundle). Used to seed
# a newly created fake-ip-filter when config.yaml has not been generated yet, so
# the entries the app would have applied are not silently dropped.
_FLCLASH_DEFAULT_FAKE_IP_FILTER = (
    "dns.msftnsci.com",
    "www.msftnsci.com",
    "www.msftconnecttest.com",
)
# FlClash merges the profile over its own DNS defaults, so a domain only needs a
# resolver that can see the internal zone: the OS resolver reaches the DNS that
# actually serves it (a public DoH cannot).
DEFAULT_RESOLVER = "system://"


_BACKENDS = ("clashtui", "flclash")


def _clashtui_dir():
    """ClashTUI's mihomo directory: portable install, native config, then XDG."""
    binary = shutil.which("clashtui")
    if binary:
        portable = os.path.join(os.path.dirname(os.path.realpath(binary)), "data")
        if os.path.isdir(portable):
            return os.path.join(portable, "mihomo")

    if sys.platform == "win32":
        directory = os.environ.get("APPDATA") or "~/AppData/Roaming"
    elif sys.platform == "linux":
        directory = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    else:
        directory = "~/.config"
    config_dir = os.path.join(directory, "clashtui", "mihomo")
    # The macOS installer honors XDG_CONFIG_HOME even though ClashTUI itself
    # defaults to ~/.config. Use the installer layout if only it has an override.
    if sys.platform == "darwin" and not os.path.isfile(
            os.path.join(os.path.expanduser(config_dir), _OVERRIDE_FILE)):
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            installed = os.path.join(xdg, "clashtui", "mihomo")
            if os.path.isfile(os.path.join(installed, _OVERRIDE_FILE)):
                return installed
    return config_dir


def _flclash_candidates():
    env = os.environ.get(_FLCLASH_DIR_ENV)
    if env:
        yield env
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or "~/AppData/Roaming"
    elif sys.platform == "linux":
        base = os.environ.get("XDG_DATA_HOME") or "~/.local/share"
    else:
        base = "~/Library/Application Support"
    yield os.path.join(base, _FLCLASH_APP_ID)


def _is_flclash_dir(path):
    """FlClash keeps its profile index in SQLite next to the profiles it indexes."""
    return (os.path.isfile(os.path.join(path, "database.sqlite"))
            and os.path.isdir(os.path.join(path, "profiles")))


def _flclash_dir():
    for candidate in _flclash_candidates():
        if _is_flclash_dir(os.path.expanduser(candidate)):
            return candidate
    return None


def _clean(path):
    """Return an absolute path with one separator style and no trailing slash."""
    return os.path.normpath(os.path.expanduser(path))


def _clashtui_ready(directory):
    return os.path.isfile(os.path.join(os.path.expanduser(directory), _OVERRIDE_FILE))


def resolve(config_dir=None, backend=None):
    """Return ``(backend, directory)`` for the configuration lanlock edits.

    Neither setup can be picked by mtime or process state, and guessing wrong
    edits a file that governs nothing while looking successful, so a machine
    that has both is an error instead of a silent choice.
    """
    if backend is not None and backend not in _BACKENDS:
        raise ValueError(f"unknown backend {backend!r}; expected one of "
                         f"{', '.join(_BACKENDS)}")
    if config_dir is not None:
        directory = _clean(config_dir)
        if backend is not None:
            return backend, directory
        markers = [name for name, ready in
                   (("clashtui", _clashtui_ready(directory)),
                    ("flclash", _is_flclash_dir(directory))) if ready]
        if len(markers) > 1:
            raise ValueError(f"{directory} holds both a ClashTUI override and a FlClash "
                             "configuration; pass --backend clashtui|flclash")
        return (markers[0] if markers else "clashtui"), directory

    clashtui = _clashtui_dir()
    found = []
    if backend in (None, "clashtui") and _clashtui_ready(clashtui):
        found.append(("clashtui", _clean(clashtui)))
    flclash = _flclash_dir() if backend in (None, "flclash") else None
    if flclash is not None:
        found.append(("flclash", _clean(flclash)))
    if len(found) > 1:
        raise ValueError(
            "found both a ClashTUI override and a FlClash configuration:\n  "
            + "\n  ".join(f"{name}: {path}" for name, path in found)
            + "\npass --backend clashtui|flclash to choose which one to edit")
    if found:
        return found[0]
    if backend == "flclash":
        directory = flclash or next(iter(_flclash_candidates()))
        raise ValueError(f"no FlClash configuration at {_clean(directory)}: "
                         "database.sqlite not found")
    raise ValueError(
        "ClashTUI Mihomo override missing. Start ClashTUI to initialize it, pass "
        f"--config-dir pointing to its mihomo directory ({_clean(clashtui)}), "
        "or use --backend flclash")


def _flclash_prefs():
    """Return FlClash's own settings, or ``{}`` when they cannot be read.

    FlClash (a Flutter app) stores app settings as a JSON string under
    ``flutter.config`` in the platform preference store.
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or "~/AppData/Roaming"
        path = os.path.join(base, _FLCLASH_APP_ID, "shared_preferences.json")
    elif sys.platform == "darwin":
        path = "~/Library/Preferences/com.follow.clash.plist"
    else:
        base = os.environ.get("XDG_DATA_HOME") or "~/.local/share"
        path = os.path.join(base, _FLCLASH_APP_ID, "shared_preferences.json")
    path = os.path.expanduser(path)
    try:
        if path.endswith(".plist"):
            with open(path, "rb") as f:
                raw = plistlib.load(f).get("flutter.config")
        else:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f).get("flutter.config")
        settings = json.loads(raw)
    except (OSError, ValueError, TypeError, AttributeError, plistlib.InvalidFileException):
        return {}
    return settings if isinstance(settings, dict) else {}


def _flclash_selected_profile_id():
    """Return FlClash's selected profile id from its own settings, or None."""
    try:
        return int(_flclash_prefs()["currentProfileId"])
    except (KeyError, TypeError, ValueError):
        return None


def _flclash_patch_dns():
    """FlClash's app-level DNS settings, the profile-independent baseline."""
    patch = _flclash_prefs().get("patchClashConfig")
    dns = patch.get("dns") if isinstance(patch, dict) else None
    return dns if isinstance(dns, dict) else {}


def _default_state_dir():
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or "~/AppData/Local"
    elif sys.platform == "darwin":
        base = "~/Library/Application Support"
    else:
        base = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return os.path.join(base, "mihomo-internal")


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
_INDENTED_SEQUENCE = re.compile(r"^ +- ", re.MULTILINE)
_INDENTLESS_SEQUENCE = re.compile(r"^- ", re.MULTILINE)


def _indent_style(text):
    """Return indent settings that match the file's own sequence style.

    ruamel normalises block sequences to one style, so dumping an override that
    indents its sequences without this would rewrite every line of a profile
    the edit has nothing to do with.
    """
    if len(_INDENTED_SEQUENCE.findall(text)) > len(_INDENTLESS_SEQUENCE.findall(text)):
        return {"mapping": 2, "sequence": 4, "offset": 2}
    return {"mapping": 2, "sequence": 2, "offset": 0}


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
    def __init__(self, text, *, create_sections=False, seed_filters=(),
                 seed_filter_mode="blacklist"):
        self.text = text
        self._create_sections = create_sections
        self._seed_filters = list(seed_filters)
        self._seed_filter_mode = seed_filter_mode
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(**_indent_style(text))
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
        self._has_filters = "fake-ip-filter" in self.dns
        self.policy = _section(self.dns, "nameserver-policy", CommentedMap)
        self.rule_domains = self._domains(self.rules, _rule_domain)
        self.filter_domains = (self._domains(self.filters, _filter_domain)
                               if self._filter_mode() == "blacklist" else set())

    @staticmethod
    def _domains(entries, parse):
        return {domain for entry in entries if (domain := parse(entry)) is not None}

    def rows(self):
        return [{"domain": d, "rule": d in self.rule_domains, "filter": d in self.filter_domains}
                for d in sorted(self.rule_domains | self.filter_domains)]

    def _filter_mode(self):
        """The effective mode, including the backend's own baseline when unset."""
        return self.dns.get("fake-ip-filter-mode") or self._seed_filter_mode

    def _edit_filters(self):
        if self._filter_mode() != "blacklist":
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
        if not self._has_filters:
            # A partial dns section still replaces the inherited list key by key.
            self.filters = CommentedSeq(
                SingleQuotedScalarString(entry) for entry in self._seed_filters)
            self._has_filters = True
        self.filters.append(SingleQuotedScalarString(f"+.{domain}"))
        self.dns["fake-ip-filter"] = self.filters
        self.root["dns"] = self.dns
        self.filter_domains.add(domain)
        return True

    @staticmethod
    def _policy_key(domain):
        return f"+.{domain}"

    def add_policy(self, domain, servers):
        """Resolve one domain through ``servers`` so a DIRECT dial can resolve it.

        An existing entry is left alone: it is the user's choice of resolver.
        """
        if self._policy_key(domain) in self.policy:
            return False
        self._require_section("dns")
        _require_editable(self.root, self.dns, self.policy)
        self.policy[SingleQuotedScalarString(self._policy_key(domain))] = CommentedSeq(servers)
        self.dns["nameserver-policy"] = self.policy
        return True

    def has_policy(self, domain):
        return self._policy_key(domain) in self.policy

    def remove_policy(self, domain, servers):
        """Drop the policy entry only if it still names lanlock's own resolvers.

        A resolver the user chose is left alone: deleting it would silently move
        that domain back onto the public resolvers.
        """
        key = self._policy_key(domain)
        current = self.policy.get(key)
        if current is None:
            return False
        current = [current] if isinstance(current, str) else [str(entry) for entry in current]
        if current != [str(entry) for entry in servers]:
            return False
        _require_editable(self.root, self.dns, self.policy)
        del self.policy[key]
        if not self.policy:
            del self.dns["nameserver-policy"]
        return True

    def _require_section(self, key):
        """Materialise a missing section when the backend merges, not replaces.

        ClashTUI replaces entire top-level sections in the selected profile, so a
        missing ``rules`` or ``dns`` section must be copied from the profile
        first. FlClash merges the profile over its own DNS key by key, so a
        partial section is safe; the filter list is seeded with the entries the
        generated configuration already has, which keeps them in effect.
        """
        if self.root.get(key) is not None:
            return
        if not self._create_sections:
            raise ValueError(f"copy the profile's {key} section into the override first; "
                             f"adding it would replace the profile's {key} settings")
        if key == "rules":
            self.rules = CommentedSeq()
            self.root["rules"] = self.rules
            return
        self.dns = CommentedMap()
        self.filters = CommentedSeq()
        self.policy = CommentedMap()
        self.root["dns"] = self.dns

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


def _lf(text):
    """Return ``text`` with CRLF and lone CR folded to LF."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


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
    def __init__(self, config_dir=None, api=DEFAULT_API, profile=None,
                 state_dir=None, resolver=DEFAULT_RESOLVER, backend=None):
        self.backend, self.config_dir = resolve(config_dir, backend)
        self.flclash = self.backend == "flclash"
        self.api = api
        self.profile_override = profile
        self.state_dir = os.path.expanduser(state_dir or DEFAULT_STATE_DIR)
        if not isinstance(resolver, str) or not resolver.strip():
            raise ValueError("--resolver must name a DNS server, for example system://")
        self.resolver = resolver.strip()
        self._flclash_profile = None

    # ---------- paths ----------
    @property
    def override(self):
        if self.flclash:
            return os.path.join(self.profiles_dir, f"{self._flclash_target()[0]}.yaml")
        return os.path.join(self.config_dir, _OVERRIDE_FILE)

    @property
    def generated(self):
        if self.flclash:
            return os.path.join(self.config_dir, "config.yaml")
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

    # ---------- FlClash profile index ----------
    def _flclash_query(self, sql, params=(), missing_ok=False):
        path = os.path.join(self.config_dir, "database.sqlite")
        uri = Path(os.path.abspath(path)).as_uri() + "?mode=ro"
        try:
            with closing(sqlite3.connect(uri, uri=True)) as db:
                return db.execute(sql, params).fetchall()
        except sqlite3.OperationalError as e:
            # An older FlClash may lack a column or table; that is not a reason
            # to refuse every edit, only the feature that needs it.
            if missing_ok and "no such" in str(e):
                return []
            raise OSError(f"cannot read FlClash data from {path}: {e}") from e
        except sqlite3.Error as e:
            raise OSError(f"cannot read FlClash data from {path}: {e}") from e

    def _flclash_rows(self):
        """Return ``(id, label, type, overrides)`` for every FlClash profile."""
        rows = self._flclash_query(
            'SELECT id, label, type, overrides FROM profiles ORDER BY "order", id',
            missing_ok=True)
        if not rows:
            rows = self._flclash_query(
                'SELECT id, label FROM profiles ORDER BY "order", id')
        return [(int(row[0]), str(row[1]), str(row[2] if len(row) > 2 else ""),
                 row[3] if len(row) > 3 else None) for row in rows]

    @staticmethod
    def _flclash_label(row):
        return f"{row[1]} (#{row[0]})"

    def _flclash_target(self):
        """Return the ``(id, label, type, overrides)`` row to edit, cached per config."""
        if self._flclash_profile is not None:
            return self._flclash_profile
        rows = self._flclash_rows()
        if not rows:
            raise ValueError("no profiles in the FlClash configuration")
        available = ", ".join(self._flclash_label(row) for row in rows)
        chosen = None
        if self.profile_override:
            wanted = self.profile_override
            matches = [row for row in rows if str(row[0]) == wanted or row[1] == wanted]
            if not matches:
                raise ValueError(f"no FlClash profile {wanted!r}; available: {available}")
            if len(matches) > 1:
                raise ValueError(
                    f"{wanted!r} matches more than one FlClash profile: "
                    + ", ".join(self._flclash_label(row) for row in matches)
                    + "; pass the profile id")
            chosen = matches[0]
        if chosen is None:
            selected = _flclash_selected_profile_id()
            chosen = next((row for row in rows if row[0] == selected), None)
        if chosen is None and len(rows) == 1:
            chosen = rows[0]
        if chosen is None:
            raise ValueError("cannot tell which FlClash profile is selected; "
                             f"pass --profile (available: {available})")
        self._flclash_profile = chosen
        return chosen

    # DNS keys this backend writes into a profile.
    _EDITED_DNS_KEYS = ("fake-ip-filter", "fake-ip-filter-mode", "nameserver-policy")

    @staticmethod
    def _dns_override_keys(row):
        raw = row[3]
        if not raw:
            return ()
        try:
            overrides = json.loads(raw)
        except (TypeError, ValueError):
            return ()
        if not isinstance(overrides, dict):
            return ()
        for name, value in overrides.items():
            if str(name).lower().replace("_", "") == "dnsoverridekeys":
                if isinstance(value, dict):
                    return tuple(str(key) for key in value)
                if isinstance(value, (list, tuple)):
                    return tuple(str(item) for item in value)
        return ()

    def _flclash_added_rule(self, profile_id, domain):
        """Return FlClash's added rule covering ``domain``, or None.

        FlClash prepends the added rules from its database to the profile's own
        rules, so one of those wins over a rule written here.
        """
        rows = self._flclash_query(
            "SELECT rule_action, content FROM rules WHERE profile_id = ?", (profile_id,),
            missing_ok=True)
        for action, content in rows:
            action, content = str(action or "").upper(), str(content or "").strip().lower()
            if not content:
                continue
            if action in ("DOMAIN", "DOMAIN-SUFFIX") and (
                    domain == content or domain.endswith("." + content)):
                return f"{action},{content}"
            if action == "DOMAIN-KEYWORD" and content in domain:
                return f"{action},{content}"
        return None

    def _flclash_edit_guard(self, domain=None):
        """Refuse edits that FlClash's own settings would shadow or already make."""
        if not self.flclash:
            return
        row = self._flclash_target()
        if row[2] and row[2] != "file":
            raise ValueError(
                f"{self._flclash_label(row)} is a {row[2]} profile; lanlock edits the file "
                "of a local profile. Export it as a file profile (or change it in "
                "FlClash's editor) first")
        clashes = [key for key in self._EDITED_DNS_KEYS if key in self._dns_override_keys(row)]
        if clashes:
            raise ValueError(
                f"{self._flclash_label(row)} overrides {', '.join(clashes)} in FlClash's own "
                "settings, which replace the profile's values; clear that override first")
        if domain is not None:
            shadow = self._flclash_added_rule(row[0], domain)
            if shadow:
                raise ValueError(
                    f"FlClash's added rule {shadow!r} is applied before the profile's rules "
                    f"and already covers {domain}; edit it in FlClash instead")

    def _flclash_seed(self):
        """The fake-IP filter list and mode a profile without one inherits.

        Read from FlClash's app-level DNS settings, which do not depend on the
        profile. The generated ``config.yaml`` must not be used: it is the merged
        result of whichever profile ran last, so it would seed one profile with
        another profile's list.
        """
        settings = _flclash_patch_dns()
        filters = settings.get("fake-ip-filter")
        mode = settings.get("fake-ip-filter-mode")
        return ([str(entry) for entry in filters] if isinstance(filters, list)
                else list(_FLCLASH_DEFAULT_FAKE_IP_FILTER),
                str(mode or "blacklist"))

    # ---------- yaml ----------
    def read(self, path=None):
        """Return the file as ``\\n``-separated text, whatever its line endings."""
        target = self.override if path is None else path
        try:
            with open(target, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError as e:
            if path is not None:
                raise
            # The path goes in the message rather than in ``filename``: OSError
            # renders ``filename`` with repr(), which on Windows escapes every
            # backslash and buries the path users need to copy.
            if self.flclash:
                raise FileNotFoundError(
                    e.errno,
                    f"FlClash profile {self._flclash_target()[1]!r} is missing its "
                    f"profile file: {target}",
                ) from None
            raise FileNotFoundError(
                e.errno,
                f"ClashTUI Mihomo override missing at {target}. Start ClashTUI to "
                "initialize it or pass --config-dir pointing to its mihomo directory",
            ) from None

    def save(self, text, expect=None):
        """Validate first, then replace the override atomically and keep one backup.

        ``text`` is treated as ``\\n``-separated and written with the newline style
        the file already uses, so a CRLF override stays CRLF and a no-op save does
        not rewrite the file. ``expect`` is the text the caller read before
        editing: a file that changed since then is refused instead of overwritten,
        because FlClash (or its own editor) may have written it in between.
        """
        text = _lf(text)
        _Override(text)
        path = os.path.realpath(self.override)
        with open(path, encoding="utf-8", newline="") as f:
            before = f.read()
            mode = S_IMODE(os.fstat(f.fileno()).st_mode)
        if expect is not None and _lf(before) != _lf(expect):
            raise ValueError(f"{path} changed since it was read; re-run to edit the "
                             "current version")
        newline = "\r\n" if "\r\n" in before else "\n"
        updated = text.replace("\n", newline)
        if before != updated:
            _atomic_write(os.path.abspath(self.override + ".bak"), before, mode)
            _atomic_write(path, updated, mode)

    # ---------- entries ----------
    def rows(self, text=None):
        return self._override(text).rows()

    def _override(self, text=None):
        if self.flclash:
            seed_filters, seed_mode = self._flclash_seed()
            return _Override(self.read() if text is None else text,
                             create_sections=True, seed_filters=seed_filters,
                             seed_filter_mode=seed_mode)
        return _Override(self.read() if text is None else text)

    def add_rule_only(self, text, domain):
        self._flclash_edit_guard(norm(domain))
        config = self._override(text)
        changed = config.add_rule(norm(domain))
        return config.render(changed), changed

    def add_filter_only(self, text, domain):
        self._flclash_edit_guard(norm(domain))
        config = self._override(text)
        changed = config.add_filter(norm(domain))
        return config.render(changed), changed

    def add(self, domain, text=None):
        """Add rule + fake-ip-filter entry. Returns (text, changed).

        FlClash also gets a ``nameserver-policy`` entry for the domain: its
        profile is merged over DNS defaults whose resolvers are public, and a
        public resolver cannot answer for an internal zone, so a DIRECT dial
        would fail without one.
        """
        domain = norm(domain)
        self._flclash_edit_guard(domain)
        config = self._override(text)
        rule = config.add_rule(domain)
        filtered = config.add_filter(domain)
        policy = config.add_policy(domain, [self.resolver]) if self.flclash else False
        changed = rule or filtered or policy
        return config.render(changed), changed

    def remove(self, domain, text=None):
        domain = norm(domain)
        self._flclash_edit_guard(domain)
        config = self._override(text)
        changed = config.remove(domain)
        if self.flclash:
            changed = config.remove_policy(domain, [self.resolver]) or changed
        return config.render(changed), changed

    def sync(self, text=None):
        """Make rules and fake-ip-filter agree in both directions.

        Policies are not created here: a domain that is merely registered is not
        evidence that its resolver should change. ``add`` writes them.

        Returns (text, [(domain, "rule"|"filter"), ...]).
        """
        self._flclash_edit_guard()
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
        return config.render(bool(added)), added

    # ---------- ClashTUI / FlClash profiles, Mihomo controller ----------
    def profiles(self):
        if self.flclash:
            try:
                return [row[1] for row in self._flclash_rows()]
            except OSError:
                return []
        try:
            result = self._clashtui("profile", "list", "--name-only")
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode or result.stdout.strip() == "No profiles found.":
            return []
        return [name.strip() for name in result.stdout.splitlines() if name.strip()]

    def active_profile(self):
        """Return the profile name in use: FlClash's edit target, ClashTUI's selection."""
        if self.flclash:
            try:
                return self._flclash_target()[1]
            except (OSError, ValueError):
                return None
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
        """Regenerate and reload: through ClashTUI, or by handing back to FlClash.

        FlClash has no command line and its Mihomo controller is off unless the
        user configures one, so the profile is edited in place and FlClash
        regenerates ``config.yaml`` the next time it starts the core.
        """
        if self.flclash:
            return self._apply_flclash(log, domains)
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

    def _apply_flclash(self, log=print, domains=None):
        """Report what was saved and how to load it; never claim it is live.

        FlClash has no command line and no controller here, so nothing reloads:
        the profile on disk is only picked up when FlClash reapplies it.
        """
        try:
            row = self._flclash_target()
        except (OSError, ValueError) as e:
            log(f"error: {e}")
            return False
        selected = _flclash_selected_profile_id()
        log(f"profile: {self._flclash_label(row)}")
        if selected is not None and selected != row[0]:
            log(f"warning: FlClash has {self._flclash_label(row)} edited but not selected; "
                "select it before reloading")
        try:
            document = self._override()
            if domains is None:
                domains = [entry["domain"] for entry in document.rows()]
        except (OSError, ValueError) as e:
            log(f"error: cannot read configuration: {e}")
            return False
        log(f"file: {self.override}")
        for d in domains:
            log("  %-36s rule=%s filter=%s policy=%s" % (
                d, "y" if d in document.rule_domains else "n",
                "y" if d in document.filter_domains else "n",
                "y" if document.has_policy(d) else "n"))
        log("saved, NOT applied: select this profile in FlClash and reapply it, or "
            "stop and start the core, then run `check`")
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
        if self.flclash and self.controller_state() != "ready":
            log("note: no Mihomo controller, so verdicts come from DNS alone "
                "(pass --api once FlClash exposes one)")
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
