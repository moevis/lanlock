"""Command line interface: lanlock [options] <command> ..."""
import argparse
import sys

from . import __version__
from .config import DEFAULT_API, DEFAULT_RESOLVER, MihomoConfig, norm


def _tolerant_stdio():
    """Stop non-ASCII output from crashing a redirected Windows stream.

    Profile labels, paths and the controller hint are not guaranteed ASCII; a
    cp1252 pipe would raise UnicodeEncodeError while printing them.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def _cfg(args):
    return MihomoConfig(config_dir=args.config_dir, api=args.api, profile=args.profile,
                        resolver=args.resolver, backend=args.backend,
                        secret=args.secret)


def build_parser():
    p = argparse.ArgumentParser(prog="lanlock",
                                description="keep internal domains on DIRECT in mihomo")
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

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ls", help="list registered domains")
    sub.add_parser("check", help="probe every domain, exit 1 on LEAK/FAKE-IP/MISMATCH")
    sub.add_parser("sync", help="make rules and fake-ip-filter agree both ways")
    sub.add_parser("tui", help="Textual UI")

    for name, hlp in (("add", "add domains"), ("rm", "remove domains")):
        sp = sub.add_parser(name, help=hlp)
        sp.add_argument("domains", nargs="+")
        sp.add_argument("--no-apply", action="store_true",
                        help="edit the override only, skip ClashTUI regeneration and reload")

    for name in ("sync",):
        sub.choices[name].add_argument("--no-apply", action="store_true")
    return p


def _load_tui():
    try:
        from . import tui
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] not in ("textual", "rich"):
            raise
        print('error: install the TUI extra with pip install "lanlock[tui]"',
              file=sys.stderr)
        return None
    return tui


def tui_main(argv=None):
    tui = _load_tui()
    return 2 if tui is None else tui.main(argv)


def main(argv=None):
    _tolerant_stdio()
    args = build_parser().parse_args(argv)
    # Report a missing TUI extra before resolving a backend: the extra is what
    # the user asked for, and it must not depend on any configuration existing.
    if args.cmd == "tui" and _load_tui() is None:
        return 2
    try:
        return _run(args, _cfg(args))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def _run(args, cfg):
    if args.cmd == "tui":
        tui = _load_tui()
        return 2 if tui is None else tui.run(cfg)

    domains = list(dict.fromkeys(map(norm, args.domains))) if args.cmd in ("add", "rm") else []
    text = original = cfg.read()
    if args.cmd == "ls":
        for row in cfg.rows(text):
            print(f"{row['domain']:40s} rule={'y' if row['rule'] else '-'} "
                  f"filter={'y' if row['filter'] else '-'}"
                  + (f" target={row['match_target']}" if row.get("match_target") else ""))
        print(f"rules: {cfg.rule_count(text)} in {cfg.override}")
        print("backend:", f"{cfg.backend} ({cfg.config_dir})")
        print("profile:", cfg.active_profile() or "?")
        print("controller:", cfg.controller_state())
        return 0

    if args.cmd == "check":
        domains = [r["domain"] for r in cfg.rows(text)]
        if not domains:
            print("no domains registered")
            return 0
        results = cfg.audit(log=print, domains=domains, text=text)
        return 1 if any(r["verdict"] in ("LEAK", "FAKE-IP", "MISMATCH") for r in results) else 0

    if args.cmd == "sync":
        text, added = cfg.sync(text)
        if not added:
            print("already in sync")
            return 0
        cfg.save(text, expect=original)
        for d, kind in added:
            print(f"+{kind:6s} {d}")
        print(f"edited {cfg.override} (backup: {cfg.override}.bak)")
        if not args.no_apply:
            ok = cfg.apply(log=print, domains=list(dict.fromkeys(d for d, _ in added)))
            return 0 if ok else 1
        return 0

    changed = False
    messages = []
    for d in domains:
        if args.cmd == "add":
            text, edited = cfg.add(d, text)
            messages.append(f"{'added  ' if edited else 'present'} {d}")
        else:
            text, edited = cfg.remove(d, text)
            messages.append(f"{'removed' if edited else 'absent '} {d}")
        changed |= edited
    if changed:
        cfg.save(text, expect=original)
    for message in messages:
        print(message)
    if changed:
        print(f"edited {cfg.override} (backup: {cfg.override}.bak)")
    if not args.no_apply:
        ok = cfg.apply(log=print, domains=domains)
        return 0 if ok else 1
    return 0
