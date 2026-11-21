"""lanlock — keep internal domains on DIRECT in a clashtui-managed mihomo.

Quick start::

    from lanlock import MihomoConfig

    cfg = MihomoConfig()                 # ClashTUI override, or a FlClash profile
    text, changed = cfg.add("corp.example")
    if changed:
        cfg.save(text)
    cfg.apply(log=print)                 # regenerate and reload (ClashTUI), or
                                         # report the restart FlClash needs
    for row in cfg.audit(log=print):     # check DNS and observed routing decisions
        print(row["domain"], row["verdict"])

Everything is also available as a CLI (``lanlock``) and a Textual UI (``lanlock-tui``).
"""
from .config import MihomoConfig, dns_check, norm
from .probe import audit, probe

__all__ = ["MihomoConfig", "norm", "audit", "probe", "dns_check"]
__version__ = "0.1.0"
