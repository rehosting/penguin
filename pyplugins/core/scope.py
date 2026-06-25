"""
Analysis scoping (scope.py)
===========================

Restricts per-process analysis to the firmware-under-analysis process subtree.

At handoff, ``init.sh`` runs the real guest init in a fresh UTS namespace, so the
firmware subtree (which inherits the namespace across fork/exec) lives outside
the kernel's initial namespace, while Penguin's own infrastructure stays in it:
the boot machinery, the backgrounded ``vpnguin``/``console``/``guesthopper``
helpers, and anything spawned via ``call_usermodehelper``.

The igloo_driver gates syscall/exec/bind hypercall emission on that distinction
(``igloo_in_scope``), which automatically scopes every logger fed by those
hypercalls (syscalls, exec, read/write, binds, ...). This plugin:

  * enables that driver-side gating when ``core.analysis_scope`` is set, early
    enough to also exclude Penguin's pre-handoff boot machinery, and
  * exposes ``plugins.scope.in_scope(pid)`` for the two emission paths the
    driver does not see -- busybox shell coverage and libnvram getenv/strstr --
    so ``shell.py`` and ``env.py`` can drop out-of-scope events.

The in-scope pid set is seeded for free from the (already driver-scoped)
``exec_event`` stream: every exec the host hears is in-scope by construction,
so its pid belongs to the firmware subtree.
"""

from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop


class Scope(Plugin):
    """
    Tracks which guest pids belong to the firmware-under-analysis subtree and
    enables kernel-side analysis gating.

    **Arguments:** none (reads ``core.analysis_scope`` from the global config).
    """

    def __init__(self) -> None:
        conf = self.get_arg("conf")
        self.enabled: bool = (
            bool(conf["core"].get("analysis_scope", True)) if conf else True
        )

        # pids known to be in the firmware subtree (seen via in-scope exec_event)
        self.in_scope_pids: set = set()
        self._enable_sent: bool = False

        if not self.enabled:
            self.logger.info("analysis_scope disabled; capturing all processes")
            return

        # Turn on kernel-side gating as early as possible (before the init
        # handoff) so Penguin's own pre-handoff boot machinery is excluded too.
        plugins.portal.register_interrupt_handler("scope", self._enable_handler)
        plugins.portal.queue_interrupt("scope")

        plugins.subscribe(plugins.Execs, "exec_event", self._on_exec_event)

    def _enable_handler(self):
        """Portal interrupt handler: tell the driver to enable scope gating."""
        if self._enable_sent:
            return False
        self._enable_sent = True
        yield PortalCmd(hop.HYPER_OP_SET_SCOPE_ENABLED, addr=1)
        return False

    def _on_exec_event(self, event) -> None:
        """Record the pid of every (already in-scope) exec we observe."""
        # exec_event is published as a Wrapper; unwrap to the underlying dict.
        data = event.unwrap() if hasattr(event, "unwrap") else event
        proc = data.get("proc") if hasattr(data, "get") else None
        pid = getattr(proc, "pid", None)
        if pid is not None:
            try:
                self.in_scope_pids.add(int(pid))
            except (TypeError, ValueError):
                pass

    def in_scope(self, pid) -> bool:
        """
        Whether ``pid`` belongs to the firmware-under-analysis subtree.

        Returns ``True`` for everything when scoping is disabled, so callers can
        gate unconditionally.
        """
        if not self.enabled:
            return True
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            # Unknown / unreadable pid: treat as out of scope.
            return False
        return pid in self.in_scope_pids
