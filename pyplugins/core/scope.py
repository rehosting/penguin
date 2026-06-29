"""
Analysis scoping (scope.py)
===========================

Restricts per-process **syscall/exec** analysis to the firmware-under-analysis
process subtree.

At handoff, ``init.sh`` runs the real guest init in a fresh UTS namespace, so the
firmware subtree (which inherits the namespace across fork/exec) lives outside
the kernel's initial namespace, while Penguin's own infrastructure stays in it:
the boot machinery, the backgrounded ``vpnguin``/``console``/``guesthopper``
helpers, and anything spawned via ``call_usermodehelper``.

The igloo_driver gates syscall/exec hypercall emission on that distinction
(``igloo_in_scope``), which automatically scopes every logger fed by those
hypercalls (syscalls, exec, read/write, ...). This plugin's only job is to
enable that driver-side gating, early enough to also exclude Penguin's
pre-handoff boot machinery.

Two things are deliberately **not** scoped this way:

  * **netbinds** -- bind events always report, for every process, so Penguin's
    own service binds remain visible.
  * **busybox shell coverage** -- scoped in the guest instead: busybox suppresses
    its coverage hypercalls when ``IGLOO_NO_SHELL_COV`` is set, which Penguin
    exports for its infrastructure and clears at the firmware handoff. That needs
    no host-side per-process tracking, so this plugin no longer maintains one.
"""

from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop


class Scope(Plugin):
    """
    Enables kernel-side scoping of syscall/exec analysis to the
    firmware-under-analysis subtree.

    **Arguments:** none (reads ``core.analysis_scope`` from the global config).
    """

    def __init__(self) -> None:
        conf = self.get_arg("conf")
        raw = conf["core"].get("analysis_scope", "firmware") if conf else "firmware"
        self.mode: str = self._normalize_mode(raw)

        # Scoping is active for every mode except "none". "firmware" keeps only
        # the firmware subtree; future modes (e.g. "infra") reuse the same
        # driver gating with a different interpretation.
        self.enabled: bool = self.mode != "none"
        self._enable_sent: bool = False

        if not self.enabled:
            self.logger.info("analysis_scope=none; capturing all processes")
            return

        if self.mode != "firmware":
            # The field is a string so new interpretations can be added without
            # a schema change; only "firmware"/"none" are wired up so far.
            self.logger.warning(
                "analysis_scope=%r not yet implemented; treating as 'firmware'",
                self.mode,
            )

        # Turn on kernel-side gating as early as possible (before the init
        # handoff) so Penguin's own pre-handoff boot machinery is excluded too.
        plugins.portal.register_interrupt_handler("scope", self._enable_handler)
        plugins.portal.queue_interrupt("scope")

    @staticmethod
    def _normalize_mode(raw) -> str:
        """
        Map the ``core.analysis_scope`` config value to a scope mode string.

        Booleans are accepted for backward compatibility (``True`` -> ``firmware``,
        ``False`` -> ``none``); strings are lowercased and passed through so new
        interpretations can be added without touching the schema.
        """
        if isinstance(raw, bool):
            return "firmware" if raw else "none"
        if isinstance(raw, str):
            return raw.strip().lower() or "firmware"
        return "firmware"

    def _enable_handler(self):
        """Portal interrupt handler: tell the driver to enable scope gating."""
        if self._enable_sent:
            return False
        self._enable_sent = True
        yield PortalCmd(hop.HYPER_OP_SET_SCOPE_ENABLED, addr=1)
        return False
