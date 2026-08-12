"""
QMP command API plugin.

Owns the mapping of custom QMP command names to Python handlers, mirroring
:class:`apis.hypercall.Hypercall`. ``qemu_compat`` installs a single C-level
QMP trampoline and forwards each unrecognized QMP command here; this plugin
resolves the command name to a registered handler and marshals the result.

The C trampoline is installed **lazily**: it is wired up only when the first
command is registered (usually in a consumer plugin's ``__init__``), so a
loaded-but-unused Qmp plugin never touches the QEMU callback.

This plugin is **opt-in**: unlike ``Hypercall`` it is not loaded automatically.
List ``qmp`` in the config ``plugins`` to enable it. On load it opens a QMP
socket for QEMU itself -- it appends ``-qmp unix:<outdir>/qmp.sock,...`` to the
QEMU argv (which penguin has assembled but not yet launched) -- so no
``penguin_run``/config-schema change is needed. The socket path can be
overridden with the ``socket`` arg; ``server``/``nowait`` keep QEMU from
blocking on a client.

Registration reads like every other plugin-facing capability::

    from penguin import plugins

    @plugins.qmp.command("penguin-snapshot-save")
    def save(args):
        plugins.snapshot.save(args["name"])
        return {"saved": args["name"]}

A handler receives the decoded ``arguments`` object (a dict) and returns one
of:

  * ``None`` / ``False`` -- decline the command. If no handler claims it,
    QEMU reports ``CommandNotFound``.
  * ``True`` -- handled, empty ``{"return": {}}`` response.
  * any JSON-serializable object -- used as the QMP ``return`` value.

Handler contract / caveats
--------------------------

* Handlers run **on the QEMU main loop with the BQL held** (QMP dispatch is
  not in guest context). A handler that blocks waiting on the guest freezes
  timers and I/O -- keep them short and non-blocking.
* Because dispatch is on the main loop rather than in a guest hypercall,
  guest-memory access via the portal (``yield from plugins.mem.read_*``) is
  **not** serviceable here. A handler that returns a generator is rejected
  explicitly (logged) rather than silently failing to serialize.
* The current QEMU ABI (``penguin_qmp_cb_t``) can only express "handled +
  result string" or "not handled". It cannot carry a structured
  ``{"error": {...}}``, so a handler that raises or returns a non-serializable
  value is reported to the client as ``CommandNotFound`` (with the real cause
  logged host-side). A dedicated error out-param in the QEMU fork
  (``char **error``) would let a handler surface a real ``GenericError``; that
  ABI change is intentionally deferred so nothing depends on it yet.
"""
import os
from collections.abc import Iterator
from typing import Any, Callable, Dict

from penguin import Plugin, PluginArgs
from pydantic import Field


class Qmp(Plugin):
    """QMP custom-command registry (host-side control plane).

    Replaces the compat layer's single global ``cb_qmp`` handler with a
    proper registry so multiple plugins can each own distinct QMP commands.
    """

    class Args(PluginArgs):
        socket: str = Field(
            default="qmp.sock",
            description=(
                "QMP UNIX socket path. Relative paths resolve under the run's "
                "results dir (outdir)."
            ),
        )

    def __init__(self) -> None:
        # command name -> handler. One handler per command; a second
        # registration for the same name is a hard error (see register()).
        self.handlers: Dict[str, Callable] = {}
        self.qemu_compats = []
        # Open a QMP socket for QEMU by appending to the argv penguin has
        # assembled but not yet launched (plugin __init__ runs before
        # panda.run()). This keeps the feature reachable purely by loading the
        # plugin -- no penguin_run.py / config-schema change.
        self._open_qmp_socket()
        self._bind_active_qemu_compats()

    def _open_qmp_socket(self) -> None:
        # Tolerate standalone construction (e.g. unit tests) where the plugin
        # manager hasn't run __preinit__, so self.panda/get_arg/logger are unset.
        panda = getattr(self, "panda", None)
        args = getattr(panda, "panda_args", None)
        if args is None:
            return
        if "-qmp" in args:
            # Respect an already-configured QMP socket (e.g. extra_qemu_args).
            self.logger.info("QMP socket already configured; not adding one")
            return

        sock = self.get_arg("socket") or "qmp.sock"
        outdir = self.get_arg("outdir")
        if not os.path.isabs(sock) and outdir:
            sock = os.path.join(outdir, sock)
        self.sock_path = sock
        args += ["-qmp", f"unix:{sock},server,nowait"]
        self.logger.info("QMP socket at %s", sock)

    def _bind_active_qemu_compats(self) -> None:
        try:
            from compat.qemu_compat import QemuCompat
        except Exception:
            try:
                from pyplugins.compat.qemu_compat import QemuCompat
            except Exception:
                return

        for qemu_compat in QemuCompat.active_instances():
            self.bind_qemu_compat(qemu_compat)

    def bind_qemu_compat(self, qemu_compat) -> None:
        """Attach to a QemuCompat instance.

        The C-level QMP trampoline is installed lazily -- only once at least one
        command is registered (see register()). Binding a compat that already
        has commands to serve installs immediately; otherwise it waits, so a
        loaded-but-unused Qmp plugin never touches the QEMU callback.
        """
        if qemu_compat not in self.qemu_compats:
            self.qemu_compats.append(qemu_compat)
        if self.handlers:
            self._install_dispatch(qemu_compat)

    def _install_dispatch(self, qemu_compat) -> None:
        install = getattr(qemu_compat, "install_qmp_dispatch", None)
        if install is not None:
            install(self)

    def register(self, name: str, func: Callable) -> Callable:
        """Register ``func`` as the handler for QMP command ``name``.

        Raises if ``name`` is already registered: silently replacing a handler
        (the old compat-layer behavior) means the second plugin to register
        would knock the first offline with no warning.
        """
        name = str(name)
        existing = self.handlers.get(name)
        if existing is not None and existing is not func:
            raise ValueError(
                f"QMP command {name!r} is already registered by "
                f"{getattr(existing, '__qualname__', existing)!r}; "
                "command names must be unique across plugins"
            )
        first_command = not self.handlers
        self.handlers[name] = func
        # Lazy: the first registered command installs the C trampoline on every
        # bound QemuCompat. Registering more commands is then a no-op install
        # (install_qmp_dispatch is idempotent).
        if first_command:
            for qemu_compat in self.qemu_compats:
                self._install_dispatch(qemu_compat)
        return func

    def command(self, name: str) -> Callable[[Callable], Callable]:
        """Decorator: register the wrapped function for QMP command ``name``."""
        def decorator(func: Callable) -> Callable:
            return self.register(name, func)
        return decorator

    def __call__(self, name: str) -> Callable[[Callable], Callable]:
        return self.command(name)

    def _run_result(self, command: str, result: Any) -> Any:
        """Reject generator handlers with a clear error.

        Guest-memory access via the portal isn't serviceable from the QMP
        main-loop context, so a handler that ``yield from plugins.mem.*``
        cannot work here. Fail loudly instead of letting ``json.dumps`` choke
        on a generator and surface as ``CommandNotFound``.
        """
        if isinstance(result, Iterator):
            raise RuntimeError(
                f"QMP handler for {command!r} returned a generator; guest "
                "portal access is not serviceable from QMP main-loop context"
            )
        return result

    def dispatch(self, command: str, args: Any) -> Any:
        """Resolve and invoke the handler for ``command``.

        Returns the handler's result (None/False/True/JSON-able object) for
        the compat trampoline to marshal, or None if no handler is registered
        (so QEMU reports CommandNotFound). Handler exceptions propagate to the
        trampoline, which logs and declines.
        """
        handler = self.handlers.get(command)
        if handler is None:
            return None
        result = handler(args)
        return self._run_result(command, result)
