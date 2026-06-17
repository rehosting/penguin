"""
Snapshot Plugin (snapshot.py) for Penguin
==========================================

Saves and restores VM snapshots (QEMU savevm/loadvm). Driven by the
``core.snapshot`` config section (snapshotting is active whenever ``save_at`` or
``boot_from`` is set — there is no separate enable flag):

- ``save_at: readiness``: save once the guest reaches steady state.
- ``save_at: manual``: save/restore on request — from inside the guest via the
  ``snapshot_save`` / ``snapshot_load`` hypercalls, or from the host via the
  RemoteCtrl socket (see ``cli_snapshot``).
- ``boot_from``: the run was already restored at boot via ``-loadvm``; this
  plugin announces the restore so host-side plugins can rehydrate.

All save requests funnel into :meth:`request_save`, which *arms* the capture at a
chosen execution boundary ("find a safe spot") rather than snapping at the
request instant:

- ``when="next_syscall"`` (default for host-driven requests): capture at the next
  syscall return (optionally filtered to a process) — a clean userspace/kernel
  boundary.
- ``when="symbol"``: capture when execution reaches a symbol (one-shot uprobe).
- ``when="now"``: capture immediately (used by the in-guest triggers, which are
  already at a hypercall boundary).

The actual save/restore is always handed to ``KVMQemu.schedule_snapshot`` (a
main-loop bottom half), so it is safe to request from a vCPU-thread callback.

Other plugins that hold host-side state (e.g. the VPN bridge) reconcile by
subscribing to this plugin's ``on_snapshot`` / ``on_restore`` events.
"""

import json
import os
from datetime import datetime
from os.path import join

import yaml

from penguin import Plugin, plugins


class Snapshot(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        conf = self.get_arg("conf")
        snap = (conf["core"].get("snapshot") if conf else None) or {}

        self.tag = snap.get("tag", "boot")
        self.save_at = snap.get("save_at")
        self.boot_from = snap.get("boot_from")
        self.stop_after_save = bool(snap.get("stop_after_save"))
        # Snapshotting is active whenever a save or restore is configured;
        # there is no separate enable flag.
        self.enabled = (self.save_at is not None) or (self.boot_from is not None)
        self.saved = False
        # Live one-shot arming handles, so we can guard against double-fire.
        self._armed = []

        # Lifecycle events for host-side reconciliation around save/restore.
        plugins.register(self, "on_snapshot")
        plugins.register(self, "on_restore")

        if not self.enabled:
            self.logger.debug("core.snapshot not enabled; plugin idle")
            return

        if self.save_at == "readiness":
            # Observe the Readiness plugin's broadcast (don't steal the
            # single-subscriber send_hypercall "readiness" event).
            plugins.subscribe(plugins.Readiness, "ready", self.on_ready)

        # Manual triggers from inside the guest (no-op unless the guest issues
        # them). Registered regardless of save_at so a user can always poke a
        # save/restore via guest_cmd.
        plugins.send_hypercall.subscribe("snapshot_save", self.on_guest_save)
        plugins.send_hypercall.subscribe("snapshot_load", self.on_guest_load)

        if self.boot_from:
            # The VM was already restored at boot via -loadvm. Defer host-side
            # rehydration until ALL plugins have loaded (some load after us):
            # penguin_run calls dispatch_restore() right after load_plugins,
            # before the guest resumes.
            self.logger.info("Run booted from snapshot '%s'", self.boot_from)

    def dispatch_restore(self) -> None:
        """Rehydrate host-side state for a boot_from restore.

        Called by penguin_run after all plugins are loaded and before the guest
        resumes. Loads the snapshot's host sidecar into each plugin's
        load_state, then fires on_restore so plugins can re-establish bridges /
        replay bindings.
        """
        if not self.boot_from:
            return
        self._restore_host_state(self.boot_from)
        self._dispatch_lifecycle("on_restore", self.boot_from)
        plugins.publish(self, "on_restore", self.boot_from)

    # --- triggers -----------------------------------------------------------

    def on_ready(self, kind: str = "igloo_init"):
        # Readiness IS the chosen point; capture at the next main-loop tick.
        if kind == "igloo_init" and not self.saved:
            self.request_save(self.tag, when="now")

    def on_guest_save(self, tag: str = "", when: str = "now", proc: str = ""):
        # The guest explicitly asked, from a hypercall boundary.
        ok = self.request_save(tag or self.tag, when=when or "now",
                               proc=proc or None)
        return (0 if ok else 1), ("snapshot armed" if ok else "not armed")

    def on_guest_load(self, tag: str = ""):
        ok = self.request_restore(tag or self.tag)
        return (0 if ok else 1), ("restore scheduled" if ok else "not scheduled")

    # --- public API ---------------------------------------------------------

    def request_save(self, tag=None, when="next_syscall", proc=None,
                     symbol=None) -> bool:
        """Arm a savevm at a safe execution boundary.

        :param tag: snapshot name (defaults to the configured tag).
        :param when: ``next_syscall`` | ``symbol`` | ``now``.
        :param proc: optional process-name filter for the boundary.
        :param symbol: required when ``when='symbol'``.
        :return: True if the capture was scheduled/armed.
        """
        tag = tag or self.tag
        if when == "now":
            return self._do_save_now(tag)
        if when == "next_syscall":
            return self._arm(tag, self._register_syscall_boundary, proc)
        if when == "symbol":
            if not symbol:
                self.logger.error("snapshot when='symbol' needs a symbol")
                return False
            return self._arm(tag, self._register_symbol_boundary, proc, symbol)
        self.logger.error("Unknown snapshot 'when': %s", when)
        return False

    def request_restore(self, tag=None) -> bool:
        """Schedule a loadvm of ``tag`` into the running guest."""
        tag = tag or self.tag
        self.logger.info("Scheduling snapshot restore '%s'", tag)
        ok = self.panda.schedule_snapshot(tag, load=True)
        if ok:
            plugins.publish(self, "on_restore", tag)
        return ok

    # --- safe-spot arming ---------------------------------------------------

    def _arm(self, tag, register_fn, proc, symbol=None) -> bool:
        """Register a one-shot boundary hook that fires the save exactly once."""
        state = {"fired": False, "handle": None, "unregister": None}

        def fire(*_args, **_kwargs):
            if state["fired"]:
                return
            state["fired"] = True
            try:
                if state["unregister"] and state["handle"] is not None:
                    state["unregister"](state["handle"])
            except Exception as e:
                self.logger.debug("snapshot hook unregister failed: %s", e)
            self._do_save_now(tag)

        try:
            state["handle"], state["unregister"] = register_fn(fire, proc, symbol)
        except Exception as e:
            self.logger.error("Failed to arm snapshot boundary: %s", e)
            return False
        self._armed.append(state)
        where = symbol or (f"proc {proc}" if proc else "any process")
        self.logger.info("Armed snapshot '%s' at %s (%s)", tag,
                         register_fn.__name__.replace("_register_", "").replace("_boundary", ""),
                         where)
        return True

    def _register_syscall_boundary(self, cb, proc, _symbol):
        handle = plugins.syscalls.syscall("on_all_sys_return", comm_filter=proc)(cb)
        return handle, plugins.syscalls.unregister

    def _register_symbol_boundary(self, cb, proc, symbol):
        handle = plugins.uprobes.uprobe(symbol=symbol, process_filter=proc)(cb)
        return handle, plugins.uprobes.unregister

    # --- actions ------------------------------------------------------------

    def _do_save_now(self, tag: str) -> bool:
        """Schedule a savevm of the running guest under ``tag`` immediately."""
        self.logger.info("Scheduling snapshot save '%s'", tag)
        ok = self.panda.schedule_snapshot(tag, load=False)
        if ok:
            self.saved = True
            self._write_sidecar(tag)
            self._save_host_state(tag)
            self._dispatch_lifecycle("on_snapshot", tag)
            plugins.publish(self, "on_snapshot", tag)
            if self.stop_after_save:
                # The save runs on the main loop; the shutdown request is
                # honoured after the queued snapshot bottom-half completes.
                self.logger.info("stop_after_save set; ending analysis")
                self.panda.end_analysis()
        return ok

    # --- host-side state (output-dir carry + opt-in save/load_state) --------

    def _host_sidecar_path(self, tag: str) -> str:
        # Travels with the snapshot overlay (qcows/) rather than the per-run
        # output dir, so a fresh cross-process restore run can find it.
        return join(self.proj_dir, "qcows", f"snapshot_{tag}.host.json")

    def _iter_plugins(self):
        # plugins.plugins maps name -> instance for everything loaded.
        return list(getattr(self.plugins, "plugins", {}).values())

    def _save_host_state(self, tag: str) -> None:
        states = {}
        for p in self._iter_plugins():
            try:
                data = p.save_state()
            except Exception as e:
                self.logger.warning("save_state failed for %s: %s", p.name, e)
                continue
            if data is not None:
                states[p.name] = data
        if not states:
            return
        path = self._host_sidecar_path(tag)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(states, f)
        self.logger.info("Saved host-side state for %d plugin(s) to %s",
                         len(states), path)

    def _restore_host_state(self, tag: str) -> None:
        path = self._host_sidecar_path(tag)
        if not os.path.isfile(path):
            self.logger.debug("No host sidecar for snapshot '%s'", tag)
            return
        with open(path) as f:
            states = json.load(f)
        by_name = {p.name: p for p in self._iter_plugins()}
        for name, data in states.items():
            p = by_name.get(name)
            if p is None:
                self.logger.debug("Plugin %s not loaded; skipping its state", name)
                continue
            try:
                p.load_state(data)
            except Exception as e:
                self.logger.warning("load_state failed for %s: %s", name, e)

    def _dispatch_lifecycle(self, method_name: str, tag: str) -> None:
        for p in self._iter_plugins():
            if p is self:
                continue
            try:
                getattr(p, method_name)(tag)
            except Exception as e:
                self.logger.warning("%s.%s failed: %s", p.name, method_name, e)

    # --- helpers ------------------------------------------------------------

    def _write_sidecar(self, tag: str) -> None:
        os.makedirs(self.outdir, exist_ok=True)
        meta = {"tag": tag, "saved_at": datetime.now().isoformat()}
        with open(join(self.outdir, "snapshot.yaml"), "w") as f:
            yaml.safe_dump(meta, f, sort_keys=True)
