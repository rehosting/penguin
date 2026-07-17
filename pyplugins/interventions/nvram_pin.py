"""Pin (force) selected nvram keys at the libnvram VFS read layer.

Some firmware restores nvram defaults on every boot, clobbering values that a
rehost needs to hold steady (e.g. asuswrt's per-boot ``## Restoring defaults ##``
/ ``init_nvram`` rewrites the WAN keys, so ``wan0_ifname`` goes empty and the WAN
never comes up). Config-level nvram seeding does not survive that.

penguin's nvram is file-backed: the libnvram shim stores one file per key under
``/igloo/libnvram_tmpfs/`` and, on get, does ``access(path, F_OK)`` then
``fopen(path, "rb")`` + a ``while (fgets(...))`` read loop. The value the firmware
sees is whatever bytes ``read()`` returns for that file. The ``nvram2`` tracker
only *logs* get/set (it cannot change the returned value), and pseudofiles only
model ``/dev``/``/proc``/``/sys`` paths, not a regular tmpfs file -- so neither
can force a value.

This plugin forces values at the VFS read layer instead: in ``on_sys_read_return``
it resolves the fd to its path (``OSI.get_fd_name``), and if the path is a pinned
key under the tmpfs mount it overwrites the read buffer with the pinned value
**once per open** (tracked by ``(pid, fd)``, cleared on ``on_sys_close_enter``),
then forces ``retval = 0`` (EOF) so the shim's ``fgets`` loop terminates. This is
immune to the restore truncating/emptying the file -- as long as the key file
*exists* (so the ``access`` gate passes), which config-level nvram seeding of the
same keys guarantees.

Config::

    plugins:
      nvram_pin:
        pins:
          wan0_ifname: wan0
          wan0_proto: static

The key files must also be seeded (via the ``nvram:`` block) so they exist;
otherwise the shim's ``access(F_OK)`` gate bails before ``read()`` and the
override never fires.
"""
from os.path import basename
from typing import Dict, Optional

from pydantic import Field

from penguin import Plugin, PluginArgs, plugins

MOUNT_POINT = "/igloo/libnvram_tmpfs/"


class nvram_pin(Plugin):
    class Args(PluginArgs):
        pins: Optional[Dict[str, str]] = Field(
            default=None,
            description="nvram key -> forced value, applied at the libnvram read layer")

    def __init__(self):
        pins = self.get_arg("pins")
        if not pins:
            # Fallback for when this plugin is loaded as a project-local drop-in
            # (whose nested args are stripped during config processing): read a
            # conf["env"] sentinel IGLOO_NVRAM_PIN="key=value;key=value;...".
            conf = self.get_arg("conf") or {}
            spec = (conf.get("env") or {}).get("IGLOO_NVRAM_PIN", "")
            pins = {}
            for item in spec.split(";"):
                item = item.strip()
                if not item or "=" not in item:
                    continue
                k, v = item.split("=", 1)
                pins[k.strip()] = v.strip()
        # Normalise every value to str -> bytes once.
        self.pins = {str(k): str(v).encode() for k, v in pins.items()}
        # (pid, fd) already served this open -> force EOF on subsequent reads so
        # the firmware's `while (fgets(...))` loop terminates.
        self.served = set()
        self.hits = {}
        self.logger.setLevel("INFO")
        self.logger.info(
            f"nvram_pin loaded, pinning {len(self.pins)} keys: "
            f"{', '.join(sorted(self.pins))}")

    def _match_key(self, fname):
        if not fname or not fname.startswith(MOUNT_POINT):
            return None
        key = basename(fname)
        return key if key in self.pins else None

    @plugins.syscalls.syscall("on_sys_read_return")
    def _read(self, regs, proto, syscall, fd, buf, count):
        fname = yield from plugins.OSI.get_fd_name(fd)
        key = self._match_key(fname)
        if key is None:
            return
        proc = yield from plugins.OSI.get_proc()
        pid = proc.pid if proc else -1
        tag = (pid, int(fd))
        if tag in self.served:
            # Second+ read of this open: the pinned value was already delivered.
            # Return EOF so fgets() stops instead of re-reading offset 0 forever.
            syscall.retval = 0
            return
        data = self.pins[key]
        n = min(len(data), int(count))
        yield from plugins.mem.write_bytes(buf, data[:n])
        syscall.retval = n
        self.served.add(tag)
        self.hits[key] = self.hits.get(key, 0) + 1
        if self.hits[key] <= 3 or self.hits[key] % 50 == 0:
            self.logger.info(
                f"pinned {key} = {data.decode(errors='replace')!r} "
                f"(pid={pid} fd={int(fd)}, hit #{self.hits[key]})")

    @plugins.syscalls.syscall("on_sys_close_enter")
    def _close(self, regs, proto, syscall, fd):
        proc = yield from plugins.OSI.get_proc()
        pid = proc.pid if proc else -1
        self.served.discard((pid, int(fd)))

    def on_stop(self):
        self.logger.info(
            "nvram_pin: served pins " +
            ", ".join(f"{k}x{v}" for k, v in sorted(self.hits.items())))
