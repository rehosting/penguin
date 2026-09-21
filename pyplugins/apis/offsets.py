"""
Struct-Offsets Plugin (offsets.py) for Penguin
==============================================

Pushes the running kernel's *recovered* struct offsets to the igloo driver so
its introspection (OSI) reads the true layout of the live vendor kernel instead
of the compile-time (donor) layout baked into ``igloo.ko``.

Background
----------

Historically igloo reads kernel structs with plain member access
(``task->pid``, ``mm->mmap_base``, ...), so every offset is fixed at build time
from the donor kernel's headers. That is correct only while the running kernel's
layout matches the donor's -- which breaks under randstruct, config drift, or a
genuinely different vendor kernel. kernel-lift recovers the true offsets of the
running kernel; the driver's ``portal_offsets.h`` exposes a runtime-offset table
(``KOFF``/``KFIELD``) fed by the ``SET_OFFSETS`` portal op. This plugin is the
host end of that channel: it serializes the recovered offsets into the driver's
wire format and issues ``SET_OFFSETS`` once, early.

Fully back-compatible / no-op by default
-----------------------------------------

- If no recovered offsets are configured, this plugin does nothing and the guest
  keeps its compile-time ``offsetof`` defaults for every field.
- If the loaded ``igloo.ko`` predates the runtime-offset work (no
  ``HYPER_OP_SET_OFFSETS`` op / no ``koff_field`` enum in the ISF), the plugin
  degrades to a no-op and logs a warning if offsets *were* configured.
- A field the host doesn't have simply keeps its in-guest default; a field the
  guest doesn't know (id out of range) is ignored by the driver.

Honest scope
------------

This fixes struct-LAYOUT portability only. It does NOT make ``igloo.ko`` loadable
against an arbitrary kernel build (module vermagic/ABI is a separate, per-build
constraint) -- it makes igloo READ the right fields once the module is running.

Configuration
-------------

Enable the plugin in the run config and give it the recovered offsets, either
inline or as a path to a JSON file, in the ``{struct: {field: offset}}`` shape
kernel-lift's recovery emits::

    struct_offsets:
      task_struct: {pid: 2464, mm: 2432, comm: 3040, cred: 3016, ...}
      mm_struct:   {mmap_base: 640, pgd: 80, ...}
      cred:        {uid: 4, gid: 8, euid: 20, egid: 24}

or::

    struct_offsets_path: /path/to/recovered_offsets.json

Only offsets for fields the driver actually exposes (its ``KOFF_FIELD_LIST`` /
``enum koff_field``) are sent; the rest are skipped with a debug log. The
acquisition classifier (kernel-lift) indicates which offsets are worth sending
(the non-STATIC set plus any layout-drift-risk fields).
"""

import json
import struct
from typing import Dict, Iterator, Tuple

from penguin import Plugin, plugins
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd

# The driver's runtime-offset field enum (portal_offsets.h). Members are named
# KF_<struct>__<field>; the enum value is the wire field_id. Pulled from the ISF
# so the host stays in lock-step with the driver with no hardcoded ordering.
KOFF_ENUM = "koff_field"


class Offsets(Plugin):
    """Push recovered struct offsets to the igloo driver via SET_OFFSETS."""

    def __init__(self) -> None:
        self._sent = False
        self._offsets = self._load_offsets()

        # Feature gate: the loaded driver must expose the SET_OFFSETS op.
        self._supported = hasattr(hop, "HYPER_OP_SET_OFFSETS")
        if not self._supported:
            if self._offsets:
                self.logger.warning(
                    "recovered struct offsets were configured, but the loaded "
                    "igloo.ko has no HYPER_OP_SET_OFFSETS op; ignoring them "
                    "(guest keeps compile-time offsets)")
            return

        self._field_ids = self._load_field_ids()
        self._payload, self._count = self._encode()

        if self._count:
            # Mirror portalcall.py: register a one-shot interrupt handler and
            # queue it so the push happens on the next portal interrupt window
            # (i.e. once the driver's mem region + portal interrupt are up).
            plugins.portal.register_interrupt_handler(
                "offsets", self._interrupt_handler)
            plugins.portal.queue_interrupt("offsets")

    # -- configuration ------------------------------------------------------

    def _load_offsets(self) -> Dict[str, Dict[str, int]]:
        """Recovered ``{struct: {field: offset}}`` from config (inline or file)."""
        offs = self.get_arg("struct_offsets")
        if isinstance(offs, dict):
            return offs
        path = self.get_arg("struct_offsets_path")
        if path:
            try:
                with open(path) as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    return loaded
                self.logger.error(
                    f"struct_offsets_path {path} is not a JSON object")
            except (OSError, ValueError) as e:
                self.logger.error(
                    f"failed to read struct_offsets_path {path}: {e}")
        return {}

    def _load_field_ids(self) -> Dict[str, int]:
        """The driver's ``KF_<struct>__<field>`` -> id map, from the ISF."""
        try:
            return dict(plugins.kffi.get_enum_dict(KOFF_ENUM).to_dict())
        except Exception as e:  # dwarffi lookup is best-effort
            self.logger.error(
                f"could not load '{KOFF_ENUM}' enum from ISF ({e}); "
                "cannot map recovered offsets to driver field ids")
            return {}

    # -- wire encoding ------------------------------------------------------

    def _encode(self) -> Tuple[bytes, int]:
        """Pack recovered offsets into the SET_OFFSETS wire buffer.

        Wire entry mirrors ``struct koff_wire_entry`` (portal_offsets.h):
        ``{ uint32 field_id; uint32 _reserved; int64 offset; }`` -> 16 bytes,
        in guest endianness. Only fields present in both the recovered set and
        the driver's field list are emitted."""
        if not self._offsets or not self._field_ids:
            return b"", 0

        endian = "<" if self.panda.endianness == "little" else ">"
        entry = struct.Struct(f"{endian}IIq")

        out = bytearray()
        count = 0
        applied, skipped = [], []
        for sname, fields in self._offsets.items():
            if not isinstance(fields, dict):
                continue
            for fname, off in fields.items():
                key = f"KF_{sname}__{fname}"
                fid = self._field_ids.get(key)
                if fid is None:
                    skipped.append(f"{sname}.{fname}")
                    continue
                if off is None or int(off) < 0:
                    skipped.append(f"{sname}.{fname}(bad offset {off})")
                    continue
                out += entry.pack(int(fid), 0, int(off))
                count += 1
                applied.append(f"{sname}.{fname}@{int(off)}")

        if applied:
            self.logger.info(
                f"prepared {count} runtime struct offsets: {', '.join(applied)}")
        if skipped:
            self.logger.debug(
                f"skipped {len(skipped)} offsets not in the driver field set: "
                f"{', '.join(skipped)}")
        return bytes(out), count

    # -- push ---------------------------------------------------------------

    def _interrupt_handler(self) -> Iterator:
        """One-shot: emit the SET_OFFSETS portal op with the packed buffer."""
        if self._sent or not self._count:
            return
        self._sent = True
        yield PortalCmd(
            hop.HYPER_OP_SET_OFFSETS, addr=0, size=self._count, data=self._payload)
        self.logger.info(
            f"pushed {self._count} runtime struct offsets to the igloo driver")
