"""
Which of a lifted ISF's fields to believe
=========================================

A kernel ISF lifted from a vendor binary (kernel-lift) says, per field, how
it was obtained.  QEMU's syscall trap (compat/syscall_trap.py) and its OSI
walks (compat/osi_layout.py) take only the fields it trusts: an untrusted
one is treated as absent (offset -1), so whatever needs it is not done, and
an OSI answer that needs it is unavailable rather than possibly wrong.
Fields the provenance does not name are taken as the ISF has them.

The provenance comes from ``PENGUIN_ISF_PROVENANCE``: one or more paths
(``:``-separated) to either of kernel-lift's files:

- ``offsets.provenance.json`` (export-offsets): ``fields`` maps
  ``"struct.field"`` to ``{"trusted": bool, ...}``;
- ``provenance.json`` (the lift): ``fields`` maps a struct to its fields by
  class; ``reference-carried`` is untrusted, ``target-verified`` and
  ``inferred`` are trusted.  A field in its ``collisions`` (its offset falls
  inside a verified field) is untrusted whatever its class, as
  ``offsets.provenance.json`` marks it.
"""
import json
import lzma
import os

UNTRUSTED_CLASSES = {"reference-carried", "collisions"}

_untrusted = None
_source = None


def _open(path):
    return lzma.open(path, "rt") if path.endswith(".xz") else open(path)


def load(path):
    """the "struct.field" names @path marks untrusted"""
    with _open(path) as f:
        d = json.load(f)
    out = set()
    for key, v in (d.get("fields") or {}).items():
        if not isinstance(v, dict):
            continue
        if "trusted" in v:                      # offsets.provenance.json
            if not v["trusted"]:
                out.add(key)
            continue
        for cls, fields in v.items():           # the lift's provenance.json
            if cls in UNTRUSTED_CLASSES:
                out.update(f"{key}.{name}" for name in fields)
    return out


def untrusted():
    """the untrusted fields of every PENGUIN_ISF_PROVENANCE file (read once
    per value of the variable)"""
    global _untrusted, _source
    src = os.environ.get("PENGUIN_ISF_PROVENANCE", "")
    if _untrusted is None or src != _source:
        _untrusted, _source = set(), src
        for p in filter(None, src.split(":")):
            _untrusted |= load(p)
    return _untrusted


def trusted(struct, field):
    """may the ISF's offset of @struct.@field be used?  @struct with or
    without "struct " """
    if struct.startswith("struct "):
        struct = struct[len("struct "):]
    return f"{struct}.{field}" not in untrusted()
