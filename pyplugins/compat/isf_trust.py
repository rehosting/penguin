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
  ``offsets.provenance.json`` marks it.  A field of class ``invariant`` (a
  record whose layout is the same in every reference build of the data
  model: a prior from builds, not evidence from the target) is trusted, and
  answers that walk it say so (``Label.offsets``).

A third kind of file, in ``offsets.provenance.json``'s shape, carries grades
made apart from the lift (live checks against /proc through
injected system calls): an entry with ``"class": "l1-graded"`` (or
``"l1-graded-in-use"``, or ``"l1-graded+lift"``: a grade that narrowed the
field to candidates and a lift-trusted field that picked one) and
``"trusted": true`` overrides any file's
untrusted mark for that field, whatever the order of the files, and its
``offset`` is used, replacing the ISF's where they differ (a lifted ISF can
carry a vanilla value the grade found wrong).  Only graded entries override:
the lift's own files never clear each other's marks.  Answers that walk a
field taken this way say so in their label (``Label.offsets ==
"l1-graded"``, compat/osi_label.py).
"""
import json
import logging
import lzma
import os

UNTRUSTED_CLASSES = {"reference-carried", "collisions"}
GRADED_CLASSES = {"l1-graded", "l1-graded-in-use", "l1-graded+lift"}

logger = logging.getLogger("isf_trust")
_untrusted = None
_graded = {}
_accepted = set()
_invariant = set()
_invariant_used = set()
_source = None


def _open(path):
    return lzma.open(path, "rt") if path.endswith(".xz") else open(path)


def _read(path):
    """(the "struct.field" names @path marks untrusted, {name: offset} of
    its l1-graded entries, the names it classes invariant)"""
    with _open(path) as f:
        d = json.load(f)
    out, graded, invariant = set(), {}, set()
    for key, v in (d.get("fields") or {}).items():
        if not isinstance(v, dict):
            continue
        if "trusted" in v:                      # offsets.provenance.json's shape
            if v["trusted"] and v.get("class") in GRADED_CLASSES:
                graded[key] = v.get("offset")
            elif not v["trusted"]:
                out.add(key)
            continue
        for cls, fields in v.items():           # the lift's provenance.json
            if cls in UNTRUSTED_CLASSES:
                out.update(f"{key}.{name}" for name in fields)
            elif cls == "invariant":
                invariant.update(f"{key}.{name}" for name in fields)
    return out, graded, invariant


def load(path):
    """the "struct.field" names @path marks untrusted"""
    return _read(path)[0]


def untrusted():
    """the untrusted fields of every PENGUIN_ISF_PROVENANCE file (read once
    per value of the variable)"""
    global _untrusted, _graded, _source
    src = os.environ.get("PENGUIN_ISF_PROVENANCE", "")
    if _untrusted is None or src != _source:
        _untrusted, _graded, _source = set(), {}, src
        _accepted.clear()
        _invariant.clear()
        _invariant_used.clear()
        for p in filter(None, src.split(":")):
            u, g, i = _read(p)
            _untrusted |= u
            _graded.update(g)
            _invariant.update(i)
    return _untrusted


def _name(struct, field):
    if struct.startswith("struct "):
        struct = struct[len("struct "):]
    return f"{struct}.{field}"


def offset(struct, field, isf_offset):
    """the offset to use for @struct.@field (@struct with or without
    "struct "): the ISF's (@isf_offset, -1 if it has none) if trusted; an
    l1-graded entry's if not; else -1"""
    name = _name(struct, field)
    if name not in untrusted():
        if name in _invariant and isf_offset >= 0:
            _invariant_used.add(name)
        return isf_offset
    if name not in _graded:
        return -1
    g = _graded[name]
    g = isf_offset if g is None else int(g)
    if name not in _accepted:
        _accepted.add(name)
        if isf_offset >= 0 and g != isf_offset:
            logger.info("isf_trust: %s at %d (l1-graded), not the ISF's %d", name, g, isf_offset)
    return g


def trusted(struct, field):
    """may @struct.@field be used at all (trusted, or l1-graded)?"""
    name = _name(struct, field)
    return name not in untrusted() or name in _graded


def graded_used():
    """the untrusted fields an l1-graded entry let through, so far"""
    untrusted()
    return set(_accepted)


def invariant_used():
    """the fields taken on the strength of class invariant, so far"""
    untrusted()
    return set(_invariant_used)
