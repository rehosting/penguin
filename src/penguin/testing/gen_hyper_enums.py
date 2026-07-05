"""Regenerate ``hyper_enums.json`` — the captured real values of the ``hyper.consts``
enums, used by ``penguin.testing.install_fake_enums`` so host-side tests behind the
FFI-enum boundary see *real* enum values instead of bogus auto-ints.

Source of truth: the published kernel/driver ISF pair Penguin ships
(``igloo.ko.<arch>.json.xz`` + ``cosi.<arch>.json.xz``), read via ``dwarffi`` — the
exact path ``apis.kffi`` uses at runtime (``get_type(name).constants``). The values
are C enum constants and are arch-invariant, so one arch's capture covers all.

This is dev-only tooling (needs ``dwarffi`` + a real ISF); it is not imported by
the test suite. Re-run it when the driver's enums change:

    python -m penguin.testing.gen_hyper_enums \\
        --igloo-ko /path/to/igloo.ko.armel.json.xz \\
        --cosi     /path/to/cosi.armel.json.xz

(omit args to auto-discover an ``igloo.ko.*.json.xz`` + ``cosi.*.json.xz`` pair
under /nix/store or a --kernels dir).
"""
import argparse
import glob
import json
import os

# The enums hyper.consts exposes (mirrors hyper/consts.py::enum_names).
ENUM_NAMES = [
    "HYPER_OP",
    "portal_type",
    "igloo_hypercall_constants",
    "igloo_base_hypercalls",
    "hyperfs_ops",
    "hyperfs_file_ops",
    "value_filter_type",
]

FIXTURE = os.path.join(os.path.dirname(__file__), "hyper_enums.json")


def _discover(pattern, search):
    for root in search:
        hits = glob.glob(os.path.join(root, "**", pattern), recursive=True)
        if hits:
            return sorted(hits)[0]
    return None


def extract(igloo_ko, cosi):
    from dwarffi.dffi import DFFI
    ffi = DFFI([igloo_ko, cosi])
    out = {}
    for name in ENUM_NAMES:
        t = ffi.get_type(name)
        consts = getattr(t, "constants", None) if t else None
        if not isinstance(consts, dict) or not consts:
            raise SystemExit(f"enum {name!r} not found / empty in ISF {igloo_ko}")
        out[name] = {k: int(v) for k, v in sorted(consts.items())}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--igloo-ko", help="path to igloo.ko.<arch>.json.xz")
    ap.add_argument("--cosi", help="path to cosi.<arch>.json.xz")
    ap.add_argument("--kernels", action="append", default=["/nix/store"],
                    help="dir(s) to search for the ISF pair (repeatable)")
    args = ap.parse_args()

    igloo_ko = args.igloo_ko or _discover("igloo.ko.*.json.xz", args.kernels)
    cosi = args.cosi or _discover("cosi.*.json.xz", args.kernels)
    if not igloo_ko or not cosi:
        raise SystemExit("could not find ISF pair; pass --igloo-ko/--cosi")
    print(f"igloo.ko ISF: {igloo_ko}\ncosi ISF:     {cosi}")

    data = extract(igloo_ko, cosi)
    data["_meta"] = {
        "source": "penguin kernel/driver ISF (dwarffi get_type().constants)",
        "igloo_ko": os.path.basename(igloo_ko),
        "cosi": os.path.basename(cosi),
        "note": "C enum values, arch-invariant; regenerate via "
                "python -m penguin.testing.gen_hyper_enums",
    }
    with open(FIXTURE, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    counts = {k: len(v) for k, v in data.items() if k != "_meta"}
    print(f"wrote {FIXTURE}: {counts}")


if __name__ == "__main__":
    main()
