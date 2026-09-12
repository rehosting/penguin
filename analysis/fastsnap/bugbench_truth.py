"""Ground truth for bugbench_victim.c, and the scorer that grades a run against it.

WHY THIS FILE EXISTS SEPARATELY FROM THE HARNESS. A fuzzing result of the form
"we found three crashes" has no denominator: it cannot distinguish a strong
fuzzer on a hard target from a weak one on an easy target, and it cannot
distinguish "did not find B6" from "B6 is unreachable because the harness never
delivered a byte that far into the request". The victim has a closed, known set
of bugs, so every run can be scored against what a working fuzzer SHOULD have
found.

Two entries here are not bugs and carry the weight of the result:

  SAFE   opcode 0x00 is a negative control. It must never appear in a crash
         report. If it does, the harness is manufacturing crashes and every
         positive finding in the same run is suspect.

  B1     is the canary. It is reachable by essentially any 8-byte input whose
         first byte is 0x01. A run that reports zero crashes INCLUDING B1 has
         a broken pipeline -- injection, detection or attribution -- and the
         honest conclusion is "harness broken", not "target robust".

Grading a run without both of those is how a plumbing failure gets written up
as a security result.
"""

import hashlib

PAGE_NOTE = "req[0] is the opcode; every bug indexes at least req[5], so inputs shorter than 8 bytes reach nothing."


def _inp(*prefix, length=32, fill=0x41):
    """Build a request: the given prefix, padded to `length`."""
    b = bytearray([fill]) * length
    for i, v in enumerate(prefix):
        b[i] = v
    return bytes(b)


# tier: how much search each bug should require of a working fuzzer.
#   trivial -- almost any input with the right opcode
#   easy    -- needs one specific operand byte
#   hard    -- needs a 4-byte magic (2^-32 blind)
#   hardest -- needs two independent conditions to hold at once
BUGS = [
    {
        "id": "B1",
        "name": "stack_overflow",
        "tier": "trivial",
        "role": "canary",
        # Both, and which one you get is a property of the TOOLCHAIN, not the
        # bug: a build with -fstack-protector detects the smash and abort()s
        # (SIGABRT) before the corrupted return address is ever used (SIGSEGV).
        # Measured natively: gcc -O1 with its default hardening gives SIGABRT.
        # Pinning this to SIGSEGV would have scored a correctly-found canary as
        # a miss on any hardened target, and a miss on the canary is read as
        # "harness broken" -- so the manifest would have condemned a working
        # pipeline. Both signals are in the crash plugin's watched set.
        "signal": "SIGSEGV|SIGABRT",
        "func": "bug1_stack_overflow",
        "trigger": _inp(0x01, 0xFF),
        "why": "unvalidated length copy into a 16-byte stack buffer; any req[1] > 16 overflows",
    },
    {
        "id": "B2",
        "name": "null_deref",
        "tier": "trivial",
        "signal": "SIGSEGV",
        "func": "bug2_null_deref",
        "trigger": _inp(0x02, 0x00),
        "why": "dereferences NULL unless req[1] == 0xff",
    },
    {
        "id": "B3",
        "name": "div_zero",
        "tier": "trivial",
        "signal": "SIGFPE",
        "func": "bug3_div_zero",
        "trigger": _inp(0x03, 0x00),
        "why": "1000 / req[1] with req[1] == 0",
    },
    {
        "id": "B4",
        "name": "oob_read",
        "tier": "easy",
        "signal": "SIGSEGV",
        "func": "bug4_oob_read",
        "trigger": _inp(0x04, 0x80),
        "why": "indexes an 8-byte table at req[1] * 1MB",
    },
    {
        "id": "B5",
        "name": "wild_write",
        "tier": "easy",
        "signal": "SIGSEGV",
        "func": "bug5_wild_write",
        "trigger": _inp(0x05, 0xC0),
        "why": "writes through (req[1] << 28) when req[1] >= 0x40",
    },
    {
        "id": "B6",
        "name": "magic_guard",
        "tier": "hard",
        # Arch-dependent, exactly like B1 is toolchain-dependent. Measured:
        # x86-64 gives SIGSEGV, mipsel gives SIGBUS -- 0xa5a5a5a4 lands in a
        # region MIPS reports as a bus error rather than a page fault.
        #
        # The general lesson, having now been caught twice: THE SIGNAL IS NOT A
        # PROPERTY OF THE BUG. It is a property of the architecture and the
        # toolchain. The durable identity of a planted bug is its faulting
        # function and its distinct PC; the signal is corroboration, not the
        # key. A manifest that keys on signal will mis-score every port.
        "signal": "SIGSEGV|SIGBUS",
        "func": "bug6_magic_guard",
        "trigger": _inp(0x06, ord("F"), ord("U"), ord("Z"), ord("Z")),
        "why": "guarded by req[1..4] == 'FUZZ'; 2^-32 for blind mutation",
    },
    {
        "id": "B7",
        "name": "two_condition",
        "tier": "hardest",
        "signal": "SIGBUS|SIGSEGV",
        "func": "bug7_two_condition",
        # req[1] == 0x5a and req[2..5] summing to 255
        "trigger": _inp(0x07, 0x5A, 0xFF, 0x00, 0x00, 0x00),
        "why": "two independent conditions; rewards preserved partial progress",
    },
]

SAFE_OPCODE = 0x00
SAFE_FUNCS = ("safe_path",)


def trigger_manifest():
    """id -> (sha256, len, hex head) for the inputs that MUST crash."""
    out = {}
    for b in BUGS:
        t = b["trigger"]
        out[b["id"]] = {
            "sha256": hashlib.sha256(t).hexdigest(),
            "len": len(t),
            "head_hex": t[:8].hex(),
        }
    return out


def score(found_funcs, saw_safe=False, note=""):
    """Grade a run.

    found_funcs: iterable of victim function names that crashed (resolved from
    the crash PCs -- NOT the opcodes we sent, because attributing a crash to the
    input we intended rather than to where it actually faulted is how a harness
    grades its own homework).

    Returns a dict with a verdict that distinguishes the three cases that matter:
    a working pipeline finding little, a broken pipeline, and a fabricating one.
    """
    found = set(found_funcs)
    by_id = {b["id"]: (b["func"] in found) for b in BUGS}

    canary = next(b for b in BUGS if b.get("role") == "canary")
    canary_hit = by_id[canary["id"]]
    n_found = sum(1 for v in by_id.values() if v)

    if saw_safe:
        verdict = ("INVALID: the negative control faulted. Opcode 0x00 cannot "
                   "crash, so the harness is producing crashes that the victim "
                   "did not. No finding in this run can be believed.")
    elif not canary_hit:
        verdict = ("HARNESS BROKEN: the canary (B1, reachable by almost any "
                   "input) was not found. This is a plumbing failure -- "
                   "injection, detection or attribution -- not evidence that "
                   "the target is robust.")
    else:
        tiers = {}
        for b in BUGS:
            tiers.setdefault(b["tier"], [0, 0])
            tiers[b["tier"]][1] += 1
            if by_id[b["id"]]:
                tiers[b["tier"]][0] += 1
        verdict = "VALID: %d/%d bugs found (%s)" % (
            n_found, len(BUGS),
            ", ".join("%s %d/%d" % (t, v[0], v[1]) for t, v in tiers.items()))

    return {
        "verdict": verdict,
        "found": n_found,
        "total": len(BUGS),
        "by_id": by_id,
        "canary_hit": canary_hit,
        "negative_control_violated": bool(saw_safe),
        "note": note,
    }


if __name__ == "__main__":
    import json
    print(json.dumps({
        "bugs": [{k: (v.hex() if isinstance(v, bytes) else v)
                  for k, v in b.items()} for b in BUGS],
        "triggers": trigger_manifest(),
    }, indent=2))
