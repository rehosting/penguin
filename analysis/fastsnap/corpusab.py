#!/usr/bin/env python3
"""Judge a coverage-guided corpus run, by criteria fixed before the data.

WHY THIS IS A SCRIPT AND NOT A LOOK AT THE JSON. This lane has twice read a
result the way it hoped to -- once quoting a confounded cumulative total as
validation, once ranking three runs on a metric that was noise. Both were
caught afterwards. Writing the decision rule down first is cheaper than
catching it afterwards a third time, and a rule in a file can be shown to have
predated the run it judges.

    python3 corpusab.py <result-dir> [<baseline-result-dir>]

THE PRIMARY TEST IS IN-RUN, and the baseline is optional on purpose. Two runs
of this config draw different spans, and that difference has swamped real
effects here before (runs 109-112, where two controls differed 23%). So the
headline is corpus_lift: new edges per corpus-derived input divided by new
edges per seed-derived input, both measured inside the SAME run, on one
snapshot, from one draw.

  lift > 1  inputs descended from a discovery find more than inputs
            descended from a seed -- the corpus is guiding
  lift ~ 1  the corpus is collected, drawn from, and worth nothing
  lift < 1  the corpus is actively worse than the seeds, which is a real
            possible outcome: a corpus can drift into malformed requests the
            victim rejects early, and rejecting early is cheap coverage

WHAT WOULD MAKE THE NUMBER UNREADABLE, checked first and reported as refusals
rather than folded into the verdict:

  * no coverage attached to laps      -> nothing could ever be banked
  * corpus never drawn from           -> collected and ignored
  * corpus empty                      -> nothing to draw
  * one arm has no inputs             -> no ratio exists
  * many multi-fed laps               -> attribution was skipped often
                                         enough that the ratio rests on a
                                         minority of laps

ONE BIAS THAT IS NOT REFUSED, BECAUSE IT RUNS THE SAFE WAY. The corpus starts
empty, so the first laps of a run are necessarily seed-derived, and those are
the richest laps a run has -- discovery decays as the easy edges are taken.
Corpus-derived inputs therefore face a harder environment on average than seed
-derived ones, and the lift is pulled DOWN by it. The prefix is short (the
corpus takes its first entry within a few dozen laps and ~10% of laps
discover) so the effect should be small, but the direction matters: a lift
above 1 is trustworthy in spite of this, while a lift of ~1 is ambiguous
between "no effect" and "an effect this bias ate". Do not read a null result
here as strong evidence of no effect.
"""
import json
import pathlib
import sys

# Fixed before run 119. A lift inside this band is "no effect": the two arms
# differ by less than the run-to-run noise this lane has measured on per-lap
# coverage quantities (~5%), doubled for the fact that this is a ratio of two
# noisy things.
NULL_BAND = (0.90, 1.10)
# Above this share of discovery laps feeding more than one payload, the edge
# ratio rests on too few laps to lead with.
MULTI_FED_LIMIT = 0.10


def load(d):
    d = pathlib.Path(d)
    sf = json.load(open(d / "snapfeed.json"))
    fl = json.load(open(d / "fastloop.json"))
    return sf, fl


def judge(sf):
    """Return (verdict, [refusals]). Refusals mean the number is not readable,
    which is different from the number being bad."""
    refusals = []
    if not sf.get("corpus_on"):
        refusals.append("corpus was OFF in this run")
    if sf.get("cov_absent_laps", 0) > 50 and not sf.get("corpus_size"):
        refusals.append(
            f"{sf['cov_absent_laps']} laps arrived with no coverage -- this is "
            f"fastloop coverage:0, not a corpus that found nothing")
    if not sf.get("corpus_size"):
        refusals.append("the corpus stayed empty")
    if not sf.get("n_corpus_draw"):
        refusals.append("the corpus was never drawn from (corpus_p=0?)")
    if not sf.get("n_corpus_input"):
        refusals.append("no corpus-derived input ever landed in a lap that "
                        "could attribute")
    if not sf.get("n_seed_input"):
        refusals.append("no seed-derived inputs, so there is nothing to "
                        "compare the corpus against")

    lift = sf.get("corpus_lift")
    if lift is None:
        refusals.append("corpus_lift could not be computed")
        return None, refusals

    laps_new = sf.get("n_new_from_corpus", 0) + sf.get("n_new_from_seed", 0)
    multi = sf.get("n_multi_fed_laps", 0)
    if laps_new and multi / laps_new > MULTI_FED_LIMIT:
        refusals.append(
            f"{multi} of {laps_new} discovery laps fed more than one payload "
            f"({multi / laps_new:.1%}), so the edge ratio rests on the rest")

    if NULL_BAND[0] <= lift <= NULL_BAND[1]:
        verdict = (f"NO EFFECT: lift {lift} is inside the null band "
                   f"{NULL_BAND}. The corpus is collected and drawn from and "
                   f"changes nothing measurable.")
    elif lift > NULL_BAND[1]:
        verdict = (f"GUIDING: lift {lift}. A corpus-derived input finds "
                   f"{lift:.2f}x the new edges of a seed-derived one.")
    else:
        verdict = (f"WORSE THAN THE SEEDS: lift {lift}. Inputs descended from "
                   f"a discovery find LESS than inputs descended from a seed.")
    return verdict, refusals


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    sf, fl = load(sys.argv[1])
    cov = fl.get("coverage") or {}

    print(f"run {sys.argv[1]}")
    print(f"  corpus       on={sf.get('corpus_on')} size={sf.get('corpus_size')}"
          f"/{sf.get('corpus_max')} p={sf.get('corpus_p')}")
    print(f"  banked       add={sf.get('n_corpus_add')} "
          f"dup={sf.get('n_corpus_dup')} evict={sf.get('n_corpus_evict')} "
          f"boundary-rejected={sf.get('n_corpus_reject_boundary')}")
    print(f"  draws        corpus={sf.get('n_corpus_draw')} "
          f"seed={sf.get('n_seed_draw')}")
    print(f"  attributable corpus={sf.get('n_corpus_input')} "
          f"seed={sf.get('n_seed_input')}  "
          f"(multi-fed laps refused: {sf.get('n_multi_fed_laps')})")
    print(f"  discoveries  laps corpus={sf.get('n_new_from_corpus')} "
          f"seed={sf.get('n_new_from_seed')}   "
          f"edges corpus={sf.get('edges_from_corpus')} "
          f"seed={sf.get('edges_from_seed')}")
    if sf.get("n_corpus_input") and sf.get("n_seed_input"):
        print(f"  per input    corpus="
              f"{sf['edges_from_corpus'] / sf['n_corpus_input']:.4f} "
              f"seed={sf['edges_from_seed'] / sf['n_seed_input']:.4f} "
              f"new edges")
    print(f"  run          laps={cov.get('laps')} "
          f"new_edges_total={cov.get('new_edges_total')} "
          f"exec/s={fl.get('exec_per_s_median')}")

    verdict, refusals = judge(sf)
    print()
    for r in refusals:
        print(f"  REFUSED: {r}")
    if verdict:
        print(f"  {verdict}")

    if len(sys.argv) > 2:
        bsf, bfl = load(sys.argv[2])
        bcov = bfl.get("coverage") or {}
        print(f"\n  cross-run against {sys.argv[2]} -- THE WEAK HALF. Two runs "
              f"of this config draw different spans;")
        print(f"  read this only as corroboration of the in-run ratio above, "
              f"never instead of it.")
        print(f"    new_edges_total  {bcov.get('new_edges_total')} -> "
              f"{cov.get('new_edges_total')}")
        print(f"    exec/s           {bfl.get('exec_per_s_median')} -> "
              f"{fl.get('exec_per_s_median')}")
        print(f"    laps             {bcov.get('laps')} -> {cov.get('laps')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
