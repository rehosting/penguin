# Written before run 120's results were read

Run 119 (corpus on) completed 12,000 laps at **108 laps/s wall** against runs
116/118 (corpus off, otherwise identical) at **33**. Its JSON was lost, so
there is no result from it -- but the wall rate is in the log and it is 3.3x
outside the 23.4-33.1 spread of the three corpus-off runs. Before reading run
120, here is what I think that is, and what would falsify it.

## Ruled out already

- **The arm.** All four runs armed on the cheap mode: probe lap 3.31, 3.48,
  3.58, 3.33 ms. The armed span is comparable.
- **A degraded guest looping fast.** `DEVICE SCOPE TOO NARROW` (a virtio-net
  section outside the device block) fires on every one of these runs and fired
  FEWER times in run 119: 23, against 75/42/102. Pre-existing, and pointing
  the wrong way to explain a speedup.
- **Verify laps.** `verify_every: 100` puts ~120 oracle laps in a run at
  ~48 ms each, about 6 s. The gap being explained is ~250 s.

## The hypothesis

The probe-lap rate is ~290 laps/s in every run; the wall rate is 11% of that
with the corpus off and 36% with it on. The difference is how many laps were
EXPENSIVE, and on this target an expensive lap is one whose replayed span
contains a connection boundary -- a guest fork+exec worth ~1050 ms.

Connections die when a mutated request makes lighttpd hang up. Corpus entries
are inputs that *produced new coverage*, which means the victim processed
them, which makes them likelier to be answerable than a random mutant. So the
corpus should kill fewer connections, the guest should reconnect less, and
fewer laps should straddle a boundary.

## What would confirm it, and what would kill it

`n_accept` in snapfeed.json counts connections established. Run 116 (corpus
off): **146**.

- **Confirms:** run 120's `n_accept` is materially below 146, and its wall
  rate is well above 33 laps/s.
- **Kills it:** `n_accept` is at or above 146 while the run is still fast. The
  speedup is then something else and this explanation is wrong, whatever the
  rate says.
- **Leaves it open:** run 120 comes back near 33 laps/s. Run 119 was then an
  outlier for a reason not yet identified -- most likely host load, which I
  cannot reconstruct retroactively -- and one fast run proves nothing.

**A faster run is not the result this experiment is for.** The result is
`corpus_lift`, which is measured inside one run and does not depend on any of
this. Throughput is a side effect, it is confounded by the draw, and a single
pair of runs cannot settle it. It is written down here because it was noticed
before the data was read, and because "the corpus made it 3x faster" is
exactly the kind of claim this lane has previously made and had to retract.

---

# Outcome: the prediction was wrong (run 120)

**`n_accept` = 148**, against 146 on both corpus-off runs. Not materially
fewer — indistinguishable. And run 120 was still fast: **126 laps/s wall**
against 33. That is the case written above as *"Kills it: `n_accept` is at or
above 146 while the run is still fast."*

So the connection-death explanation is dead. Corpus entries do not keep the
connection alive more often, and the wall-rate gap is something else.

What is left, neither confirmed:

- **Outlier laps.** Runs 116/118 had 15 and 14 laps over twice the median edge
  count; run 120 had **3**. Those are the expensive replays. But 12 extra laps
  at ~1050 ms is ~13 s, and the gap is ~250 s, so this is at most a tenth of
  it.
- **Host load.** Runs 116–118 ran in a previous session; 119 and 120 ran on an
  otherwise idle machine. Runs 116 and 118 agree closely (33.1, 33.0) while
  117 was 23.4 — so ~30% wall variance exists within one session, and 3.8x
  across sessions is more likely environmental than causal. This cannot be
  reconstructed retroactively.

**The wall-rate difference is unexplained and is not attributed to the
corpus.** `keepalive_fixed` did halve (1725 → 886), which is expected and
mechanical — corpus entries are stored after `_keep_alive` has already run, so
mutating one starts from a keepalive-clean base — but with `n_accept` flat it
explains no connection deaths and therefore no time.

Recording this rather than quietly dropping it: the hypothesis was specific,
it named its own falsifier, and the falsifier fired.
