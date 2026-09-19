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
