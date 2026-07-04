# Guest-boot integration fixtures (`tests/integration/`)

These directories boot a real guest under PANDA-QEMU (per arch) and assert on
what the run produces. They are the slow integration gate — run in CI by the
`run_tests` (per-arch matrix) and `run_compose` jobs of
`.github/workflows/build.yaml`. The fast, host-side unit suite lives in
`tests/unit/`.

- `test_target/` — boots a guest per arch and runs the `patches/tests/*.yaml`
  fixtures; pass/fail is decided by a guest-side `verifier` plugin emitting
  JUnit `verifier.xml`.
- `basic_target/` — smoke test: `init`/`refresh`/boot, C drop-in + lib_inject
  markers (plus the `snapshot_*_test.py` save/restore/VPN tests).
- `compose/` — two-guest network end-to-end test (arch-independent).

These contain stand-alone configs realized without a rootfs, to test failure
detection and remediation. Each config adds a shell script at `/init` that
drives the guest to take actions that should fail; the dynamic analyses should
detect them and propose mitigations.

Run after building the container:

```sh
docker build -t rehosting/penguin ..
python3 test_target/test.py --arch armel      # or basic_target/, compose/
```

# Working tests

## EnvUnset
* Shell script tries accessing `envvar` variable that's unset
* Busybox instrumentation should detect this access
* XXX: we also want to be able to detect direct accesses to /proc/cmdline but that's harder

## EnvCmp
* Guest compares the value of `envvar` to a constant `"target"`
* The config sets envvar to DYNVALDYNVALDYNVAL (i.e., we had already identified it as a variable to solve for)
* Expected results: `env_cmp.txt` in output directory contains `target`

## PseudofileMissing
* Guest attempts to access /dev/missing which doesn't exist
* Expected results: `pseudofiles_failures.yaml` contains a key of `/dev/missing` with a nonzero count for a `stat`-like syscall

## PseudofileIoctl
* Guest issues an IOCTL on /dev/missing which has no ioctl model (using busybox hdparm utility)
* Expected results: `pseudofiles_failures` contains a key of `/dev/missing` with an `ioctl` entry that has a key of `799` with a non-zero count.
