# Penguin unit tests
These directories contain stand-alone configs that we can realize without any rootfs to test failure detection and remediation. The `test.sh` script has logic for running each config
for armel/mips/mipsel and checking if the expected failures are reported correctly

Each config adds a shell script at `/init` that drives the guest to take some actions that should fail. Our dynamic analyses should detect these failures and propose mitigations.

Run after building the container with:

```sh
docker build -t rehosting/penguin ..
./test.sh
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
