#!/usr/bin/env python3
import argparse
import logging
import re
import subprocess
import sys
import tempfile
import yaml
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SCRIPT_PATH=Path(__file__).resolve().parent # Script's directory
TEST_DIR=Path(f"{SCRIPT_PATH}/configs")
BASE_CONFIG=Path(f"{SCRIPT_PATH}/base_config.yaml")
DEFAULT_KERNELS = ["4.10",
                    #"6.7"
                   ]
DEFAULT_ARCHS = ["armel", "mipsel", "mipseb"]

def assert_generic(filepath, patterns):
    '''
    Does a file within the results directory contain a pattern?
    '''
    def assert_func(results_dir):
        for pattern in patterns if isinstance(patterns, list) else [patterns]:
            if not re.search(pattern, (results_dir / Path(filepath)).read_text()):
                print(f"FAILURE: Pattern {pattern} not found in {filepath}")
                return False
        return True
    return assert_func

def assert_yaml(filepath, subkeys_l, assertion=None):
    def assert_func(results_dir):
        data = yaml.safe_load((results_dir / Path(filepath)).open())
        for subkeys in subkeys_l:
            try:
                data_key = data
                for subkey in (subkeys or []):
                    data_key = data_key[subkey]
                if assertion:
                    if assertion(data_key):
                        return True
                    print(f"FAILURE: assertion failed on {key} in {filepath}")
                    return False
                continue
            except KeyError:
                print(f"FAILURE: key {key} not found in {filepath}") # May be nested
                return False
        return True
    return assert_func

class TestRunner:
    def __init__(self, kernel_versions, archs, tests, checks):
        self.kernel_versions = kernel_versions
        self.archs = archs
        self.tests = tests
        self.checks = checks
        self.qcows_dir = SCRIPT_PATH / Path("qcows")
        self.qcows_dir.mkdir(exist_ok=True)

    def run_test(self, kernel_version, arch, test_name, assertion):
        # Create a scratch directory + results dir in it
        with tempfile.TemporaryDirectory() as tmpdir:
            self._generate_config(test_name, kernel_version, arch, tmpdir)
            self._run_test(kernel_version, arch, test_name, tmpdir)

            # Backup output from the run (not the full tmpdir, just output)
            output_dir = SCRIPT_PATH / Path("results") / Path(f"{test_name}_{kernel_version}_{arch}")
            # Replace the output directory if it already exists
            if output_dir.exists():
                subprocess.run(["rm", "-rf", output_dir])
            output_dir.mkdir(exist_ok=True, parents=True)
            subprocess.run(["mv", f"{tmpdir}/output", output_dir])
            subprocess.run(["mv", f"{tmpdir}/config.yaml", output_dir])
            subprocess.run(["mv", f"{tmpdir}/test_log.txt", output_dir])
            if not self._check_results(test_name, output_dir / Path("output"), assertion):
                logging.error(f"Test {test_name} failed on kernel version {kernel_version} with architecture {arch}")
                return False
        return True

    def _generate_config(self, test_name, kernel_version, arch, tmpdir):
        if not (test_path := (TEST_DIR / Path(test_name + ".yaml"))).is_file():
            raise ValueError(f"Test {test_name} does not exist")

        test_data = yaml.safe_load(test_path.open())

        with open(BASE_CONFIG, "r") as f:
            base_data = f.read()
            base_data = base_data.replace("@KERNEL_VERSION@", kernel_version)
            base_data = base_data.replace("@ARCH@", arch)
            if arch == "armel":
                base_data = base_data.replace("vmlinux", "zImage")
        base_config = yaml.safe_load(base_data)

        # For each key in test_data, update base_config - note it's a dict so we need to
        # go through each key and update the base_config
        for key in test_data:
            if key in base_config:
                base_config[key].update(test_data[key])
            else:
                base_config[key] = test_data[key]

        # Write the updated base_config to a file in the tmpdir
        with open(tmpdir / Path("config.yaml"), "w") as f:
            yaml.dump(base_config, f)

    def _run_test(self, kernel_version, arch, test_name, tmpdir):
        logging.info(f"Testing {test_name} on kernel version {kernel_version} with architecture {arch}...")
        try:
            subprocess.run([
                "docker", "run", "--rm", "-v", f"{SCRIPT_PATH}:/tests",
                "-v", f"{tmpdir}:{tmpdir}",
                "rehosting/penguin", "/tests/_in_container_run.sh", tmpdir, arch
            ],
            check=True,
            stdout=open(tmpdir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            logging.error("Docker run failed, showing last 30 lines from log:")
            subprocess.run(["tail", "-n", "30", tmpdir / Path("test_log.txt")])
            sys.exit(1)

    def _check_results(self, test_name, outdir, assertion):
        if assertion(outdir):
            logging.info(f"{test_name}: PASS")
            return True
        else:
            logging.info(f"{test_name}: FAIL: invalid results")
            subprocess.run(["tail", "-n30", outdir.parent / Path("test_log.txt")])
            subprocess.run(["tail", "-n30", outdir / Path("console.log")])
        return False

    def run_all(self):
        num_fails = 0
        for kernel_version in self.kernel_versions:
            for arch in self.archs:
                for test_name in self.tests:
                    if not self.run_test(kernel_version, arch, test_name, self.checks[test_name]):
                        num_fails += 1
        if num_fails:
            logging.error(f"{num_fails} tests failed")
            sys.exit(1)

def main():
    tests_to_checks = {
        "env_unset": assert_generic("shell_env.csv", [
            "('var2', None)",
            "('anothervar', None)"
        ]),
        "env_cmp": assert_generic("env_cmp.txt", [
            "firsttarget",
            # "secondtarget" # TODO: this is not found
        ]),
        "pseudofile_missing": assert_generic("pseudofiles_failures.yaml", [
            "/dev/missing",
            "/dev/net/missing",
            "/dev/foo/missing",
            "/proc/missing",
            "/proc/fs/missing",
            "/proc/foo/missing",
            "/sys/missing",
            "/sys/fs/missing",
            "/sys/foo/missing"
        ]),
        "pseudofile_ioctl": assert_yaml("pseudofiles_failures.yaml", [
                ["/dev/missing", "ioctl", 799, "count"],
                ["/dev/fs/missing",
                "ioctl", 799, "count"],
                ["/dev/foo/missing",
                "ioctl", 799, "count"],
            ],
            lambda x: x > 0),
        "hostfile": assert_generic("console.log", "tests pass"),
        "shared_dir": assert_generic("shared/from_guest.txt", "Hello from guest"),
    }

    parser = argparse.ArgumentParser(description="Run PENGUIN unit tests.")
    parser.add_argument('--kernel-version', nargs='*', help=f'Kernel version(s) to test. Default: {", ".join(DEFAULT_KERNELS)}', default=DEFAULT_KERNELS)
    parser.add_argument('--arch', nargs='*', help=f'Architecture(s) to test. Default: {", ".join(DEFAULT_ARCHS)}', default=DEFAULT_ARCHS)
    parser.add_argument('--test', nargs='*', help=f'Specific test(s) to run. Default: {", ".join(list(tests_to_checks.keys()))}')
    args = parser.parse_args()
    kernel_versions = args.kernel_version
    archs = args.arch

    # Load all tests if none are specified, else filter the requested tests.
    if args.test:
        tests = [test for test in args.test if test in tests_to_checks]
        if not tests:
            raise ValueError("None of the specified tests are recognized.")
        # Ensure that all requested tests are in the checks dictionary
        for test in tests:
            if test not in tests_to_checks:
                raise ValueError(f"Test {test} is not recognized.")
    else:
        tests = list(tests_to_checks.keys())


    runner = TestRunner(kernel_versions, archs, tests, {test: tests_to_checks[test] for test in tests})
    runner.run_all()

if __name__ == "__main__":
    main()