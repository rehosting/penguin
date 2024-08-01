#!/usr/bin/env python3
import argparse
import logging
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("penguin.tests")

SCRIPT_PATH = Path(__file__).resolve().parent  # Script's directory
TEST_DIR = Path(f"{SCRIPT_PATH}/configs")
BASE_CONFIG = Path(f"{SCRIPT_PATH}/base_config.yaml")
DEFAULT_KERNELS = [
    "4.10",
    # "6.7"
]
DEFAULT_ARCHS = ["armel", "mipsel", "mipseb", "mips64eb", "aarch64"]


def assert_generic(filepath, patterns):
    """
    Does a file within the results directory contain a pattern?
    """

    def assert_func(results_dir):
        for pattern in patterns if isinstance(patterns, list) else [patterns]:
            if pattern not in (results_dir / Path(filepath)).read_text():
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
                for subkey in subkeys or []:
                    data_key = data_key[subkey]
                if assertion:
                    if assertion(data_key):
                        return True
                    print(f"FAILURE: assertion failed on {data_key} in {filepath}")
                    return False
                continue
            except KeyError:
                print(
                    f"FAILURE: key {data_key} not found in {filepath}"
                )  # May be nested
                return False
        return True

    return assert_func


def create_elf_file(filename, e_machine, e_flags, endian=">", word_size=32):
    # ELF Header fields
    # e_ident part: EI_MAG, EI_CLASS, EI_DATA, EI_VERSION, EI_OSABI, EI_ABIVERSION
    ei_mag = b"\x7fELF"  # Magic number
    ei_class = b"\x01" if word_size == 32 else b"\x02"  # 32-bit or 64-bit
    ei_data = (
        b"\x01" if endian == "<" else b"\x02"
    )  # Little-endian for <, big-endian for >
    ei_version = b"\x01"  # Original version of ELF
    ei_osabi = b"\x00"  # System V
    ei_abiversion = b"\x00"
    ei_pad = b"\x00" * 7

    # Common fields
    e_type = struct.pack(endian + "H", 0x02)  # Executable file
    e_machine = struct.pack(endian + "H", e_machine)  # Architecture type
    e_version = struct.pack(endian + "I", 0x01)  # ELF version
    e_flags = struct.pack(endian + "I", e_flags)  # Processor-specific flags

    if word_size == 32:
        e_entry = struct.pack(endian + "I", 0x00)  # Entry point virtual address
        e_phoff = struct.pack(endian + "I", 0x00)  # Program header table file offset
        e_shoff = struct.pack(endian + "I", 0x00)  # Section header table file offset
        e_ehsize = struct.pack(
            endian + "H", 0x34
        )  # ELF header size (52 bytes for 32-bit)
        e_phentsize = struct.pack(endian + "H", 0x20)  # Program header table entry size
        e_shentsize = struct.pack(endian + "H", 0x28)  # Section header table entry size
    else:
        e_entry = struct.pack(
            endian + "Q", 0x00
        )  # Entry point virtual address (64-bit)
        e_phoff = struct.pack(
            endian + "Q", 0x00
        )  # Program header table file offset (64-bit)
        e_shoff = struct.pack(
            endian + "Q", 0x00
        )  # Section header table file offset (64-bit)
        e_ehsize = struct.pack(
            endian + "H", 0x40
        )  # ELF header size (64 bytes for 64-bit)
        e_phentsize = struct.pack(
            endian + "H", 0x38
        )  # Program header table entry size (64-bit)
        e_shentsize = struct.pack(
            endian + "H", 0x40
        )  # Section header table entry size (64-bit)

    e_phnum = struct.pack(endian + "H", 0x00)  # Program header table entry count
    e_shnum = struct.pack(endian + "H", 0x00)  # Section header table entry count
    e_shstrndx = struct.pack(endian + "H", 0x00)  # Section header string table index

    # Assemble the complete ELF header
    header = (
        ei_mag
        + ei_class
        + ei_data
        + ei_version
        + ei_osabi
        + ei_abiversion
        + ei_pad
        + e_type
        + e_machine
        + e_version
        + e_entry
        + e_phoff
        + e_shoff
        + e_flags
        + e_ehsize
        + e_phentsize
        + e_phnum
        + e_shentsize
        + e_shnum
        + e_shstrndx
    )

    # Write to file
    with open(filename, "wb") as f:
        f.write(header)


class TestRunner:
    def __init__(self, kernel_versions, archs, tests, checks):
        self.kernel_versions = kernel_versions
        self.archs = archs
        self.tests = tests
        self.checks = checks
        # self.qcows_dir = SCRIPT_PATH / Path("qcows") # TODO: can we cache these across projects?
        # self.qcows_dir.mkdir(exist_ok=True)

    def _make_project(self, test_name, kernel_version, arch, proj_dir):
        # First we need to create a tar archive for the rootfs with "./bin/busybox" of
        # the target arch (note it won't be the real binary), we'll use create_elf_file
        e_machine = 0x08
        if arch == "armel":
            e_machine = 0x28
        elif arch == "aarch64":
            e_machine = 0xB7
        kwargs = {
            "e_machine": e_machine,
            "endian": ">" if arch in ["mipseb", "mips64eb"] else "<",
            "word_size": 64 if arch in ["aarch64", "mips64eb"] else 32,
            # Use o32 ABI to prevent detecting as 64-bit
            "e_flags": 0x00001000 if arch in ("mipsel", "mipseb") else 0,
        }

        if "64" in arch and kwargs["word_size"] == 32:
            logger.warning(
                f"Architecture {arch} looks like 64-bits but word size is 32-bit"
            )

        if "eb" in arch and kwargs["endian"] == "<":
            logger.warning(
                f"Architecture {arch} looks like big-endian but little-endian specified"
            )

        # Create tar archive with the ELF file at /bin/busybox
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            os.makedirs(tmp / Path("fs/bin"))
            create_elf_file(tmp / "fs/bin/busybox", **kwargs)
            subprocess.run(
                ["tar", "-C", tmp / "fs", "-czf", f"{tmpdir}/rootfs.tar.gz", "."]
            )

            # Now we have a "rootfs" to import
            # Run penguin script (up 2 directories) to initialize
            subprocess.run(
                [
                    os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                    "init",
                    f"{tmpdir}/rootfs.tar.gz",
                    "--output",
                    f"{proj_dir}",
                ],
                check=True,
            )

        assert os.path.isfile(
            f"{proj_dir}/config.yaml"
        ), f"config.yaml not found in generated {proj_dir}"

    def _patch_config(self, test_name, proj_dir):
        # TODO: consider setting kernel version here if we add multiple kernel versions
        test_path = TEST_DIR / Path(test_name + ".yaml")
        if not test_path.is_file():
            raise ValueError(f"Test {test_name} does not exist")

        subprocess.run(
            [
                os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                "patch",
                f"{proj_dir}/config.yaml",
                TEST_DIR / Path(test_name + ".yaml"),
            ],
            check=True,
        )

    def _run_config(self, kernel_version, arch, test_name, proj_dir):
        logger.info(
            f"Testing {test_name} on kernel version {kernel_version} with architecture {arch}..."
        )
        try:
            subprocess.run(
                [
                    os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                    "run",
                    f"{proj_dir}/config.yaml",
                    "--output",
                    f"{proj_dir}/output",
                ],
                check=True,
                stdout=open(proj_dir / Path("test_log.txt"), "w"),
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError:
            logger.error("Penguin run failed, showing last 50 lines from log:")
            subprocess.run(["tail", "-n", "50", proj_dir / Path("test_log.txt")])
            sys.exit(1)

    def run_test(self, kernel_version, arch, test_name, assertion):
        # Create a project directory for this test
        proj_dir = (
            SCRIPT_PATH / Path("results") / Path(f"{test_name}_{kernel_version}_{arch}")
        )
        if proj_dir.exists():
            subprocess.run(["rm", "-rf", proj_dir])

        self._make_project(test_name, kernel_version, arch, proj_dir)
        self._patch_config(test_name, proj_dir)
        # Sanity check. Config arch should match our arch
        # Read generated config.yaml
        with open(proj_dir / Path("config.yaml"), "r") as f:
            config = yaml.safe_load(f)
            if config["core"]["arch"] != arch:
                logger.error(
                    f"Generated config arch {config['core']['arch']} does not match requested arch {arch}"
                )
                return False

        self._run_config(kernel_version, arch, test_name, proj_dir)

        if not self._check_results(test_name, proj_dir / Path("output"), assertion):
            logger.error(
                f"Test {test_name} failed on kernel version {kernel_version} with architecture {arch}"
            )
            return False
        return True

    def _check_results(self, test_name, outdir, assertion):
        if assertion(outdir):
            logger.info(f"{test_name}: PASS")
            return True
        else:
            logger.info(f"{test_name}: FAIL: invalid results")
            subprocess.run(["tail", "-n30", outdir.parent / Path("test_log.txt")])
            subprocess.run(["tail", "-n30", outdir / Path("console.log")])
        return False

    def run_all(self):
        num_fails = 0
        for kernel_version in self.kernel_versions:
            for arch in self.archs:
                for test_name in self.tests:
                    if not self.run_test(
                        kernel_version, arch, test_name, self.checks[test_name]
                    ):
                        num_fails += 1
        if num_fails:
            logger.error(f"{num_fails} tests failed")
            sys.exit(1)


def main():
    tests_to_checks = {
        "env_unset": assert_generic(
            "shell_env.csv", ["('var2', None)", "('anothervar', None)"]
        ),
        "env_cmp": assert_generic("env_cmp.txt", ["firsttarget", "secondtarget"]),
        "pseudofile_missing": assert_generic(
            "pseudofiles_failures.yaml",
            [
                "/dev/missing",
                "/dev/net/missing",
                "/dev/foo/missing",
                "/proc/missing",
                "/proc/fs/missing",
                "/proc/foo/missing",
                "/sys/missing",
                "/sys/fs/missing",
                "/sys/foo/missing",
            ],
        ),
        "pseudofile_ioctl": assert_yaml(
            "pseudofiles_failures.yaml",
            [
                ["/dev/missing", "ioctl", 799, "count"],
                ["/dev/fs/missing", "ioctl", 799, "count"],
                ["/dev/foo/missing", "ioctl", 799, "count"],
            ],
            lambda x: x > 0,
        ),
        "hostfile": assert_generic("console.log", "tests pass"),
        # shared directory isn't in proj/output, it's in proj itself. So go up
        "shared_dir": assert_generic(
            "../host_shared/from_guest.txt", "Hello from guest"
        ),
        "net_missing": assert_generic("iface.log", ["eth0", "ens3"]),
        "netdevs": assert_generic("console.log", "tests pass"),
        "proc_self": assert_generic("console.log", "tests pass"),
        "pseudofile_readdir": assert_generic("console.log", "tests pass"),
        "pseudofile_mmap_shared": assert_generic("console.log", "tests pass"),
        "bash": assert_generic(
            "bash_cov.csv",
            [
                '/init,5,1,"echo ""Hello from $0 $@"""',
                "/init,6,1,for x in a b c d",
                "/init,7,1,echo $x",
            ],
        ),
        "proc_mtd_dynamic": assert_generic("env_mtd.txt", "flash"),
        "proc_mtd_missing": assert_generic("pseudofiles_proc_mtd.txt", "read"),
        "proc_mtd": assert_generic("console.log", "All good"),
        "pseudofile_devfs": assert_generic("console.log", "[bioset]"),
        "pseudofile_sysfs": assert_generic("console.log", "[bioset]"),
        "uboot_env_cmp": assert_generic("env_cmp.txt", "target"),
    }

    # Ensure test configs stay in sync with this script
    ignored_tests = set(os.listdir(TEST_DIR)) - set(
        f"{test}.yaml" for test in tests_to_checks.keys()
    )
    assert ignored_tests == set(), f"Tests ignored: {ignored_tests}"

    # Ensure this script stays in sync with the CI script
    with open(TEST_DIR / "../../../.github/workflows/build.yaml") as f:
        ci_yaml = yaml.safe_load(f)
    ci_yaml_matrix = ci_yaml["jobs"]["run_tests"]["strategy"]["matrix"]
    ignored_tests = set(tests_to_checks.keys()) - set(ci_yaml_matrix["test"])
    assert ignored_tests == set(), f"Tests not run in CI: {ignored_tests}"
    ignored_archs = set(DEFAULT_ARCHS) - set(ci_yaml_matrix["arch"])
    assert ignored_archs == set(), f"Archs not tested in CI: {ignored_archs}"
    ignored_kernels = set(DEFAULT_KERNELS) - set(ci_yaml_matrix["kernel"])
    assert ignored_kernels == set(), f"Kernels not tested in CI: {ignored_kernels}"

    parser = argparse.ArgumentParser(description="Run PENGUIN unit tests.")
    parser.add_argument(
        "--kernel-version",
        nargs="*",
        help=f'Kernel version(s) to test. Default: {", ".join(DEFAULT_KERNELS)}',
        default=DEFAULT_KERNELS,
    )
    parser.add_argument(
        "--arch",
        nargs="*",
        help=f'Architecture(s) to test. Default: {", ".join(DEFAULT_ARCHS)}',
        default=DEFAULT_ARCHS,
    )
    parser.add_argument(
        "--test",
        nargs="*",
        help=f'Specific test(s) to run. Default: {", ".join(list(tests_to_checks.keys()))}',
    )
    args = parser.parse_args()

    kernel_versions = args.kernel_version
    if kernel_versions != ["4.10"]:
        # TODO: when we support multiple kernel versions, support testing each.
        # Will need to update how we generate configs to support this.
        raise ValueError("Only kernel version 4.10 is supported at this time.")

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

    runner = TestRunner(
        kernel_versions, archs, tests, {test: tests_to_checks[test] for test in tests}
    )
    runner.run_all()


if __name__ == "__main__":
    main()
