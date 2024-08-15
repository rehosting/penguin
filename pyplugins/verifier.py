"""
Use this plugin for testing the results of a system run.
"""

from pandare import PyPlugin
from penguin import getColoredLogger
from os.path import join, exists
import yaml
from junit_xml import TestSuite, TestCase


class Verifier(PyPlugin):
    def __init__(self, _panda):
        self.outdir = self.get_arg("outdir")
        self.conditions = self.get_arg("conditions")
        self.logger = getColoredLogger("plugins.verifier")

    def test_file_contains(self, name, test_case):
        f = join(self.outdir, test_case["file"])
        if not exists(f):
            self.logger.error(f"Test {name}: file not found at {f}")
            return False

        if "strings" in test_case:
            test_strs = test_case["strings"]
            with open(f, "r", encoding="latin-1") as f:
                f_text = f.read()
                return all([test_str in f_text for test_str in test_strs])
        elif "string" in test_case:
            test_str = test_case["string"]
            with open(f, "r", encoding="latin-1") as f:
                f_text = f.read()
                return test_str in f_text
        else:
            self.logger.error(f"Test {name}: No strings to test for")
            return False

    def test_yaml_contains(self, name, test_case):
        f = join(self.outdir, test_case["file"])
        if not exists(f):
            self.logger.error(f"Test {name}: Console log not found at {f}")
            return False

        data = yaml.safe_load(open(f, "r"))
        subkeys_l = test_case.get("subkeys", [])

        def check_subkeys(data, subkeys):
            if data == subkeys:
                return True
            if isinstance(subkeys, dict):
                for subkey in subkeys:
                    if subkey not in data:
                        return False
                    d = data[subkey]
                    if not check_subkeys(d, subkeys[subkey]):
                        self.logger.debug(
                            f"Test {name}: failed on condition {d} {subkeys[subkey]}"
                        )
                        return False
            else:
                self.logger.error(f"Test {name}: error in yaml subkeys")
                return False
            return True

        return check_subkeys(data, subkeys_l)

    def get_test_case_output(self, name, kind):
        if "+" in name:
            name = name.split("+")[0]
        testcase_outdir = join(self.outdir, f"shared/tests/{name}.sh/")
        val = open(join(testcase_outdir, kind)).read()
        return val

    def uninit(self):
        self.logger.info("Running verifier")
        self.results = {}
        test_cases = []
        for name in self.conditions:
            test_type = self.conditions[name]["type"]
            test = getattr(self, f"test_{test_type}", None)
            if test is None:
                print(f"Verifier does not have test_{test_type}")
                continue
            test_passed = test(name, self.conditions[name])
            self.logger.info(f"Test {name} {'passed' if test_passed else 'failed'}")
            self.results[name] = test_passed
            tc = TestCase(
                name=name,
                stdout=self.get_test_case_output(name, "stdout"),
                stderr=self.get_test_case_output(name, "stderr"),
            )
            if not test_passed:
                tc.add_failure_info("Failed")
            test_cases.append(tc)
        ts = TestSuite("verifier", test_cases)
        with open(join(self.outdir, "verifier.xml"), "w") as f:
            TestSuite.to_file(f, [ts])
        self.logger.info(f"Verified output written to {join(self.outdir, 'verifier.xml')}")
