"""
Use this plugin for testing the results of a system run.
"""

from pandare2 import PyPlugin
from penguin import getColoredLogger
from os.path import join, exists
import yaml
from junit_xml import TestSuite, TestCase
import threading
import time


class Verifier(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.conditions = self.get_arg("conditions")
        self.logger = getColoredLogger("plugins.verifier")

        self.continuous_eval = self.get_arg("continuous_eval") or False

        if self.continuous_eval:
            self.logger.info("Continuous evaluation enabled")
            self.shutdown_event = threading.Event()
            self.eval_thread = threading.Thread(
                target=self.eval_thread,
            )
            self.eval_thread.start()

    def eval_thread(self):
        while True:
            if self.shutdown_event.is_set():
                return
            _, results = self.check_test_cases()
            if all(results.values()):
                self.logger.info("Verifier: ALL tests passed")
                self.shutdown_event.set()
                self.panda.end_analysis()
                return
            else:
                self.logger.debug(
                    "Some tests failed, waiting 10s before re-evaluating")
            time.sleep(10)

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
    
    def test_csv_contains(self, name, test_case):
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
        kind_f = join(testcase_outdir, kind)
        val = ""
        if exists(kind_f):
            val = open(kind_f).read()
        return val

    def check_test_cases(self):
        results = {}
        test_cases = []
        for name in self.conditions:
            test_type = self.conditions[name]["type"]
            test = getattr(self, f"test_{test_type}", None)
            if test is None:
                print(f"Verifier does not have test_{test_type}")
                continue
            test_passed = test(name, self.conditions[name])

            results[name] = test_passed
            tc = TestCase(
                name=name,
                stdout=self.get_test_case_output(name, "stdout"),
                stderr=self.get_test_case_output(name, "stderr"),
            )
            if not test_passed:
                tc.add_failure_info("Failed")
            test_cases.append(tc)
        return test_cases, results

    def uninit(self):
        if hasattr(self, "shutdown_event"):
            self.shutdown_event.set()
        self.logger.info("Running verifier")
        test_cases, results = self.check_test_cases()

        for tc in test_cases:
            GREEN = "\x1b[32m"
            RED = "\x1b[31m"
            END = "\x1b[0m"
            PASSED = f"{GREEN}passed{END}"
            FAILED = f"{RED}failed{END}"
            test_passed = results[tc.name]
            self.logger.info(
                f"Test {tc.name} {PASSED if test_passed else FAILED}")
            self.logger.info(f"STDOUT: {tc.stdout}")
            self.logger.info(f"STDERR: {tc.stderr}")

        ts = TestSuite("verifier", test_cases)
        with open(join(self.outdir, "verifier.xml"), "w") as f:
            TestSuite.to_file(f, [ts])
        self.logger.info(
            f"Verified output written to {join(self.outdir, 'verifier.xml')}")

        if all(results.values()):
            self.logger.info("Verifier: ALL tests passed")
