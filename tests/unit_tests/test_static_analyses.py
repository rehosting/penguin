import tempfile
import unittest
from pathlib import Path

from penguin.static_analyses import PseudofileFinder


class TestPseudofileFinder(unittest.TestCase):
    def test_does_not_model_proc_sys_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "cat /proc/sys\n"
                "cat /proc/sys/\n"
                "cat /proc/sys/kernel/hostname\n"
                "cat /proc/vendor_knob\n"
            )

            result = PseudofileFinder().run(tmpdir, {})

        self.assertNotIn("/proc/sys", result["proc"])
        self.assertNotIn("/proc/sys/kernel/hostname", result["proc"])
        self.assertIn("/proc/vendor_knob", result["proc"])

    def test_does_not_model_static_dev_convenience_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "ls /dev/pts/\n"
                "ls /dev/fd/\n"
                "ls /dev/shm/\n"
                "cat /dev/vendor_knob\n"
            )

            result = PseudofileFinder().run(tmpdir, {})

        self.assertNotIn("/dev/pts", result["dev"])
        self.assertNotIn("/dev/pts/.placeholder", result["dev"])
        self.assertNotIn("/dev/fd", result["dev"])
        self.assertNotIn("/dev/fd/.placeholder", result["dev"])
        self.assertNotIn("/dev/shm", result["dev"])
        self.assertIn("/dev/vendor_knob", result["dev"])


if __name__ == "__main__":
    unittest.main()
