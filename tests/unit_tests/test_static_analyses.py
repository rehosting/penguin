import tempfile
import unittest
from pathlib import Path

from penguin.static_analyses import PseudofileFinder


class TestPseudofileFinder(unittest.TestCase):
    def test_does_not_model_proc_sys_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "cat /proc/sys\n"
                "cat /proc/sys/kernel/hostname\n"
                "cat /proc/vendor_knob\n"
            )

            result = PseudofileFinder().run(tmpdir, {})

        self.assertNotIn("/proc/sys", result["proc"])
        self.assertNotIn("/proc/sys/kernel/hostname", result["proc"])
        self.assertIn("/proc/vendor_knob", result["proc"])


if __name__ == "__main__":
    unittest.main()
