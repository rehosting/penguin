"""
This plugin verifies that shared directory setup works correctly.
"""

from penguin import Plugin
from os.path import join

HYPERCALL_MAGIC = 0xc1c10dcd

class SharedDirTest(Plugin):
    def __init__(self):
        self.shared_dir = self.get_arg("shared_dir")
        self.panda.hypercall(HYPERCALL_MAGIC)(self.hypercall_test)
        with open(join(self.shared_dir, "hypercall_test.txt"), "w") as f:
            f.write("Hypercall test file created successfully.\n")
    
    def hypercall_test(self, cpu):
        with open(join(self.shared_dir, "test_out.txt"), "w") as f:
            f.write("Hypercall copy completed\n"*1000000)
