import os
import unittest
from unittest.mock import patch

from penguin.penguin_run import use_virtio_console


def _conf(mode="kvm", graphics=False):
    return {"core": {"execution_mode": mode, "graphics": graphics}}


AARCH64 = {"arch": "aarch64"}


class TestUseVirtioConsole(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("PENGUIN_VIRTIO_CONSOLE", None)

    def test_on_for_aarch64_kvm(self):
        self.assertTrue(use_virtio_console(_conf("kvm"), AARCH64))

    def test_off_for_aarch64_tcg(self):
        self.assertFalse(use_virtio_console(_conf("qemu"), AARCH64))

    def test_off_for_other_arches(self):
        for arch in ("arm", "x86_64", "mipsel"):
            self.assertFalse(use_virtio_console(_conf("kvm"), {"arch": arch}))

    def test_off_with_graphics(self):
        self.assertFalse(use_virtio_console(_conf("kvm", graphics=True), AARCH64))

    def test_env_forces(self):
        os.environ["PENGUIN_VIRTIO_CONSOLE"] = "0"
        self.assertFalse(use_virtio_console(_conf("kvm"), AARCH64))
        os.environ["PENGUIN_VIRTIO_CONSOLE"] = "1"
        self.assertTrue(use_virtio_console(_conf("qemu"), AARCH64))
        self.assertFalse(use_virtio_console(_conf("qemu"), {"arch": "arm"}))
