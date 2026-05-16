import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add penguin src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

# Pre-mock gen_image.make_image and redirect functions
mock_make_image = MagicMock()
sys.modules["penguin.gen_image"] = MagicMock()
sys.modules["penguin.gen_image"].make_image = mock_make_image

from penguin.penguin_run import run_config  # noqa: E402


class TestKVMRunnerSelection(unittest.TestCase):
    @patch("penguin.penguin_run.Panda")
    @patch("penguin.penguin_run.KVMQemu")
    @patch("penguin.penguin_run.load_config")
    @patch("penguin.penguin_run.load_q_config")
    @patch("penguin.penguin_run.get_penguin_kernel_version")
    @patch("penguin.penguin_run.hash_image_inputs")
    @patch("penguin.penguin_run.os.path.isdir")
    @patch("penguin.penguin_run.os.path.isfile")
    @patch("penguin.penguin_run.os.path.getsize")
    @patch("penguin.penguin_run.os.makedirs")
    @patch("penguin.penguin_run.shutil.copy")
    @patch("penguin.penguin_run.shutil.rmtree")
    @patch("penguin.penguin_run.print_to_log")
    @patch("penguin.penguin_run.redirect_stdout_stderr")
    @patch("penguin.penguin_run.find_free_port")
    @patch("penguin.penguin_run.os.open")
    def test_selects_kvm(self, mock_open, mock_find_port, mock_redirect, mock_log, mock_rmtree,
                         mock_copy, mock_mkdir, mock_getsize, mock_isfile,
                         mock_isdir, mock_hash, mock_version, mock_qconfig,
                         mock_load_config, mock_kvmqemu, mock_panda):
        # Setup mocks to reach the selection logic
        mock_load_config.return_value = {
            "core": {"execution_mode": "kvm", "arch": "x86_64", "mem": "128M", "kernel": "/fake/kernel", "fs": "fake/fs", "smp": 1},
            "env": {"igloo_init": "/sbin/init"},
            "plugins": {}
        }
        mock_qconfig.return_value = {"arch": "x86_64", "qemu_machine": "pc", "kconf_group": "x86_64"}

        # Selective isfile mock to avoid lock loop
        def side_effect_isfile(path):
            if ".lock" in str(path):
                return False
            return True
        mock_isfile.side_effect = side_effect_isfile

        mock_getsize.return_value = 1024
        mock_isdir.return_value = True
        mock_version.return_value = (4, 10)
        mock_find_port.return_value = 4321

        qemu = MagicMock()
        qemu.panda_args = ["-append", "root=/dev/vda"]
        mock_kvmqemu.from_installation.return_value = qemu

        run_config("/fake/proj", "/fake/config.yaml", "/fake/out")

        mock_kvmqemu.from_installation.assert_called_once_with("kvm", "x86_64")
        self.assertFalse(mock_panda.called)

    @patch("penguin.penguin_run.Panda")
    @patch("penguin.penguin_run.KVMQemu")
    @patch("penguin.penguin_run.load_config")
    @patch("penguin.penguin_run.load_q_config")
    @patch("penguin.penguin_run.get_penguin_kernel_version")
    @patch("penguin.penguin_run.hash_image_inputs")
    @patch("penguin.penguin_run.os.path.isdir")
    @patch("penguin.penguin_run.os.path.isfile")
    @patch("penguin.penguin_run.os.path.getsize")
    @patch("penguin.penguin_run.os.makedirs")
    @patch("penguin.penguin_run.shutil.copy")
    @patch("penguin.penguin_run.shutil.rmtree")
    @patch("penguin.penguin_run.print_to_log")
    @patch("penguin.penguin_run.redirect_stdout_stderr")
    @patch("penguin.penguin_run.find_free_port")
    @patch("penguin.penguin_run.os.open")
    def test_selects_panda(self, mock_open, mock_find_port, mock_redirect, mock_log, mock_rmtree,
                           mock_copy, mock_mkdir, mock_getsize, mock_isfile,
                           mock_isdir, mock_hash, mock_version, mock_qconfig,
                           mock_load_config, mock_kvmqemu, mock_panda):
        mock_load_config.return_value = {
            "core": {"execution_mode": "panda", "arch": "x86_64", "mem": "128M", "kernel": "/fake/kernel", "fs": "fake/fs", "smp": 1},
            "env": {"igloo_init": "/sbin/init"},
            "plugins": {}
        }
        mock_qconfig.return_value = {"arch": "x86_64", "qemu_machine": "pc", "kconf_group": "x86_64"}

        def side_effect_isfile(path):
            if ".lock" in str(path):
                return False
            return True
        mock_isfile.side_effect = side_effect_isfile

        mock_getsize.return_value = 1024
        mock_isdir.return_value = True
        mock_version.return_value = (4, 10)
        mock_find_port.return_value = 4321

        mock_panda.return_value.panda_args = ["-append", "root=/dev/vda"]

        run_config("/fake/proj", "/fake/config.yaml", "/fake/out")

        self.assertTrue(mock_panda.called)
        self.assertFalse(mock_kvmqemu.from_installation.called)


if __name__ == "__main__":
    unittest.main()
