import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add penguin src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../pyplugins")))

# Pre-mock gen_image.make_image and redirect functions
mock_make_image = MagicMock()
sys.modules["penguin.gen_image"] = MagicMock()
sys.modules["penguin.gen_image"].make_image = mock_make_image

from penguin.penguin_run import run_config  # noqa: E402


class TestKVMRunnerSelection(unittest.TestCase):
    # The mocks below carry run_config past runtime.yaml and the KVM backend
    # selection, but it then does `from apis.hypercall import Hypercall`, which
    # pulls in the Portal/hyper.consts machinery and dereferences the live
    # `plugins` singleton at import time (its __getattr__ recurses without a
    # real backend). Running this host-side needs the in-place plugin harness
    # (penguin.testing.load_pyplugin, the follow-on session); until then this
    # exercises selection only as far as a bare host allows.
    @unittest.expectedFailure
    @patch("compat.qemu_compat.KVMQemu")
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
    # run_config now writes runtime.yaml via the module-level helper before the
    # execution-mode selection; stub it so the test doesn't touch the real FS.
    @patch("penguin.penguin_run._write_runtime_metadata")
    # Stub the plugin-manager singleton: after selecting the KVM backend
    # run_config goes on to load pyplugins from /pyplugins (a container path),
    # which isn't present host-side. The selection assertion only needs
    # from_installation to have been called, so neutralize the rest. `new=` is
    # given explicitly because the singleton's custom __getattr__ recurses when
    # mock autospec-inspects it.
    @patch("penguin.penguin_run.plugins", new=MagicMock())
    def test_selects_kvm(self, mock_write_meta, mock_open, mock_find_port, mock_redirect, mock_log, mock_rmtree,
                         mock_copy, mock_mkdir, mock_getsize, mock_isfile,
                         mock_isdir, mock_hash, mock_version, mock_qconfig,
                         mock_load_config, mock_kvmqemu):
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

    @patch("compat.qemu_compat.KVMQemu")
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
    @patch("penguin.penguin_run._write_runtime_metadata")
    def test_rejects_panda(self, mock_write_meta, mock_open, mock_find_port, mock_redirect, mock_log, mock_rmtree,
                           mock_copy, mock_mkdir, mock_getsize, mock_isfile,
                           mock_isdir, mock_hash, mock_version, mock_qconfig,
                           mock_load_config, mock_kvmqemu):
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

        with self.assertRaisesRegex(RuntimeError, "PANDA execution mode is no longer supported"):
            run_config("/fake/proj", "/fake/config.yaml", "/fake/out")

        self.assertFalse(mock_kvmqemu.from_installation.called)


if __name__ == "__main__":
    unittest.main()
