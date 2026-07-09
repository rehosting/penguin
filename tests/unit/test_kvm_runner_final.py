"""Host-side tests for backend selection in ``penguin_run.run_config``.

We want confidence that the KVM path is wired correctly — the right execution
mode is chosen, the KVM QEMU installation is requested for the right arch, and
``-accel kvm`` lands in the launch args — *without* actually launching QEMU/KVM.

``run_config`` is one long function: it selects the backend and assembles the
QEMU argv, then (for qemu/kvm modes) does ``from apis.hypercall import
Hypercall``, which builds the Portal/``hyper.consts`` FFI-enum tables at import
and needs a live ``kffi`` backend that doesn't exist host-side. That import is
the boundary. Backend selection happens *before* it, so we drive the real
function through selection + argv assembly and stop deterministically at the
first post-selection integration point (``plugins.initialize``) via a sentinel
exception — never reaching the boundary.
"""
import contextlib
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add penguin src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../pyplugins")))

# gen_image pulls in image-build machinery irrelevant here; stub it before import.
sys.modules["penguin.gen_image"] = MagicMock()
sys.modules["penguin.gen_image"].make_image = MagicMock()

from penguin.penguin_run import run_config  # noqa: E402


class _StopAfterSelection(Exception):
    """Sentinel raised from plugins.initialize to halt run_config right after
    backend selection + argv assembly, before the apis.hypercall boundary."""


class TestKVMRunnerSelection(unittest.TestCase):
    def setUp(self):
        es = contextlib.ExitStack()
        self.addCleanup(es.close)

        def start(target, **kw):
            return es.enter_context(patch(target, **kw))

        self.mock_kvmqemu = start("compat.qemu_compat.KVMQemu")
        self.mock_load_config = start("penguin.penguin_run.load_config")
        self.mock_qconfig = start("penguin.penguin_run.load_q_config")
        start("penguin.penguin_run.get_penguin_kernel_version").return_value = (4, 10)
        start("penguin.penguin_run.hash_image_inputs")
        start("penguin.penguin_run.os.path.isdir").return_value = True
        # Every file "exists" except lockfiles (whose absence avoids a wait loop).
        start("penguin.penguin_run.os.path.isfile").side_effect = \
            lambda p: ".lock" not in str(p)
        start("penguin.penguin_run.os.path.getsize").return_value = 1024
        start("penguin.penguin_run.os.makedirs")
        start("penguin.penguin_run.shutil.copy")
        start("penguin.penguin_run.shutil.rmtree")
        start("penguin.penguin_run.print_to_log")
        start("penguin.penguin_run.redirect_stdout_stderr")
        start("penguin.penguin_run.find_free_port").return_value = 4321
        start("penguin.penguin_run.os.open")
        start("penguin.penguin_run._write_runtime_metadata")
        start("penguin.penguin_run._write_connect_script")
        start("penguin.penguin_run._write_root_shell_port")
        # Replace the plugin-manager singleton; initialize() is the first thing
        # run_config calls after backend selection, so it is our stop point.
        # Patch with new=<instance> (not new_callable): letting patch pick the
        # mock class would make it introspect the real singleton, whose custom
        # __getattr__ recurses without a live backend.
        self.mock_plugins = MagicMock()
        self.mock_plugins.initialize.side_effect = _StopAfterSelection
        start("penguin.penguin_run.plugins", new=self.mock_plugins)

    def _configure(self, execution_mode, arch="x86_64"):
        core = {"arch": arch, "mem": "128M", "kernel": "/fake/kernel",
                "fs": "fake/fs", "smp": 1}
        if execution_mode is not None:
            core["execution_mode"] = execution_mode
        self.mock_load_config.return_value = {
            "core": core, "env": {"igloo_init": "/sbin/init"}, "plugins": {}}
        self.mock_qconfig.return_value = {
            "arch": arch, "qemu_machine": "pc", "kconf_group": arch}
        qemu = MagicMock()
        qemu.panda_args = ["-append", "root=/dev/vda"]
        self.mock_kvmqemu.from_installation.return_value = qemu
        return qemu

    def _run(self):
        with self.assertRaises(_StopAfterSelection):
            run_config("/fake/proj", "/fake/config.yaml", "/fake/out")

    def test_selects_kvm_backend(self):
        qemu = self._configure("kvm")
        self._run()

        # The KVM QEMU installation is requested in kvm mode for the guest arch.
        self.mock_kvmqemu.from_installation.assert_called_once_with("kvm", "x86_64")
        # ...and `-accel kvm` is assembled into the launch argv.
        self.assertIn("-accel", qemu.panda_args)
        self.assertEqual(qemu.panda_args[qemu.panda_args.index("-accel") + 1], "kvm")
        self.assertIn("qemu-system-x86_64", qemu.panda_args)
        # We stopped exactly at the post-selection boundary, not before it.
        self.mock_plugins.initialize.assert_called_once()

    def test_selects_tcg_system_backend(self):
        qemu = self._configure("qemu")
        self._run()

        # qemu mode -> the "system" (TCG) installation, and no KVM acceleration.
        mode_arg = self.mock_kvmqemu.from_installation.call_args.args[0]
        self.assertEqual(mode_arg, "system")
        self.assertNotIn("-accel", qemu.panda_args)

    def test_defaults_to_qemu_when_mode_unset(self):
        qemu = self._configure(None)  # no core.execution_mode key
        self._run()

        self.assertEqual(self.mock_kvmqemu.from_installation.call_args.args[0], "system")
        self.assertNotIn("-accel", qemu.panda_args)

    def test_rejects_panda_mode(self):
        self._configure("panda")
        # panda mode is rejected before any backend is selected.
        with self.assertRaisesRegex(RuntimeError, "PANDA execution mode is no longer supported"):
            run_config("/fake/proj", "/fake/config.yaml", "/fake/out")
        self.assertFalse(self.mock_kvmqemu.from_installation.called)


if __name__ == "__main__":
    unittest.main()
