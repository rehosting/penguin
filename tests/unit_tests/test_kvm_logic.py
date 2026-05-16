import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import cffi

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from penguin.kvm_qemu import KVMArch, KVMQemu, MINIMAL_CDEF  # noqa: E402


class TestKVMQemu(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.lib_path = Path(self.tmpdir.name) / "libqemu-kvm-x86_64.so"
        self.header_path = Path(self.tmpdir.name) / "qemu_cffi_kvm_x86_64.h"
        self.lib_path.write_text("fake")
        self.header_path.write_text(MINIMAL_CDEF)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _fake_lib(self):
        lib = MagicMock()
        lib.set_kvm_penguin_hypercall_callback = MagicMock()
        lib.set_penguin_guest_hypercall_callback = MagicMock()
        lib.set_kvm_penguin_after_guest_init_callback = MagicMock()
        return lib

    @patch.object(cffi.FFI, "dlopen")
    def test_initialization(self, mock_dlopen):
        mock_lib = self._fake_lib()
        mock_dlopen.return_value = mock_lib

        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))

        mock_dlopen.assert_called_once()
        self.assertEqual(qemu.arch_name, "x86_64")
        self.assertEqual(qemu.mode, "kvm")
        self.assertIsInstance(qemu.arch, KVMArch)
        self.assertTrue(mock_lib.set_kvm_penguin_hypercall_callback.called)

    @patch.object(cffi.FFI, "dlopen")
    def test_hypercall_registration(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))

        @qemu.hypercall(0x1337)
        def my_handler(cpu):
            return None

        self.assertIn(0x1337, qemu.hypercall_handlers)
        self.assertEqual(qemu.hypercall_handlers[0x1337][0], my_handler)

    @patch.object(cffi.FFI, "dlopen")
    def test_dispatch_hypercall(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))

        handler_called = False

        def my_handler(cpu):
            nonlocal handler_called
            handler_called = True

        qemu.hypercall(0x1337)(my_handler)

        ret_ptr = qemu.ffi.new("uint64_t *", 0)
        res = qemu._dispatch_hypercall(qemu.ffi.NULL, 0x1337, 1, 2, 3, 4, 5, 6, ret_ptr)

        self.assertTrue(handler_called)
        self.assertEqual(res, 0)
        self.assertEqual(ret_ptr[0], 0)
        self.assertEqual(qemu._current_nr, 0x1337)
        self.assertEqual(qemu._current_args, [1, 2, 3, 4, 5, 6])

    @patch.object(cffi.FFI, "dlopen")
    def test_arch_get_arg(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))
        qemu._current_nr = 0x1234
        qemu._current_args = [10, 20, 30, 40, 50, 60]

        self.assertEqual(qemu.arch.get_arg(None, 0), 0x1234)
        self.assertEqual(qemu.arch.get_arg(None, 1), 10)
        self.assertEqual(qemu.arch.get_arg(None, 6), 60)

        with self.assertRaises(ValueError):
            qemu.arch.get_arg(None, 7)


if __name__ == "__main__":
    unittest.main()
