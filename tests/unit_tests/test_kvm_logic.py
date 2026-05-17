import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import cffi

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from penguin import plugins  # noqa: E402
from pyplugins.compat.qemu_compat import KVMArch, KVMQemu, MINIMAL_CDEF  # noqa: E402


class FakeHypercallPlugin:
    def __init__(self):
        self.handlers = {}

    def register(self, nr, func):
        self.handlers.setdefault(nr, []).append(func)

    def dispatch(self, cpu, nr, ret_ptr):
        if nr not in self.handlers:
            return 1
        for handler in self.handlers.get(nr, []):
            handler(cpu)
        ret_ptr[0] = 0
        return 0


@contextmanager
def fake_plugins_hypercall(hypercall):
    sentinel = object()
    original = plugins.__dict__.get("hypercall", sentinel)
    plugins.__dict__["hypercall"] = hypercall
    try:
        yield
    finally:
        if original is sentinel:
            del plugins.__dict__["hypercall"]
        else:
            plugins.__dict__["hypercall"] = original


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

    def _fake_memory_lib(self, memory: bytes):
        lib = self._fake_lib()

        def read_memory(cpu, addr, buf, length, is_write):
            if is_write:
                return -1
            data = memory[addr:addr + length]
            if len(data) != length:
                return -1
            cffi.FFI().memmove(buf, data, length)
            return 0

        lib.cpu_memory_rw_debug = read_memory
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
    def test_intel64_uses_x86_64_conventions(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "intel64", mode="system", header_path=str(self.header_path))

        self.assertEqual(qemu.arch_name, "x86_64")
        self.assertEqual(qemu.arch.get_arg(None, 1), 0)

    @patch.object(cffi.FFI, "dlopen")
    def test_hypercall_registration(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))
        hypercall = FakeHypercallPlugin()

        with fake_plugins_hypercall(hypercall):
            @qemu.hypercall(0x1337)
            def my_handler(cpu):
                return None

        self.assertIn(0x1337, hypercall.handlers)
        self.assertEqual(hypercall.handlers[0x1337][0], my_handler)

    @patch.object(cffi.FFI, "dlopen")
    def test_legacy_hypercall_binding(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))
        hypercall = FakeHypercallPlugin()
        qemu.bind_hypercall_plugin(hypercall)

        self.assertIs(qemu.hypercall_plugin, hypercall)
        self.assertIs(qemu.hypercall_handlers, hypercall.handlers)

    @patch.object(cffi.FFI, "dlopen")
    def test_dispatch_hypercall(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))
        hypercall = FakeHypercallPlugin()

        handler_called = False

        def my_handler(cpu):
            nonlocal handler_called
            handler_called = True

        with fake_plugins_hypercall(hypercall):
            qemu.hypercall(0x1337)(my_handler)

            ret_ptr = qemu.ffi.new("uint64_t *", 0)
            res = qemu._dispatch_hypercall(
                qemu.ffi.NULL, 0x1337, 1, 2, 3, 4, 5, 6, ret_ptr)

        self.assertTrue(handler_called)
        self.assertEqual(res, 0)
        self.assertEqual(ret_ptr[0], 0)
        self.assertEqual(qemu._current_nr, 0x1337)
        self.assertEqual(qemu._current_args, [1, 2, 3, 4, 5, 6])

    @patch.object(cffi.FFI, "dlopen")
    def test_unregistered_hypercall_falls_through(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))
        hypercall = FakeHypercallPlugin()

        with fake_plugins_hypercall(hypercall):
            ret_ptr = qemu.ffi.new("uint64_t *", 0)
            res = qemu._dispatch_hypercall(
                qemu.ffi.NULL, 0x4, 1, 2, 3, 4, 5, 6, ret_ptr)

        self.assertEqual(res, 1)
        self.assertEqual(ret_ptr[0], 0)

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

    @patch.object(cffi.FFI, "dlopen")
    def test_virtual_memory_read_ptrlist(self, mock_dlopen):
        ptrs = [0x1122334455667788, 0x8877665544332211, 0]
        memory = b"".join(ptr.to_bytes(8, "little") for ptr in ptrs)
        mock_dlopen.return_value = self._fake_memory_lib(memory)

        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))

        self.assertEqual(
            qemu.virtual_memory_read(qemu.ffi.NULL, 0, len(memory), fmt="ptrlist"),
            ptrs,
        )

        with self.assertRaises(ValueError):
            qemu.virtual_memory_read(qemu.ffi.NULL, 0, 1, fmt="ptrlist")


if __name__ == "__main__":
    unittest.main()
