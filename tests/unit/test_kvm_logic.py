import json
import os
import importlib.util
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

_hypercall_spec = importlib.util.spec_from_file_location(
    "penguin_test_hypercall",
    Path(__file__).resolve().parents[2] / "pyplugins" / "apis" / "hypercall.py",
)
_hypercall_module = importlib.util.module_from_spec(_hypercall_spec)
_hypercall_spec.loader.exec_module(_hypercall_module)
Hypercall = _hypercall_module.Hypercall

_qmp_spec = importlib.util.spec_from_file_location(
    "penguin_test_qmp",
    Path(__file__).resolve().parents[2] / "pyplugins" / "apis" / "qmp.py",
)
_qmp_module = importlib.util.module_from_spec(_qmp_spec)
_qmp_spec.loader.exec_module(_qmp_module)
Qmp = _qmp_module.Qmp


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


class FakeQemuCompat:
    def __init__(self):
        self.registered_hypercalls = []

    def register_guest_hypercall(self, nr):
        self.registered_hypercalls.append(nr)
        return True


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


@contextmanager
def fake_plugins_qmp(qmp):
    sentinel = object()
    original = plugins.__dict__.get("qmp", sentinel)
    plugins.__dict__["qmp"] = qmp
    try:
        yield
    finally:
        if original is sentinel:
            del plugins.__dict__["qmp"]
        else:
            plugins.__dict__["qmp"] = original


class TestHypercallRegistry(unittest.TestCase):
    def test_binding_registers_existing_hypercall_aliases(self):
        hypercall = Hypercall()
        hypercall.register(0xFFFFFFFF, lambda cpu: None)

        qemu = FakeQemuCompat()
        hypercall.bind_qemu_compat(qemu)

        self.assertIn(0xFFFFFFFF, qemu.registered_hypercalls)
        self.assertIn(-1, qemu.registered_hypercalls)

    def test_registering_after_bind_updates_qemu_filter(self):
        hypercall = Hypercall()
        qemu = FakeQemuCompat()
        hypercall.bind_qemu_compat(qemu)

        hypercall.register(0x1337, lambda cpu: None)

        self.assertIn(0x1337, qemu.registered_hypercalls)


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
            # The real callback crosses the C ABI, so cpu_memory_rw_debug now
            # receives addr/len as cffi CData (vaddr / size_t) rather than plain
            # ints; coerce before slicing.
            addr = int(addr)
            length = int(length)
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


class TestQmpCallback(unittest.TestCase):
    """Branch coverage for QemuCompat._dispatch_qmp (the QMP command hook).

    The compat layer only marshals: it decodes command/args, forwards to the
    bound Qmp plugin's dispatch(), and encodes the result. Registration and the
    name->handler map live in the Qmp plugin (see TestQmpRegistry). The
    end-to-end wiring (qemu's qmp_dispatch -> weak penguin_handle_qmp -> CFFI
    trampoline -> plugin) is exercised by tests/integration/qmp_hook/.
    """

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
        lib.set_penguin_qmp_callback = MagicMock()
        return lib

    def _make_qemu(self, mock_dlopen):
        mock_dlopen.return_value = self._fake_lib()
        qemu = KVMQemu(str(self.lib_path), "x86_64", header_path=str(self.header_path))

        # _dispatch_qmp writes result_ptr[0] = self.lib.strdup(payload). Model
        # strdup with a real cffi buffer and keep references alive so the test
        # can read the JSON back out (a MagicMock would return a Mock, not a
        # readable char*).
        self._strdup_bufs = []

        def fake_strdup(data):
            buf = qemu.ffi.new("char[]", data)
            self._strdup_bufs.append(buf)
            return buf

        qemu.lib.strdup = fake_strdup
        return qemu

    def _ptrs(self, qemu, command, args_json):
        command_ptr = qemu.ffi.new("char[]", command.encode())
        args_ptr = qemu.ffi.new("char[]", args_json.encode())
        result_ptr = qemu.ffi.new("char *[1]")
        # Hold refs so the input buffers aren't GC'd during the call.
        self._input_bufs = (command_ptr, args_ptr)
        return command_ptr, args_ptr, result_ptr

    @patch.object(cffi.FFI, "dlopen")
    def test_install_qmp_dispatch_installs_callback(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qemu.install_qmp_dispatch(qmp)
        self.assertIs(qemu._bound_qmp_plugin, qmp)
        self.assertTrue(qemu.lib.set_penguin_qmp_callback.called)

    @patch.object(cffi.FFI, "dlopen")
    def test_bind_without_commands_does_not_install(self, mock_dlopen):
        # Lazy: binding a Qmp plugin that has no commands registered must not
        # touch the QEMU callback.
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qmp.bind_qemu_compat(qemu)
        self.assertIn(qemu, qmp.qemu_compats)
        self.assertFalse(qemu.lib.set_penguin_qmp_callback.called)
        self.assertIsNone(qemu._bound_qmp_plugin)

    @patch.object(cffi.FFI, "dlopen")
    def test_first_command_installs_callback(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qmp.bind_qemu_compat(qemu)
        self.assertFalse(qemu.lib.set_penguin_qmp_callback.called)

        qmp.command("cmd-a")(lambda args: 1)
        self.assertTrue(qemu.lib.set_penguin_qmp_callback.called)
        self.assertIs(qemu._bound_qmp_plugin, qmp)

        # A second command must not re-install (idempotent).
        qemu.lib.set_penguin_qmp_callback.reset_mock()
        qmp.command("cmd-b")(lambda args: 2)
        self.assertFalse(qemu.lib.set_penguin_qmp_callback.called)

    @patch.object(cffi.FFI, "dlopen")
    def test_no_handler_declines(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "anything", "{}")
            self.assertFalse(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(res[0], qemu.ffi.NULL)

    @patch.object(cffi.FFI, "dlopen")
    def test_handler_returns_none_declines(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qmp.command("cmd")(lambda args: None)
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "{}")
            self.assertFalse(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(res[0], qemu.ffi.NULL)

    @patch.object(cffi.FFI, "dlopen")
    def test_handler_returns_false_declines(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qmp.command("cmd")(lambda args: False)
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "{}")
            self.assertFalse(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(res[0], qemu.ffi.NULL)

    @patch.object(cffi.FFI, "dlopen")
    def test_handler_returns_true_empty_response(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qmp.command("cmd")(lambda args: True)
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "{}")
            # True -> handled, no result buffer (empty {} supplied by C).
            self.assertTrue(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(res[0], qemu.ffi.NULL)

    @patch.object(cffi.FFI, "dlopen")
    def test_handler_returns_object_roundtrips(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        seen = {}

        @qmp.command("mycmd")
        def handler(args):
            seen["args"] = args
            return {"echo": args, "ok": True}

        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(
                qemu, "mycmd", json.dumps({"a": 1, "b": "two"}))
            self.assertTrue(qemu._dispatch_qmp(cmd, args, res))
            self.assertNotEqual(res[0], qemu.ffi.NULL)
            payload = json.loads(qemu.ffi.string(res[0]).decode())
        self.assertEqual(payload, {"echo": {"a": 1, "b": "two"}, "ok": True})
        # Decoded args are passed through to the handler.
        self.assertEqual(seen["args"], {"a": 1, "b": "two"})

    @patch.object(cffi.FFI, "dlopen")
    def test_empty_args_decode_to_dict(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        seen = {}
        qmp.command("cmd")(lambda args: seen.setdefault("args", args) or True)
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "")
            self.assertTrue(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(seen["args"], {})

    @patch.object(cffi.FFI, "dlopen")
    def test_garbage_args_decode_to_dict(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        seen = {}
        qmp.command("cmd")(lambda args: seen.setdefault("args", args) or True)
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "not-json{{")
            self.assertTrue(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(seen["args"], {})

    @patch.object(cffi.FFI, "dlopen")
    def test_non_serializable_result_declines(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()
        qmp.command("cmd")(lambda args: {"bad": object()})
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "{}")
            # json.dumps raises TypeError -> not handled. The compat layer logs
            # the failure via logger.exception; silence it for clean output.
            with self.assertLogs("pyplugins.qemu_compat", level="ERROR"):
                self.assertFalse(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(res[0], qemu.ffi.NULL)

    @patch.object(cffi.FFI, "dlopen")
    def test_handler_exception_declines(self, mock_dlopen):
        qemu = self._make_qemu(mock_dlopen)
        qmp = Qmp()

        def boom(args):
            raise RuntimeError("handler blew up")

        qmp.command("cmd")(boom)
        with fake_plugins_qmp(qmp):
            cmd, args, res = self._ptrs(qemu, "cmd", "{}")
            with self.assertLogs("pyplugins.qemu_compat", level="ERROR"):
                self.assertFalse(qemu._dispatch_qmp(cmd, args, res))
        self.assertEqual(res[0], qemu.ffi.NULL)


class TestQmpRegistry(unittest.TestCase):
    """Registration semantics owned by the Qmp plugin (no QEMU library needed)."""

    def test_command_decorator_registers(self):
        qmp = Qmp()

        @qmp.command("penguin-test")
        def handler(args):
            return {"ok": True}

        self.assertIs(qmp.handlers["penguin-test"], handler)

    def test_two_commands_both_dispatch(self):
        # The concrete bug the plugin fixes: a second registration used to
        # silently replace the first via a single global handler. With a real
        # registry, two distinct commands both keep answering.
        qmp = Qmp()
        qmp.command("cmd-a")(lambda args: {"who": "a"})
        qmp.command("cmd-b")(lambda args: {"who": "b"})

        self.assertEqual(qmp.dispatch("cmd-a", {}), {"who": "a"})
        self.assertEqual(qmp.dispatch("cmd-b", {}), {"who": "b"})

    def test_duplicate_command_raises(self):
        qmp = Qmp()
        qmp.command("dup")(lambda args: 1)
        with self.assertRaises(ValueError):
            qmp.command("dup")(lambda args: 2)

    def test_reregister_same_func_is_idempotent(self):
        qmp = Qmp()

        def handler(args):
            return 1

        qmp.register("cmd", handler)
        qmp.register("cmd", handler)  # same func, no error
        self.assertIs(qmp.handlers["cmd"], handler)

    def test_unregistered_command_returns_none(self):
        qmp = Qmp()
        self.assertIsNone(qmp.dispatch("nope", {}))

    def test_generator_result_rejected(self):
        # Guest portal access isn't serviceable from QMP main-loop context, so
        # a generator handler is a hard error rather than a confusing
        # CommandNotFound after json.dumps chokes.
        qmp = Qmp()

        def gen_handler(args):
            yield 1

        qmp.command("gen")(gen_handler)
        with self.assertRaises(RuntimeError):
            qmp.dispatch("gen", {})


if __name__ == "__main__":
    unittest.main()
