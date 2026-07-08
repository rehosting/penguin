"""Tests for the in-place pyplugin harness (penguin.testing) and a reference
end-to-end use of it against a real analysis plugin (netbinds), driven host-side
with no PANDA/guest.

This is the proof that the harness subsumes the old per-file `sys.modules`
stubbing: a plugin is loaded where it lives, fed events, and asserted on by the
file it writes.
"""
import socket
import textwrap
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin, RecorderStub, NullManager, NullPanda

REPO_ROOT = Path(__file__).resolve().parents[2]
NETBINDS = REPO_ROOT / "pyplugins" / "analysis" / "netbinds.py"


# --------------------------------------------------------------------------- #
# Harness primitives
# --------------------------------------------------------------------------- #
def test_recorder_stub_is_recursive_no_op_decorator():
    log = []
    stub = RecorderStub("plugins", log)
    # attribute chains never raise
    assert isinstance(stub.a.b.c, RecorderStub)
    # bare decorator returns the function unchanged

    def f():
        return 1
    assert stub(f) is f
    # decorator factory returns a decorator, and calls are recorded
    dec = stub.portalcall(0x1234)
    assert callable(dec)
    assert any("portalcall" in path for path, _a, _k in log)
    # container protocol is empty/no-op
    assert len(stub) == 0 and not bool(stub) and "x" not in stub


def test_null_manager_records_and_resolves_doubles():
    double = object()
    panda = NullPanda()
    mgr = NullManager(args={"plugins": {}}, doubles={"mem": double}, panda=panda, log=[])
    # registered double resolves by attribute and by get_plugin_by_name
    assert mgr.mem is double
    assert mgr.get_plugin_by_name("mem") is double
    # unknown sibling -> recording stub, never recurses into loading
    assert isinstance(mgr.Events, RecorderStub)
    # subscribe/register/publish are recorded, not executed
    mgr.subscribe(mgr.Events, "evt", lambda: None)
    mgr.register(object(), "on_x")
    mgr.publish(object(), "on_x", 1, 2)
    assert mgr.subscriptions and mgr.subscriptions[0][1] == "evt"
    assert mgr.registrations[0][1] == "on_x"
    assert mgr.published[0][1] == "on_x"


def test_dispatch_unknown_event_raises():
    lp = load_pyplugin(str(NETBINDS), outdir="/tmp", args={"shutdown_on_www": False})
    with pytest.raises(KeyError):
        lp.dispatch("no_such_event")


def test_class_body_subscribe_is_bound_and_dispatched(tmp_path):
    # `@plugins.subscribe(pub, event)` in a class body records the *unbound*
    # function; the harness must accept the decorator form and bind it to the
    # constructed instance on dispatch.
    plug = tmp_path / "tiny.py"
    plug.write_text(textwrap.dedent("""
        from penguin import plugins, Plugin

        class Tiny(Plugin):
            @plugins.subscribe(plugins.Events, "on_thing")
            def handle(self, x):
                self.seen.append(x)

            def __init__(self):
                self.seen = []
    """))
    lp = load_pyplugin(str(plug))
    assert "on_thing" in {ev for (_p, ev, _c) in lp.subscriptions}
    lp.dispatch("on_thing", 42)
    assert lp.plugin.seen == [42]  # bound to the instance, self supplied


def test_sibling_package_import_resolved(tmp_path):
    # A plugin under .../pyplugins/<cat>/ that imports a sibling package must
    # resolve, because the harness puts the pyplugins root on sys.path (the way
    # runtime discovery does).
    root = tmp_path / "pyplugins"
    (root / "sib").mkdir(parents=True)
    (root / "sib" / "__init__.py").write_text("VALUE = 7\n")
    (root / "cat").mkdir()
    plug = root / "cat" / "plug.py"
    plug.write_text(textwrap.dedent("""
        from penguin import Plugin
        from sib import VALUE

        class P(Plugin):
            def __init__(self):
                self.value = VALUE
    """))
    lp = load_pyplugin(str(plug))
    assert lp.plugin.value == 7


# --------------------------------------------------------------------------- #
# Reference: drive the real netbinds plugin in place
# --------------------------------------------------------------------------- #
def _load_netbinds(tmp_path, **args):
    args.setdefault("shutdown_on_www", False)
    # announce_debounce_s=0 announces synchronously (the historical immediate
    # behavior), so a single bind writes its row and publishes on_bind right
    # away -- what these reference tests assert. The nonzero-window debounce is
    # covered in test_netbinds_lifecycle.py.
    args.setdefault("announce_debounce_s", 0)
    # endianness="big" keeps the port value un-swapped so "80:123" -> port 80.
    return load_pyplugin(str(NETBINDS), outdir=tmp_path, args=args, endianness="big")


def test_netbinds_writes_bind_row(tmp_path):
    lp = _load_netbinds(tmp_path)

    # __init__ wrote the CSV headers and subscribed to the bind/setup/release events.
    events = {ev for (_p, ev, _c) in lp.subscriptions}
    assert {"igloo_ipv4_bind", "igloo_ipv4_setup", "igloo_ipv4_release"} <= events

    # Drive a setup (records pending procname + addr) then a bind (writes the row).
    lp.dispatch("igloo_ipv4_setup", None, "httpd", 0)      # sin_addr 0 -> 0.0.0.0
    lp.dispatch("igloo_ipv4_bind", None, "80:123", True)   # port:pid, TCP

    rows = (tmp_path / "netbinds.csv").read_text().splitlines()
    assert rows[0] == "procname,ipvn,domain,guest_ip,guest_port,pid,time,state,closed_time"
    fields = rows[1].split(",")
    assert fields[:6] == ["httpd", "4", "tcp", "0.0.0.0", "80", "123"]
    # Announced (survived the zero-length window) -> state listening, no close.
    assert fields[7] == "listening"
    assert fields[8] == ""

    # The plugin published an on_bind event for downstream consumers (VPN/Nmap).
    on_binds = [p for p in lp.published if p[1] == "on_bind"]
    assert on_binds and on_binds[0][2] == ("tcp", 4, "0.0.0.0", 80, "httpd")


def test_netbinds_dedupes_repeat_binds(tmp_path):
    lp = _load_netbinds(tmp_path)
    for _ in range(3):
        lp.dispatch("igloo_ipv4_setup", None, "httpd", 0)
        lp.dispatch("igloo_ipv4_bind", None, "80:123", True)
    data_rows = (tmp_path / "netbinds.csv").read_text().splitlines()[1:]
    assert len(data_rows) == 1  # identical binds are reported once


def test_netbinds_lifecycle_written_on_finalize(tmp_path):
    lp = _load_netbinds(tmp_path)
    lp.dispatch("igloo_ipv4_setup", None, "httpd", 0)
    lp.dispatch("igloo_ipv4_bind", None, "80:123", True)
    assert not (tmp_path / "netbinds_lifecycle.csv").exists()
    lp.finalize()  # uninit() flushes the lifecycle summary
    assert (tmp_path / "netbinds_lifecycle.csv").exists()


class _FakeMem:
    """Sibling double for the IPv6 path: netbinds reads the 16-byte address out
    of guest memory via ``plugins.mem.read_bytes_panda``."""

    def __init__(self, raw: bytes):
        self._raw = raw

    def read_bytes_panda(self, cpu, addr, length):
        return self._raw[:length]


def test_netbinds_ipv6_uses_mem_double(tmp_path):
    # Exercises load_pyplugin(doubles=...): the IPv6 setup handler dereferences
    # plugins.mem, which the harness resolves to our fake instead of a stub.
    raw = socket.inet_pton(socket.AF_INET6, "fe80::1")
    lp = load_pyplugin(
        str(NETBINDS), outdir=tmp_path,
        args={"shutdown_on_www": False, "announce_debounce_s": 0},
        endianness="little", doubles={"mem": _FakeMem(raw)},
    )
    lp.dispatch("igloo_ipv6_setup", None, "dnsd", 0)  # addr arg -> read via mem double
    lp.dispatch("igloo_ipv6_bind", None, f"{socket.htons(53)}:7", False)  # UDP

    fields = (tmp_path / "netbinds.csv").read_text().splitlines()[1].split(",")
    assert fields[:6] == ["dnsd", "6", "udp", "[fe80::1]", "53", "7"]
