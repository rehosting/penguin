"""Tests for the in-place pyplugin harness (penguin.testing) and a reference
end-to-end use of it against a real analysis plugin (netbinds), driven host-side
with no PANDA/guest.

This is the proof that the harness subsumes the old per-file `sys.modules`
stubbing: a plugin is loaded where it lives, fed events, and asserted on by the
file it writes.
"""
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


# --------------------------------------------------------------------------- #
# Reference: drive the real netbinds plugin in place
# --------------------------------------------------------------------------- #
def _load_netbinds(tmp_path, **args):
    args.setdefault("shutdown_on_www", False)
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
    assert rows[0] == "procname,ipvn,domain,guest_ip,guest_port,pid,time"
    fields = rows[1].split(",")
    assert fields[:6] == ["httpd", "4", "tcp", "0.0.0.0", "80", "123"]

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
