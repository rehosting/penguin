"""In-place harness coverage for the Readiness core plugin
(pyplugins/core/readiness.py), driven host-side with no PANDA/guest.

Readiness writes ``igloo_init.ready`` / ``netbind.ready`` marker files and
re-publishes a single ``ready`` event once init and the first netbind are seen.
Both are plain host logic: the ``on_readiness`` hypercall handler and the
``on_netbind`` subscriber (the latter is driven through the harness dispatch).
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
READINESS = REPO_ROOT / "pyplugins" / "core" / "readiness.py"


def test_on_readiness_writes_marker_and_publishes_once(tmp_path):
    lp = load_pyplugin(str(READINESS), outdir=tmp_path)
    rc = lp.plugin.on_readiness("igloo_init", "5")
    assert rc == (0, "")
    assert (tmp_path / "igloo_init.ready").read_text() == "5\n"
    assert lp.plugin.init_seen is True
    assert (lp.plugin, "ready", ("igloo_init",), {}) in lp.published

    # Second call is a no-op (marker already written, still returns cleanly).
    published_before = len(lp.published)
    assert lp.plugin.on_readiness("igloo_init", "9") == (0, "")
    assert (tmp_path / "igloo_init.ready").read_text() == "5\n"  # unchanged
    assert len(lp.published) == published_before


def test_shell_endpoints_lists_telnet_and_ssh_for_vsock(tmp_path, monkeypatch):
    # The vsock console brings up BOTH a telnet and an ssh front door, so the
    # READY line must advertise both (standard ports elide the port suffix).
    monkeypatch.setenv("CONTAINER_IP", "192.168.7.2")
    lp = load_pyplugin(
        str(READINESS), outdir=tmp_path,
        args=dict(root_shell_enabled=True, root_shell_backend="vsock",
                  telnet_port=23, ssh_port=22),
    )
    assert lp.plugin._shell_endpoints() == "telnet=192.168.7.2 ssh=root@192.168.7.2"


def test_shell_endpoints_backends_and_ports(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINER_IP", "10.0.0.5")

    def ep(**a):
        return load_pyplugin(str(READINESS), outdir=tmp_path, args=a).plugin._shell_endpoints()

    # Non-standard ports are shown explicitly (telnet <ip>:port, ssh root@<ip>:port).
    assert ep(root_shell_enabled=True, root_shell_backend="vsock",
              telnet_port=2323, ssh_port=2222) == "telnet=10.0.0.5:2323 ssh=root@10.0.0.5:2222"
    # Legacy telnet (serial) backend has no ssh door.
    assert ep(root_shell_enabled=True, root_shell_backend="telnet",
              telnet_port=23) == "telnet=10.0.0.5"
    # A vsock console whose ssh door didn't come up advertises telnet only.
    assert ep(root_shell_enabled=True, root_shell_backend="vsock",
              telnet_port=23, ssh_port=None) == "telnet=10.0.0.5"
    # No root shell -> nothing to advertise.
    assert ep() == ""


def test_shell_endpoints_gated_on_gateway_liveness(tmp_path, monkeypatch):
    # A vsock front door whose gateway failed to launch (up == False) must not be
    # advertised, so READY never points a user at a door that will refuse.
    monkeypatch.setenv("CONTAINER_IP", "10.1.1.1")
    lp = load_pyplugin(
        str(READINESS), outdir=tmp_path,
        args=dict(root_shell_enabled=True, root_shell_backend="vsock",
                  telnet_port=23, ssh_port=22),
    )
    assert lp.plugin._shell_endpoints() == "telnet=10.1.1.1 ssh=root@10.1.1.1"  # both up (unknown)
    lp.plugin.ssh_up = False
    assert lp.plugin._shell_endpoints() == "telnet=10.1.1.1"
    lp.plugin.telnet_up = False
    assert lp.plugin._shell_endpoints() == ""


def test_on_readiness_ignores_other_kinds(tmp_path):
    lp = load_pyplugin(str(READINESS), outdir=tmp_path)
    assert lp.plugin.on_readiness("something_else", "x") == (0, "")
    assert not (tmp_path / "igloo_init.ready").exists()
    assert lp.plugin.init_seen is False


def test_on_netbind_writes_marker_and_dedupes(tmp_path):
    lp = load_pyplugin(str(READINESS), outdir=tmp_path)
    lp.dispatch("on_bind", "tcp", 4, "0.0.0.0", 80, "httpd")
    assert (tmp_path / "netbind.ready").read_text() == "httpd,4,tcp,0.0.0.0,80\n"
    assert (lp.plugin, "ready", ("netbind",), {}) in lp.published

    # A second bind does not overwrite or re-publish.
    lp.dispatch("on_bind", "tcp", 4, "0.0.0.0", 443, "httpd")
    assert (tmp_path / "netbind.ready").read_text() == "httpd,4,tcp,0.0.0.0,80\n"
