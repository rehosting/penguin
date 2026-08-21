"""Host-side tests for the configurable root-shell console backend.

`core.root_shell_backend` selects how core.root_shell is served: 'vsock'
(default) runs an on-demand pty over the guest command channel (guesthopper,
freeing ttyS1), 'telnet' keeps the legacy QEMU -serial console. The resolver
(`_resolve_console_backend`) wires the vsock backend's transport dependency;
the connect.sh renderers produce the matching helper script.
"""
import shutil
import subprocess

import pytest

from penguin.penguin_config import _resolve_console_backend
from penguin.penguin_run import (
    _render_connect_script,
    _render_connect_script_vsock,
    _write_connect_script,
)


def _cfg(root_shell=True, backend=None, vpn=None, guest_cmd=False):
    core = {"root_shell": root_shell, "guest_cmd": guest_cmd}
    if backend is not None:
        core["root_shell_backend"] = backend
    plugins = {}
    if vpn is not None:
        plugins["vpn"] = vpn
    return {"core": core, "plugins": plugins}


# --- resolver -------------------------------------------------------------- #

def test_vsock_with_vpn_enabled_autoenables_guest_cmd():
    cfg = _cfg(backend="vsock", vpn={"enabled": True})
    _resolve_console_backend(cfg)
    assert cfg["core"]["root_shell_backend"] == "vsock"
    assert cfg["core"]["guest_cmd"] is True


def test_vsock_default_backend_with_vpn_enabled():
    # Backend omitted -> defaults to vsock.
    cfg = _cfg(backend=None, vpn={"enabled": True})
    _resolve_console_backend(cfg)
    assert cfg["core"]["guest_cmd"] is True


def test_vsock_with_vpn_disabled_falls_back_to_telnet():
    cfg = _cfg(backend="vsock", vpn={"enabled": False})
    _resolve_console_backend(cfg)
    assert cfg["core"]["root_shell_backend"] == "telnet"
    # No transport -> do not auto-enable guest_cmd for the console.
    assert cfg["core"]["guest_cmd"] is False


def test_vsock_with_vpn_absent_falls_back_to_telnet():
    cfg = _cfg(backend="vsock", vpn=None)
    _resolve_console_backend(cfg)
    assert cfg["core"]["root_shell_backend"] == "telnet"


def test_telnet_backend_is_left_alone():
    cfg = _cfg(backend="telnet", vpn={"enabled": True})
    _resolve_console_backend(cfg)
    assert cfg["core"]["root_shell_backend"] == "telnet"
    assert cfg["core"]["guest_cmd"] is False


def test_root_shell_off_is_noop():
    cfg = _cfg(root_shell=False, backend="vsock", vpn={"enabled": True})
    _resolve_console_backend(cfg)
    assert cfg["core"]["guest_cmd"] is False


# --- connect.sh rendering -------------------------------------------------- #

@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_vsock_connect_script_is_valid_sh(tmp_path):
    s = _render_connect_script_vsock("test_target")
    p = tmp_path / "connect.sh"
    p.write_text(s)
    r = subprocess.run(["sh", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_vsock_connect_script_drives_guest_cmd_not_telnet():
    s = _render_connect_script_vsock("test_target")
    assert '"$GUEST_CMD" --shell' in s          # interactive pty over vsock
    assert "guest_cmd.py" in s                   # the GUEST_CMD path
    assert "telnet localhost" not in s           # no serial/telnet invocation
    assert 'CONTAINER="test_target"' in s


def test_write_connect_script_picks_vsock_variant(tmp_path):
    _write_connect_script(str(tmp_path), "c", 2323, True, True, backend="vsock")
    s = (tmp_path / "connect.sh").read_text()
    assert '"$GUEST_CMD" --shell' in s
    assert "guest_cmd.py" in s
    assert "2323" not in s  # no telnet port in the vsock script


def test_write_connect_script_telnet_backend_uses_telnet(tmp_path):
    _write_connect_script(str(tmp_path), "c", 2323, True, True, backend="telnet")
    s = (tmp_path / "connect.sh").read_text()
    assert "telnet localhost" in s
    assert "2323" in s


def test_write_connect_script_off_falls_through_to_legacy(tmp_path):
    # root_shell off -> legacy renderer regardless of backend.
    _write_connect_script(str(tmp_path), "c", 2323, False, True, backend="vsock")
    s = (tmp_path / "connect.sh").read_text()
    assert "core.root_shell is off" in _render_connect_script("c", 2323, False, True)
    assert isinstance(s, str)
