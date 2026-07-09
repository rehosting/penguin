"""Host-side tests for the connect.sh generator (penguin.penguin_run).

connect.sh is the "get me into this device" helper written next to
runtime.yaml. It reaches the guest's serial root shell over the container's
localhost so it never bakes the per-run container IP. These tests assert the
rendered script's shape and that `sh -n` accepts it; the in-guest presence is
covered by the tests/integration test_target netbinds.yaml condition.
"""
import shutil
import subprocess

import pytest

from penguin.penguin_run import _render_connect_script


def _render(**kw):
    kw.setdefault("container_name", "test_target")
    kw.setdefault("telnet_port", 1023)
    kw.setdefault("root_shell", True)
    kw.setdefault("guest_cmd", True)
    return _render_connect_script(**kw)


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
@pytest.mark.parametrize("root_shell", [True, False])
def test_rendered_script_is_valid_sh(tmp_path, root_shell):
    script = _render(root_shell=root_shell)
    p = tmp_path / "connect.sh"
    p.write_text(script)
    r = subprocess.run(["sh", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_ip_agnostic_serial_attach():
    """Reaches the guest via the container's localhost -- never the guest/container IP."""
    s = _render(container_name="test_target", telnet_port=1023)
    # docker/podman exec into the named container, telnet localhost <port>.
    assert 'telnet localhost "$TELNET_PORT"' in s
    assert 'exec -it "$CONTAINER" telnet localhost' in s
    assert 'TELNET_PORT="1023"' in s
    assert 'CONTAINER="test_target"' in s
    # No IP address should be baked into the script.
    assert "192.168." not in s and "203.0.113." not in s


def test_interactive_is_plain_serial_attach():
    s = _render()
    # No-arg attach is a direct exec into the container's telnet; no tmux.
    assert 'exec "$ENGINE" exec -it "$CONTAINER" telnet localhost "$TELNET_PORT"' in s
    assert "tmux" not in s


def test_command_mode_captures_over_serial():
    s = _render()
    # command-mode marker capture with awk between begin/end markers
    assert "__PENGUIN" in s and "awk -v b=" in s


def test_root_shell_off_is_handled():
    s = _render(root_shell=False)
    assert 'ROOT_SHELL="false"' in s
    assert "core.root_shell" in s  # tells the user how to enable it


def test_guest_cmd_hint_only_when_enabled():
    assert "penguin guest_cmd" in _render(guest_cmd=True)
    assert "penguin guest_cmd" not in _render(guest_cmd=False)
