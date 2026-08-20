"""Host-side tests for the connect.sh generator (penguin.penguin_run).

connect.sh is the "get me into this device" helper written next to
runtime.yaml. It reaches the guest's serial root shell over the container's
localhost so it never bakes the per-run container IP. These tests assert the
rendered script's shape and that `sh -n` accepts it; the in-guest presence is
covered by the tests/integration test_target netbinds.yaml condition.
"""
import os
import shutil
import stat
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


# ---------------------------------------------------------------------------
# Command mode, driven end to end against a fake container engine.
#
# The engine stands in for `docker exec -i <c> telnet localhost <port>` and
# models the part that matters: telnet forwards stdin and *exits as soon as
# stdin reaches EOF*, even if the far end has not answered yet. That is why
# `printf ... | telnet` used to return before the guest replied, so command
# mode printed nothing and still exited 0.
# ---------------------------------------------------------------------------

FAKE_ENGINE = r"""#!/bin/sh
case "$1" in ps) echo "test_target"; exit 0 ;; esac
console=; for a in "$@"; do [ "$a" = "telnet" ] && console=1; done
[ -n "$console" ] || exit 0

IFS= read -r line || exit 0
TAG=$(printf '%s' "$line" | sed -n 's/.*_B_\([0-9]*\)__.*/\1/p' | head -1)
if [ -z "${FAKE_MUTE:-}" ]; then
(
  sleep "${FAKE_DELAY:-0.2}"
  printf '%s\n' "$line"
  printf '__PENGUIN_B_%s__\n' "$TAG"
  printf '%s\n' "${FAKE_OUTPUT:-hello from the guest}"
  printf '__PENGUIN_E_%s__%s\n' "$TAG" "${FAKE_RC:-0}"
  echo "trailing line after the end marker"
) & replier=$!
fi
while IFS= read -r _; do :; done
[ -n "${replier:-}" ] && kill "$replier" 2>/dev/null
exit 0
"""


@pytest.fixture
def connect(tmp_path):
    """A rendered connect.sh, plus a fake `docker` ahead of it on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    engine = bindir / "docker"
    engine.write_text(FAKE_ENGINE)
    engine.chmod(engine.stat().st_mode | stat.S_IEXEC)

    script = tmp_path / "connect.sh"
    script.write_text(_render())
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    def run(*args, env=None, timeout=60):
        e = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
        e.update(env or {})
        return subprocess.run([str(script), *args], capture_output=True,
                              text=True, env=e, timeout=timeout)

    return run


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_command_mode_returns_the_guest_output(connect):
    """The regression: this used to print nothing and exit 0."""
    r = connect("ps w")
    assert r.returncode == 0
    assert r.stdout.strip() == "hello from the guest"


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_command_mode_excludes_the_markers_and_trailing_output(connect):
    r = connect("ps w")
    assert "__PENGUIN" not in r.stdout
    assert "trailing line after the end marker" not in r.stdout


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_command_mode_preserves_output_verbatim(connect):
    """Indentation, blank lines and tabs must survive the marker slicing."""
    payload = "    indented\n\n\tt\tabbed\na line mentioning __PENGUIN_B_ partially"
    r = connect("ps w", env={"FAKE_OUTPUT": payload})
    assert r.stdout == payload + "\n"


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_command_mode_propagates_the_guest_exit_status(connect):
    r = connect("false", env={"FAKE_RC": "3"})
    assert r.returncode == 3


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_unanswered_command_is_bounded_and_fails(connect):
    """A silent guest must not hang, and must not report success."""
    r = connect("ps w", env={"FAKE_MUTE": "1", "PENGUIN_CONNECT_TIMEOUT": "2"})
    assert r.returncode == 1
    assert "no answer from the guest console" in r.stderr
    assert "PENGUIN_CONNECT_TIMEOUT" in r.stderr


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_command_mode_holds_stdin_open(connect):
    """Pin the mechanism: the guest answers after a delay and is still heard."""
    r = connect("ps w", env={"FAKE_DELAY": "1"})
    assert r.returncode == 0
    assert "hello from the guest" in r.stdout


@pytest.mark.skipif(shutil.which("sh") is None, reason="no /bin/sh")
def test_command_mode_leaves_no_temp_dir_behind(connect, tmp_path):
    before = set(os.listdir("/tmp"))
    connect("ps w")
    leaked = {n for n in set(os.listdir("/tmp")) - before if n.startswith("tmp.")}
    assert not leaked
