"""
Unit tests for uncompiled init drop-ins (draft 24).

Covers the shell half: `.sh` / extension-less shell scripts placed in a
project's `init.d/` are recognized as first-class init scripts, their shebang is
normalized to the in-guest interpreter (`/igloo/utils/sh`), and they land in
`static_files` at `/igloo/init.d/<name>`, mode 0755, with a runnable shebang.
`source.d/` and non-script drop-ins are installed verbatim.

Pure host logic: no rootfs contents, no kernel, no container.
"""

import tarfile
import tempfile
import textwrap
from pathlib import Path

import pytest

import penguin.penguin_config as pc


GUEST_SH = "/igloo/utils/sh"
GUEST_PY = "/igloo/utils/python3"


# --------------------------------------------------------------------------- #
# _resolve_init_dropin: shebang normalization decisions
# --------------------------------------------------------------------------- #
def _resolve(tmp, filename, content, python_interp=None):
    if isinstance(content, str):
        content = content.encode()
    host_path = Path(tmp) / filename
    host_path.write_bytes(content)
    return pc._resolve_init_dropin(str(host_path), filename, python_interp=python_interp)


def test_sh_without_shebang_gets_shell_shebang_prepended():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "10_net.sh", "ip link set eth0 up\n")
    assert kind == "inline"
    assert payload == f"#!{GUEST_SH}\nip link set eth0 up\n"


def test_sh_with_foreign_shebang_is_rewritten_body_preserved():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "boot.sh", "#!/bin/sh\necho hi\nexit 0\n")
    assert kind == "inline"
    assert payload == f"#!{GUEST_SH}\necho hi\nexit 0\n"


def test_sh_already_targeting_guest_shell_is_verbatim():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "ok.sh", f"#!{GUEST_SH}\necho hi\n")
    assert kind == "verbatim"
    assert payload is None


def test_extensionless_shell_shebang_is_normalized():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "runme", "#!/bin/bash\necho hi\n")
    assert kind == "inline"
    assert payload == f"#!{GUEST_SH}\necho hi\n"


def test_extensionless_env_python_shebang_normalized_when_python_staged():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(
            tmp, "probe", "#!/usr/bin/env python3\nprint('hi')\n",
            python_interp=GUEST_PY)
    assert kind == "inline"
    assert payload == f"#!{GUEST_PY}\nprint('hi')\n"


def test_extensionless_unknown_shebang_left_verbatim():
    # A deliberate non-shell/non-python interpreter is the user's choice.
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "tool", "#!/igloo/utils/busybox awk -f\nBEGIN{}\n")
    assert kind == "verbatim"
    assert payload is None


def test_extensionless_binary_left_verbatim():
    # A prebuilt ELF dropped in must never be rewritten.
    elf = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 32
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "prebuilt", elf)
    assert kind == "verbatim"
    assert payload is None


def test_other_extension_left_verbatim():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "settings.conf", "key=value\n")
    assert kind == "verbatim"
    assert payload is None


def test_py_needs_python_when_no_interpreter_staged():
    # A .py drop-in with no staged interpreter is a build error signal, not a
    # silent verbatim install of a script that would die at boot.
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "probe.py", "#!/usr/bin/python3\nprint('hi')\n")
    assert kind == "need_python"
    assert payload is None


def test_extensionless_python_shebang_needs_python_when_unstaged():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(tmp, "probe", "#!/usr/bin/env python3\nprint('hi')\n")
    assert kind == "need_python"
    assert payload is None


def test_py_normalized_when_python_interpreter_staged():
    with tempfile.TemporaryDirectory() as tmp:
        kind, payload = _resolve(
            tmp, "probe.py", "print('hi')\n", python_interp=GUEST_PY)
    assert kind == "inline"
    assert payload == f"#!{GUEST_PY}\nprint('hi')\n"


# --------------------------------------------------------------------------- #
# End-to-end through load_config
# --------------------------------------------------------------------------- #
def _project_with_dropins(tmp, init_d=None, source_d=None):
    proj = Path(tmp, "proj")
    (proj / "base").mkdir(parents=True)
    with tarfile.open(proj / "base" / "fs.tar.gz", "w"):
        pass
    for folder, files in (("init.d", init_d or {}), ("source.d", source_d or {})):
        if files:
            (proj / folder).mkdir()
            for name, body in files.items():
                (proj / folder / name).write_text(body)
    (proj / "config.yaml").write_text(textwrap.dedent("""
        core:
          arch: armel
          version: 2
        env: {}
        pseudofiles: {}
        nvram: {}
        lib_inject: {}
        static_files: {}
        plugins: {}
    """))
    return proj


def _load(proj):
    return pc.load_config(
        str(proj), str(proj / "config.yaml"), validate=True,
        resolved_kernel="/igloo_static/kernels/6.13/zImage.armel",
    )


def test_end_to_end_sh_dropin_lands_in_static_files():
    with tempfile.TemporaryDirectory() as tmp:
        proj = _project_with_dropins(tmp, init_d={"10_net.sh": "ip link set eth0 up\n"})
        cfg = _load(proj)

    entry = cfg["static_files"]["/igloo/init.d/10_net.sh"]
    assert entry["type"] == "inline_file"
    assert entry["mode"] == 0o755
    assert entry["contents"].startswith(f"#!{GUEST_SH}\n")
    assert "ip link set eth0 up" in entry["contents"]


def test_end_to_end_correct_shebang_stays_host_file():
    with tempfile.TemporaryDirectory() as tmp:
        proj = _project_with_dropins(
            tmp, init_d={"20_ok.sh": f"#!{GUEST_SH}\necho hi\n"})
        cfg = _load(proj)

    entry = cfg["static_files"]["/igloo/init.d/20_ok.sh"]
    # No rewrite needed -> installed verbatim as a host_file (zero-copy).
    assert entry["type"] == "host_file"
    assert entry["mode"] == 0o755
    assert entry["host_path"].endswith("init.d/20_ok.sh")


def test_end_to_end_source_d_is_not_normalized():
    with tempfile.TemporaryDirectory() as tmp:
        proj = _project_with_dropins(
            tmp, source_d={"env.sh": "export FOO=bar\n"})
        cfg = _load(proj)

    entry = cfg["static_files"]["/igloo/source.d/env.sh"]
    # source.d/ is sourced, not exec'd: installed verbatim, never rewritten.
    assert entry["type"] == "host_file"
    assert entry["mode"] == 0o755


# --------------------------------------------------------------------------- #
# End-to-end: .py drop-ins (gated on a staged in-guest interpreter)
# --------------------------------------------------------------------------- #
def test_end_to_end_py_dropin_resolves_to_guest_python(monkeypatch):
    # Pretend a python3 closure is staged for the target arch.
    monkeypatch.setattr(pc, "_guest_python_interp", lambda config: GUEST_PY)
    with tempfile.TemporaryDirectory() as tmp:
        proj = _project_with_dropins(tmp, init_d={"probe.py": "print('hi')\n"})
        cfg = _load(proj)

    entry = cfg["static_files"]["/igloo/init.d/probe.py"]
    assert entry["type"] == "inline_file"
    assert entry["mode"] == 0o755
    assert entry["contents"] == f"#!{GUEST_PY}\nprint('hi')\n"


def test_end_to_end_py_dropin_without_interpreter_fails_build(monkeypatch):
    # No interpreter staged for the target (host unit-test default).
    monkeypatch.setattr(pc, "_guest_python_interp", lambda config: None)
    with tempfile.TemporaryDirectory() as tmp:
        proj = _project_with_dropins(tmp, init_d={"probe.py": "print('hi')\n"})
        with pytest.raises(ValueError, match="no in-guest Python interpreter"):
            _load(proj)
