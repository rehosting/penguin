"""
Unit tests for the Penguin config layer (penguin.penguin_config).

These cover the schema reshape infrastructure:
  * static_files mode defaults
  * friendly Pydantic validation error rendering
  * `penguin schema` section resolution / docs generation
  * Jinja2 meta-variable templating

Everything here runs without a rootfs, kernel, or container.
"""

import tarfile
import tempfile
import textwrap
from pathlib import Path

import pytest

import penguin.penguin_config as pc
from penguin.penguin_config import structure
from penguin.penguin_config import gen_docs, templating
from penguin.penguin_config.errors import format_validation_error
from pydantic import ValidationError


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def base_config(**overrides):
    """A minimal config dict that validates against structure.Main."""
    cfg = dict(
        core=dict(version=2, arch="armel"),
        env={},
        pseudofiles={},
        nvram={},
        lib_inject={},
        static_files={},
        plugins={},
    )
    cfg.update(overrides)
    return cfg


def _error_for(cfg):
    try:
        structure.Main(**cfg)
    except ValidationError as e:
        return e
    raise AssertionError("expected ValidationError")


# --------------------------------------------------------------------------- #
# static_files mode defaults
# --------------------------------------------------------------------------- #
def test_inline_file_mode_defaults_to_644():
    cfg = base_config(static_files={"/x": dict(type="inline_file", contents="hi")})
    m = structure.Main(**cfg).model_dump()
    assert m["static_files"]["/x"]["mode"] == 0o644


def test_host_file_and_dir_mode_default_to_755():
    cfg = base_config(static_files={
        "/h": dict(type="host_file", host_path="/tmp/h"),
        "/d": dict(type="dir"),
    })
    m = structure.Main(**cfg).model_dump()
    assert m["static_files"]["/h"]["mode"] == 0o755
    assert m["static_files"]["/d"]["mode"] == 0o755


def test_dev_mode_defaults_to_666():
    cfg = base_config(static_files={
        "/dev/x": dict(type="dev", devtype="char", major=1, minor=2),
    })
    m = structure.Main(**cfg).model_dump()
    assert m["static_files"]["/dev/x"]["mode"] == 0o666


def test_explicit_mode_is_preserved():
    cfg = base_config(static_files={"/x": dict(type="inline_file", contents="hi", mode=0o600)})
    m = structure.Main(**cfg).model_dump()
    assert m["static_files"]["/x"]["mode"] == 0o600


# --------------------------------------------------------------------------- #
# friendly validation errors
# --------------------------------------------------------------------------- #
def test_friendly_error_bad_literal_lists_allowed_values():
    cfg = base_config(core=dict(version=2, arch="sparc"))
    msg = format_validation_error(_error_for(cfg))
    assert "core.arch" in msg
    assert "allowed:" in msg
    assert "armel" in msg and "mipsel" in msg


def test_friendly_error_unknown_union_tag_lists_tags():
    cfg = base_config(static_files={"/x": dict(type="bogus")})
    msg = format_validation_error(_error_for(cfg))
    assert "static_files./x" in msg
    assert "inline_file" in msg and "symlink" in msg


def test_friendly_error_typo_suggests_field():
    cfg = base_config()
    cfg["core"]["kernal"] = "/x"  # typo of kernel
    msg = format_validation_error(_error_for(cfg))
    assert "unknown option 'kernal'" in msg
    assert "did you mean kernel" in msg


def test_friendly_error_missing_required_section():
    cfg = base_config()
    del cfg["env"]
    msg = format_validation_error(_error_for(cfg))
    assert "required option 'env' is missing" in msg


def test_friendly_error_records_source_file_from_origin_map():
    cfg = base_config(core=dict(version=2, arch="sparc"))
    origin = {"core.arch": "/proj/patch_foo.yaml"}
    msg = format_validation_error(_error_for(cfg), origin_map=origin)
    assert "patch_foo.yaml" in msg


# --------------------------------------------------------------------------- #
# schema section resolution + docs generation
# --------------------------------------------------------------------------- #
def test_list_sections_contains_known_sections():
    names = [n for n, _ in gen_docs.list_sections()]
    for expected in ("core", "env", "static_files", "plugins", "vars"):
        assert expected in names


def test_resolve_section_core():
    assert gen_docs.resolve_section("core") is structure.Core


def test_resolve_section_into_union_variant():
    variant = gen_docs.resolve_section("pseudofiles.read.const_buf")
    assert variant is not None
    assert "val" in variant.model_fields


def test_resolve_section_unknown_returns_none():
    assert gen_docs.resolve_section("does.not.exist") is None


def test_gen_docs_runs_without_error():
    # Exercises dict/Any handling added for the `vars` section.
    out = gen_docs.gen_docs()
    assert "Template variables" in out
    assert isinstance(out, str) and len(out) > 0


# --------------------------------------------------------------------------- #
# Jinja2 templating
# --------------------------------------------------------------------------- #
def test_substitute_arch_and_core_fields():
    raw = {"core": {"arch": "mipsel", "mem": "1G"}, "x": "a={{ arch }} m={{ core.mem }}"}
    out, _ = templating.render_config(raw)
    assert out["x"] == "a=mipsel m=1G"


def test_substitute_user_vars_including_nested():
    raw = {
        "core": {"arch": "mipsel"},
        "vars": {"webroot": "/www", "libdir": "/lib/{{ arch }}"},
        "x": "{{ webroot }} {{ libdir }}",
    }
    out, _ = templating.render_config(raw)
    assert out["x"] == "/www /lib/mipsel"


def test_substitute_renders_dict_keys():
    raw = {"core": {"arch": "x"}, "vars": {"d": "/www"}, "sf": {"{{ d }}/index": 1}}
    out, _ = templating.render_config(raw)
    assert "/www/index" in out["sf"]


def test_kernel_version_two_pass():
    raw = {"core": {"arch": "mipsel"}, "p": "/k/{{ kernel_version }}/x"}
    rendered, _ = templating.render_config(raw)
    assert "{{ kernel_version }}" not in rendered["p"]
    final = templating.resolve_kernel_version(rendered, "6.13")
    assert final["p"] == "/k/6.13/x"


def test_undefined_variable_raises():
    with pytest.raises(templating.TemplateError):
        templating.render_config({"core": {"arch": "x"}, "y": "{{ nope }}"})


def test_no_template_config_is_untouched():
    raw = {"core": {"arch": "armel"}, "static_files": {"/a": {"type": "dir"}}}
    out, _ = templating.render_config(raw)
    assert out == raw


def test_legacy_at_placeholders_untouched():
    # @ARCH@-style placeholders (substituted by the test harness) must survive.
    raw = {"core": {"arch": "armel"}, "k": "/kernels/@ARCH@/vmlinux.@ARCH@"}
    out, _ = templating.render_config(raw)
    assert out["k"] == "/kernels/@ARCH@/vmlinux.@ARCH@"


# --------------------------------------------------------------------------- #
# end-to-end through load_config (no kernel/container needed)
# --------------------------------------------------------------------------- #
def test_load_config_templating_and_defaults():
    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp, "proj")
        (proj / "base").mkdir(parents=True)
        with tarfile.open(proj / "base" / "fs.tar.gz", "w"):
            pass
        (proj / "config.yaml").write_text(textwrap.dedent("""
            core:
              arch: mipsel
              version: 2
            vars:
              webroot: /www
            env: {}
            pseudofiles: {}
            nvram: {}
            lib_inject: {}
            static_files:
              "{{ webroot }}/index.html":
                type: inline_file
                contents: "arch={{ arch }} kver={{ kernel_version }}"
            plugins: {}
        """))

        cfg = pc.load_config(
            str(proj), str(proj / "config.yaml"),
            validate=True,
            resolved_kernel="/igloo_static/kernels/6.13/zImage.mipsel",
        )

    sf = cfg["static_files"]["/www/index.html"]
    assert sf["contents"] == "arch=mipsel kver=6.13"  # templated key + value + 2nd pass
    assert sf["mode"] == 0o644                          # default applied
    assert "vars" not in cfg                            # metadata stripped


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
