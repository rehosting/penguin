"""
Unit tests for the Penguin config layer (penguin.penguin_config and the plugin
argument machinery in penguin.plugin_manager).

These cover the schema reshape work:
  * static_files mode defaults
  * friendly Pydantic validation error rendering
  * `penguin schema` section resolution / docs generation
  * plugin `Args` declaration, defaults, and validation
  * first-class top-level plugin syntax
  * Jinja2 meta-variable templating

Everything here runs without a rootfs, kernel, or container.
"""

import os
import tarfile
import tempfile
import textwrap
from pathlib import Path

import pytest

import penguin.penguin_config as pc
from penguin import arch_registry
from penguin.penguin_config import structure
from penguin.penguin_config import gen_docs, templating
from penguin.penguin_config.errors import format_validation_error
from penguin import plugin_manager
from penguin.plugin_manager import Plugin, PluginArgs
from pydantic import Field, ValidationError


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


def write_plugin(dir_path, filename, body):
    p = Path(dir_path, filename)
    p.write_text(textwrap.dedent(body))
    return str(p)


DECLARING_PLUGIN = """
    from typing import List
    from pydantic import Field
    from penguin import Plugin, PluginArgs

    class Widget(Plugin):
        class Args(PluginArgs):
            names: List[str] = Field(default=[], description="names")
            count: int = Field(default=3, description="count")
            quiet: bool = False

        def __init__(self):
            pass
"""

LEGACY_PLUGIN = """
    from penguin import Plugin

    class Gadget(Plugin):
        def __init__(self):
            pass
"""

# A plugin that wires callbacks in its class body, exercising the introspection
# stub that neutralizes the manager during import.
CLASSBODY_PLUGIN = """
    from penguin import plugins, Plugin, PluginArgs
    from pydantic import Field

    class Sproket(Plugin):
        class Args(PluginArgs):
            flag: bool = Field(default=False)

        @plugins.syscalls.syscall("on_sys_open_enter")
        def on_open(self, *a, **k):
            pass

        def __init__(self):
            pass
"""


# Reads live runtime state (like hyper.consts -> plugins.kffi.get_enum_dict) at
# import time: imports with the no-op stub (len 0) but succeeds with a real
# manager bound.
RUNTIME_PLUGIN = """
    from penguin import plugins, Plugin, PluginArgs
    from pydantic import Field

    _enum = plugins.kffi.get_enum_dict("HYPER_OP")
    assert len(_enum) > 0, "needs a live manager"

    class Runtime(Plugin):
        class Args(PluginArgs):
            level: int = Field(default=1)

        def __init__(self):
            pass
"""


# A plain sibling module + a plugin that imports it at top level, to prove
# introspection doesn't leak imported sibling modules into sys.modules.
SIDECAR_MODULE = "LEAKED = True\n"
IMPORTING_PLUGIN = """
    import sidecar_mod  # noqa: F401
    from penguin import Plugin, PluginArgs

    class Importer(Plugin):
        class Args(PluginArgs):
            n: int = 0

        def __init__(self):
            pass
"""


@pytest.fixture
def plugin_dir():
    with tempfile.TemporaryDirectory() as d:
        write_plugin(d, "widget.py", DECLARING_PLUGIN)
        write_plugin(d, "gadget.py", LEGACY_PLUGIN)
        write_plugin(d, "sproket.py", CLASSBODY_PLUGIN)
        plugin_manager._import_plugin_classes.cache_clear()
        yield d
        plugin_manager._import_plugin_classes.cache_clear()


# --------------------------------------------------------------------------- #
# PR1: static_files mode defaults
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
# PR1: friendly validation errors
# --------------------------------------------------------------------------- #
def _error_for(cfg):
    try:
        structure.Main(**cfg)
    except ValidationError as e:
        return e
    raise AssertionError("expected ValidationError")


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
# PR2: schema section resolution + docs generation
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
    # the const_buf variant declares a `val` field
    assert "val" in variant.model_fields


def test_resolve_section_unknown_returns_none():
    assert gen_docs.resolve_section("does.not.exist") is None


def test_gen_docs_runs_without_error():
    # Exercises dict/Any handling added for the `vars` section.
    out = gen_docs.gen_docs()
    assert "Template variables" in out
    assert isinstance(out, str) and len(out) > 0


def test_resolve_section_docs_field_carries_field_title():
    # `plugins` is a bare `dict[str, Plugin]` whose title lives on its Field,
    # not its type. Resolving via DocsField.from_type alone dropped the title
    # and made `penguin schema plugins` raise; resolve_section_docs_field must
    # carry the field-level title so rendering succeeds.
    df = gen_docs.resolve_section_docs_field("plugins")
    assert df is not None and df.title == "Plugins"
    md = gen_docs.gen_docs(path=["plugins"], docs_field=df)
    assert "Plugins" in md and "Plugin" in md


def test_resolve_section_docs_field_every_top_level_section_renders():
    # `penguin schema <section>` must not error for any top-level section.
    for name, _title in gen_docs.list_sections():
        df = gen_docs.resolve_section_docs_field(name)
        assert df is not None, name
        assert gen_docs.gen_docs(path=[name], docs_field=df)


def test_resolve_section_docs_field_unknown_returns_none():
    assert gen_docs.resolve_section_docs_field("does.not.exist") is None


# --------------------------------------------------------------------------- #
# PR3: plugin Args declaration + defaults + validation
# --------------------------------------------------------------------------- #
class _DeclaringPlugin(Plugin):
    class Args(PluginArgs):
        names: list = []
        count: int = 3
        quiet: bool = Field(False)

    def __init__(self):
        pass


class _LegacyPlugin(Plugin):
    def __init__(self):
        pass


class _FakeMgr:
    panda = None


def test_declares_args():
    assert _DeclaringPlugin.declares_args() is True
    assert _LegacyPlugin.declares_args() is False
    # the base sentinel is not "declaring"
    assert Plugin.declares_args() is False


def test_preinit_fills_declared_defaults():
    p = _DeclaringPlugin.__new__(_DeclaringPlugin)
    p.__preinit__(_FakeMgr(), {"outdir": "/o", "names": ["a"]})
    assert p.get_arg("names") == ["a"]
    assert p.get_arg("count") == 3          # default filled
    assert p.get_arg_bool("quiet") is False  # default filled
    assert p.get_arg("outdir") == "/o"       # global arg preserved


def test_preinit_legacy_passthrough_no_defaults():
    p = _LegacyPlugin.__new__(_LegacyPlugin)
    p.__preinit__(_FakeMgr(), {"outdir": "/o", "whatever": 1})
    assert p.get_arg("whatever") == 1
    assert p.get_arg("count") is None  # no schema -> no default


def test_preinit_rejects_bad_type():
    # __preinit__ now formats the error and exits (friendly message) rather than
    # letting the raw ValidationError propagate — this is where arg types are
    # validated now that config load no longer imports plugins.
    p = _DeclaringPlugin.__new__(_DeclaringPlugin)
    with pytest.raises(SystemExit):
        p.__preinit__(_FakeMgr(), {"count": "not-an-int"})


def test_args_model_forbids_extra():
    with pytest.raises(ValidationError):
        _DeclaringPlugin.Args(bogus=1)


# --------------------------------------------------------------------------- #
# PR3: discovery / introspection against on-disk plugins
# --------------------------------------------------------------------------- #
def test_get_plugin_args_model_for_declaring_plugin(plugin_dir):
    model = plugin_manager.get_plugin_args_model("widget", "/tmp", plugin_dir)
    assert model is not None
    assert set(model.model_fields) == {"names", "count", "quiet"}


def test_get_plugin_args_model_none_for_legacy(plugin_dir):
    # discoverable but no Args schema
    assert plugin_manager.get_plugin_class("gadget", "/tmp", plugin_dir) is not None
    assert plugin_manager.get_plugin_args_model("gadget", "/tmp", plugin_dir) is None


def test_get_plugin_args_model_none_for_missing(plugin_dir):
    assert plugin_manager.get_plugin_args_model("nope", "/tmp", plugin_dir) is None


def test_introspection_handles_classbody_callbacks(plugin_dir):
    # Sproket wires a syscall callback in its class body; introspection must
    # still import it cleanly (manager neutralized by the stub).
    model = plugin_manager.get_plugin_args_model("sproket", "/tmp", plugin_dir)
    assert model is not None
    assert set(model.model_fields) == {"flag"}


# --------------------------------------------------------------------------- #
# PR3: first-class promotion + plugin arg validation (via load_config internals)
# --------------------------------------------------------------------------- #
def test_promote_first_class_plugin(plugin_dir):
    raw = base_config()
    raw["widget"] = {"names": ["x"]}
    pc._promote_first_class_plugins(raw, "/tmp", plugin_dir)
    assert "widget" not in raw
    assert raw["plugins"]["widget"] == {"names": ["x"]}


def test_promote_first_class_plugin_warns_deprecated(plugin_dir, monkeypatch):
    # First-class promotion still works for BC but must warn that it's deprecated.
    warnings = []
    monkeypatch.setattr(pc.logger, "warning",
                        lambda msg, *a, **k: warnings.append((msg % a) if a else msg))
    raw = base_config()
    raw["widget"] = {"names": ["x"]}
    pc._promote_first_class_plugins(raw, "/tmp", plugin_dir)
    assert raw["plugins"]["widget"] == {"names": ["x"]}  # still promoted
    assert any("deprecated" in w.lower() for w in warnings)


def test_unknown_top_level_key_is_left_for_schema(plugin_dir):
    raw = base_config()
    raw["totally_unknown"] = {"x": 1}
    pc._promote_first_class_plugins(raw, "/tmp", plugin_dir)
    # left in place so extra="forbid" catches it downstream
    assert "totally_unknown" in raw


def test_first_class_conflict_raises(plugin_dir):
    raw = base_config(plugins={"widget": {"count": 1}})
    raw["widget"] = {"count": 2}
    with pytest.raises(ValueError):
        pc._promote_first_class_plugins(raw, "/tmp", plugin_dir)


def test_validate_plugin_args_good(plugin_dir):
    cfg = base_config(plugins={"widget": {"names": ["a"], "count": 5}})
    # should not raise / exit
    pc._validate_plugin_args(cfg, "/tmp", plugin_dir)


def test_validate_plugin_args_defers_type_check_to_load(plugin_dir):
    # config load only catches unknown keys (statically, no import); a known key
    # with a bad *type* is not rejected here — that happens at __preinit__.
    cfg = base_config(plugins={"widget": {"count": "nope"}})
    pc._validate_plugin_args(cfg, "/tmp", plugin_dir)  # must not exit


def test_validate_plugin_args_unknown_key_exits(plugin_dir):
    cfg = base_config(plugins={"widget": {"namez": ["a"]}})
    with pytest.raises(SystemExit):
        pc._validate_plugin_args(cfg, "/tmp", plugin_dir)


def test_validate_plugin_args_skips_disabled(plugin_dir):
    cfg = base_config(plugins={"widget": {"enabled": False, "count": "bad-but-disabled"}})
    pc._validate_plugin_args(cfg, "/tmp", plugin_dir)  # disabled -> skipped


def test_gen_plugin_args_docs(plugin_dir):
    model = plugin_manager.get_plugin_args_model("widget", "/tmp", plugin_dir)
    md = gen_docs.gen_plugin_args_docs("widget", model)
    assert "`names`" in md and "`count`" in md and "`quiet`" in md


def test_discover_declaring_plugins(plugin_dir):
    # Declaring plugins are collected (sorted); the legacy plugin (gadget) is not.
    found, skipped = plugin_manager.discover_declaring_plugins(plugin_dir)
    names = [n for n, _ in found]
    assert "widget" in names
    assert "gadget" not in names


def test_config_load_does_not_import_plugins(plugin_dir):
    # Config load must not *execute* plugin code (it runs in the same process as
    # the real run). `importer` declares Args and does `import sidecar_mod` at
    # module scope; if config load imported it, sidecar_mod would appear in
    # sys.modules. Both promotion and arg-validation use AST instead.
    import sys
    write_plugin(plugin_dir, "sidecar_mod.py", SIDECAR_MODULE)
    write_plugin(plugin_dir, "importer.py", IMPORTING_PLUGIN)
    sys.modules.pop("sidecar_mod", None)

    raw = base_config()
    raw["importer"] = {"n": 1}
    pc._promote_first_class_plugins(raw, "/tmp", plugin_dir)
    assert raw["plugins"]["importer"] == {"n": 1}      # promoted via AST
    pc._validate_plugin_args(raw, "/tmp", plugin_dir)  # AST unknown-key check

    assert "sidecar_mod" not in sys.modules            # plugin was never executed


def test_discover_live_manager_recovers_runtime_plugin(plugin_dir):
    # A plugin that reads runtime state at import time is skipped under the
    # no-op stub but recovered when the live `plugins` manager is injected.
    write_plugin(plugin_dir, "runtime.py", RUNTIME_PLUGIN)
    plugin_manager._import_plugin_classes.cache_clear()

    found, skipped = plugin_manager.discover_declaring_plugins(plugin_dir)
    assert "runtime" not in [n for n, _ in found]
    assert any("runtime.py" in s for s in skipped)

    class _FakeKffi:
        def get_enum_dict(self, name):
            return {"A": 0, "B": 1}

    class _FakeManager:
        kffi = _FakeKffi()

    found, skipped = plugin_manager.discover_declaring_plugins(
        plugin_dir, manager=_FakeManager())
    assert "runtime" in [n for n, _ in found]


def test_gen_all_plugin_args_docs(plugin_dir):
    md = gen_docs.gen_all_plugin_args_docs(plugin_dir)
    # The aggregate page has exactly one H1 (its title); per-plugin sections
    # nest under it as H2 so the docs toctree shows one page with subsections
    # instead of one top-level entry per plugin.
    h1s = [ln for ln in md.splitlines() if ln.startswith("# ")]
    assert h1s == ["# Plugin arguments"]
    assert "## Plugin `widget` arguments" in md
    assert "`names`" in md and "`count`" in md


def test_gen_all_plugin_args_docs_nested_level(plugin_dir):
    # When nested under another section (as `penguin schema plugins` does), the
    # page title shifts to the given level and each plugin one deeper.
    md = gen_docs.gen_all_plugin_args_docs(plugin_dir, level=2)
    assert "## Plugin arguments" in md
    assert "### Plugin `widget` arguments" in md
    # No H1 is emitted at level 2.
    assert not any(ln == "# Plugin arguments" for ln in md.splitlines())


def test_gen_all_plugin_args_docs_show_skipped(plugin_dir):
    # The legacy plugin (gadget) doesn't declare Args so it's not "skipped"
    # (skipped == couldn't import); use a plugin that fails to import.
    write_plugin(plugin_dir, "broken.py", "import nonexistent_module_xyz\n")
    plugin_manager._import_plugin_classes.cache_clear()
    md = gen_docs.gen_all_plugin_args_docs(plugin_dir, show_skipped=True)
    # The skipped note is visible (a blockquote), not an HTML comment.
    assert "could not be introspected statically" in md
    assert "<!--" not in md


# --------------------------------------------------------------------------- #
# Static (AST-based) plugin Args extraction — covers plugins that can't be
# imported outside a live emulator, exactly as config-load validation does.
# --------------------------------------------------------------------------- #
def test_discover_declaring_plugins_static_covers_unimportable(plugin_dir):
    # IMPORTING_PLUGIN imports a sibling and RUNTIME_PLUGIN reads live state at
    # import; both are skipped by import-based discovery without a manager, but
    # the AST path reads their declared Args regardless.
    write_plugin(plugin_dir, "importer.py", IMPORTING_PLUGIN)
    write_plugin(plugin_dir, "runtime.py", RUNTIME_PLUGIN)

    imported, _ = plugin_manager.discover_declaring_plugins(plugin_dir)
    assert "runtime" not in [n for n, _ in imported]  # import path skips it

    found, skipped = plugin_manager.discover_declaring_plugins_static(plugin_dir)
    names = {n for n, _ in found}
    assert {"widget", "sproket", "importer", "runtime"} <= names
    assert "gadget" not in names          # declares no Args
    assert skipped == []                  # AST never needs to import


def test_static_arg_specs_capture_type_default_description(plugin_dir):
    found = dict(plugin_manager.discover_declaring_plugins_static(plugin_dir)[0])
    specs = {s.name: s for s in found["widget"]}
    assert specs["names"].type == "List[str]"
    assert specs["names"].default == ("literal", [])
    assert specs["names"].description == "names"
    assert specs["count"].default == ("literal", 3)
    # bare literal default (no Field) is captured too
    assert specs["quiet"].default == ("literal", False)
    assert specs["quiet"].required is False


def test_gen_all_plugin_args_docs_static(plugin_dir):
    write_plugin(plugin_dir, "runtime.py", RUNTIME_PLUGIN)
    md = gen_docs.gen_all_plugin_args_docs(plugin_dir, static=True)
    # The unimportable plugin's args are rendered from source.
    assert "## Plugin `runtime` arguments" in md
    assert "## Plugin `widget` arguments" in md
    assert "`names`" in md and "List[str]" in md


def test_plugin_declared_arg_specs_by_name(plugin_dir):
    # Single-plugin AST lookup (backs `schema <plugin>` / `schema plugins.<plugin>`),
    # including a plugin that can't be imported without a live manager.
    write_plugin(plugin_dir, "runtime.py", RUNTIME_PLUGIN)
    specs = plugin_manager.plugin_declared_arg_specs("widget", "/tmp", plugin_dir)
    assert {s.name for s in specs} == {"names", "count", "quiet"}
    # unimportable plugin still resolves via AST
    rspecs = plugin_manager.plugin_declared_arg_specs("runtime", "/tmp", plugin_dir)
    assert [s.name for s in rspecs] == ["level"]
    # legacy plugin declares no Args -> None
    assert plugin_manager.plugin_declared_arg_specs("gadget", "/tmp", plugin_dir) is None
    # unknown plugin -> None
    assert plugin_manager.plugin_declared_arg_specs("nope", "/tmp", plugin_dir) is None


# --------------------------------------------------------------------------- #
# PR3: AST <-> imported-model equivalence guard
#
# Config load detects declared plugin Args *statically* (AST, no import) while
# the real type validation happens later against the imported Pydantic model.
# That split only stays correct as long as the AST parser and the real model
# agree on which fields exist. These tests pin that invariant so the AST
# convention can't silently drift from the live model.
# --------------------------------------------------------------------------- #
def test_ast_field_set_matches_imported_model(plugin_dir):
    # For each on-disk fixture, the field names AST extracts must equal the field
    # names the imported model reports. Covers the representative declaration
    # shapes: annotated assignment (`names: List[str] = ...`), Field()-assigned,
    # and a class-body-callback plugin (sproket).
    for name in ("widget", "sproket"):
        model = plugin_manager.get_plugin_args_model(name, "/tmp", plugin_dir)
        ast_fields = plugin_manager.plugin_declared_arg_fields(name, "/tmp", plugin_dir)
        assert model is not None
        assert ast_fields == set(model.model_fields), name
    # Non-declaring / missing plugins: AST agrees there is no schema.
    assert plugin_manager.plugin_declared_arg_fields("gadget", "/tmp", plugin_dir) is None
    assert plugin_manager.plugin_declared_arg_fields("nope", "/tmp", plugin_dir) is None


def _shipped_pyplugins_dir():
    # tests/unit/test_config.py -> repo root -> pyplugins/
    d = Path(__file__).resolve().parents[2] / "pyplugins"
    return str(d) if d.is_dir() else None


def test_shipped_plugins_ast_matches_model():
    """Guard against AST drift on the *real* shipped pyplugins.

    For every declaring plugin we can actually import in this environment,
    the statically-parsed field set must equal the imported model's fields.
    Coverage depends on what imports here: full in-container (pandare + the
    live runtime resolve every declaring plugin), partial on a bare host. The
    test skips entirely when nothing imports so it never silently empty-passes.
    """
    pyplugins = _shipped_pyplugins_dir()
    if pyplugins is None:
        pytest.skip("shipped pyplugins/ directory not found")
    plugin_manager._import_plugin_classes.cache_clear()
    found, _skipped = plugin_manager.discover_declaring_plugins(pyplugins)
    if not found:
        pytest.skip("no shipped declaring plugins importable in this environment")
    mismatches = []
    for name, model in found:
        ast_fields = plugin_manager.plugin_declared_arg_fields(name, ".", pyplugins)
        expected = set(model.model_fields)
        if ast_fields != expected:
            mismatches.append((name, expected, ast_fields))
    assert not mismatches, (
        "AST-detected plugin Args drifted from the imported model "
        "(name, model_fields, ast_fields):\n" +
        "\n".join(f"  {n}: model={e} ast={a}" for n, e, a in mismatches)
    )


# --------------------------------------------------------------------------- #
# PR4: Jinja2 templating
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
    # first pass leaves a sentinel, not the literal text
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
# arch-derived template variables (used by auto-generated patches)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("arch,arch_dir,dylib_dir", [
    ("armel", "armel", "armel"),
    ("aarch64", "aarch64", "aarch64"),
    ("intel64", "x86_64", "x86_64"),
    # LE ppc64 has endian-distinct guest utils/kmods/kernel, so it owns its own
    # arch_subdir (not consolidated onto the big-endian powerpc64 tree).
    ("powerpc64le", "powerpc64le", "powerpc64le"),
    ("powerpc", "powerpc", "powerpc"),
    ("mipsel", "mipsel", "mipsel"),
    ("loongarch64", "loongarch64", "loongarch64"),
])
def test_arch_derived_context_vars(arch, arch_dir, dylib_dir):
    from penguin.arch_registry import normalize_arch
    ctx = templating.build_context({"core": {"arch": arch}})
    assert ctx["arch"] == normalize_arch(arch)  # {{ arch }} is canonicalized
    assert ctx["arch_dir"] == arch_dir
    assert ctx["dylib_dir"] == dylib_dir


def test_get_dylib_subdir_matches_context():
    from penguin.arch import get_dylib_subdir
    assert get_dylib_subdir("aarch64") == "aarch64"
    assert get_dylib_subdir("powerpc64le") == "powerpc64le"
    assert get_dylib_subdir("mipsel") == "mipsel"


def test_arch_dir_template_resolves_in_patch():
    # Mirrors the generated base patch: defines core.arch and uses the derived
    # subdir variables in host_paths.
    patch = {
        "core": {"arch": "aarch64"},
        "static_files": {
            "/igloo/dylibs/*": {"type": "host_file", "host_path": "/s/dylibs/{{ dylib_dir }}/*"},
            "/igloo/utils/*": {"type": "host_file", "host_path": "/s/{{ arch_dir }}/*"},
        },
    }
    out = templating.substitute(patch, templating.build_context(patch))
    assert out["static_files"]["/igloo/dylibs/*"]["host_path"] == "/s/dylibs/aarch64/*"
    assert out["static_files"]["/igloo/utils/*"]["host_path"] == "/s/aarch64/*"


def test_generated_base_patch_emits_arch_templates():
    # The BasePatch init plugin should emit Jinja placeholders (not baked
    # subdirs) for the arch-specific host_paths, so load-time templating
    # resolves them. (BasePatch now lives as an init plugin.)
    import inspect
    from pathlib import Path
    from penguin.plugin_manager import _import_plugin_classes
    repo_root = Path(__file__).resolve().parents[2]
    base_patch = dict(
        _import_plugin_classes(str(repo_root / "pyplugins/init/base_patch.py"))
    )["BasePatch"]
    src = inspect.getsource(base_patch.patch)
    assert "{{ dylib_dir }}" in src
    assert "{{ arch_dir }}" in src


# --------------------------------------------------------------------------- #
# PR1+PR3+PR4 end-to-end through load_config (no kernel/container needed)
# --------------------------------------------------------------------------- #
def _make_project(tmp, config_text, plugin_dir):
    proj = Path(tmp, "proj")
    (proj / "base").mkdir(parents=True)
    with tarfile.open(proj / "base" / "fs.tar.gz", "w"):
        pass
    (proj / "config.yaml").write_text(textwrap.dedent(config_text).replace("@PP@", plugin_dir))
    return proj


def test_load_config_end_to_end(plugin_dir):
    with tempfile.TemporaryDirectory() as tmp:
        proj = _make_project(tmp, """
            core:
              arch: mipsel
              version: 2
              plugin_path: @PP@
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
            widget:
              names: [a, b]
        """, plugin_dir)

        cfg = pc.load_config(
            str(proj), str(proj / "config.yaml"),
            validate=True,
            resolved_kernel="/igloo_static/kernels/6.13/zImage.mipsel",
        )

    # first-class widget folded into plugins, with declared default filled
    assert cfg["plugins"]["widget"]["names"] == ["a", "b"]
    # templated key + value, including kernel_version second pass
    sf = cfg["static_files"]["/www/index.html"]
    assert sf["contents"] == "arch=mipsel kver=6.13"
    assert sf["mode"] == 0o644            # default applied
    assert "vars" not in cfg             # metadata stripped


# --------------------------------------------------------------------------- #
# core.timeout: now a top-level core option (was the core plugin's arg)
# --------------------------------------------------------------------------- #
def _load_timeout_cfg(plugins_block, core_extra=""):
    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp, "proj")
        (proj / "base").mkdir(parents=True)
        with tarfile.open(proj / "base" / "fs.tar.gz", "w"):
            pass
        (proj / "config.yaml").write_text(textwrap.dedent(f"""
            core:
              arch: armel
              version: 2
            {core_extra}
            env: {{}}
            pseudofiles: {{}}
            nvram: {{}}
            lib_inject: {{}}
            static_files: {{}}
            plugins:
            {plugins_block}
        """))
        return pc.load_config(
            str(proj), str(proj / "config.yaml"), validate=True,
            resolved_kernel="/igloo_static/kernels/6.13/zImage.armel",
        )


def test_core_timeout_is_a_core_option():
    cfg = structure.Main(**base_config(core=dict(version=2, arch="armel", timeout=90))).model_dump()
    assert cfg["core"]["timeout"] == 90


def test_core_plugin_no_longer_declares_args():
    core_src = Path(os.path.dirname(__file__), "../../pyplugins/core/core.py").read_text()
    assert "class Args(" not in core_src


def test_legacy_plugins_core_timeout_migrates():
    cfg = _load_timeout_cfg("  core:\n                timeout: 77")
    assert cfg["core"]["timeout"] == 77
    assert "timeout" not in (cfg["plugins"].get("core") or {})


def test_explicit_core_timeout_wins_over_legacy():
    cfg = _load_timeout_cfg("  core:\n                timeout: 77", core_extra="  timeout: 5")
    assert cfg["core"]["timeout"] == 5


# --------------------------------------------------------------------------- #
# arch registry: aliases, normalization, consolidation, canonical flip
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("alias,canonical", [
    ("x86_64", "x86_64"), ("intel64", "x86_64"), ("amd64", "x86_64"),
    ("x86-64", "x86_64"), ("x64", "x86_64"),
    ("aarch64", "aarch64"), ("arm64", "aarch64"),
    ("armel", "armel"), ("arm", "armel"),
    ("powerpc64le", "powerpc64le"), ("ppc64le", "powerpc64le"),
    ("powerpc64el", "powerpc64le"), ("ppc64el", "powerpc64le"),
    ("powerpc64", "powerpc64"), ("ppc64", "powerpc64"),
    ("powerpc", "powerpc"), ("ppc", "powerpc"),
    ("mipseb", "mipseb"), ("mipsel", "mipsel"),
    ("riscv64", "riscv64"), ("rv64", "riscv64"),
    ("loongarch64", "loongarch64"), ("loongarch", "loongarch64"),
])
def test_normalize_arch(alias, canonical):
    assert arch_registry.normalize_arch(alias) == canonical
    assert arch_registry.normalize_arch(alias.upper()) == canonical  # case-insensitive


def test_normalize_arch_unknown_raises():
    with pytest.raises(KeyError):
        arch_registry.normalize_arch("sparc")
    assert arch_registry.is_known("intel64") and not arch_registry.is_known("sparc")


def test_schema_literal_matches_registry():
    import typing
    ann = structure.Core.model_fields["arch"].annotation
    lit = next(a for a in typing.get_args(ann) if typing.get_origin(a) is typing.Literal)
    assert set(typing.get_args(lit)) == set(arch_registry.all_names())


# Parity vs the OLD hardcoded mappings — guards against regressions in the flip.
# (ppc64le is the one intentional divergence: it now owns its own endian-distinct
# subdir rather than sharing the big-endian powerpc64 tree — see arch_registry.)
def _old_arch_subdir(a):
    if a == "intel64":
        return "x86_64"
    return a


@pytest.mark.parametrize("arch", [
    "armel", "aarch64", "mipsel", "mipseb", "mips64el", "mips64eb",
    "powerpc", "powerpc64", "powerpc64le", "riscv64", "loongarch64", "intel64",
])
def test_subdir_dylib_parity_with_old(arch):
    # arch_subdir maps the intel64 alias to x86_64 (the "old" hardcoded scheme);
    # ppc64le is the sole intentional divergence (owns its own subdir now).
    assert arch_registry.arch_subdir(arch) == _old_arch_subdir(arch)
    # dylib_subdir was flipped off the hyperfs-era names (arm64/ppc64el/...) to
    # the canonical arch name: it must now equal normalize_arch for every arch.
    assert arch_registry.dylib_subdir(arch) == arch_registry.normalize_arch(arch)
    assert arch_registry.arch_subdir(arch) == arch_registry.arch_subdir(arch_registry.normalize_arch(arch))


def test_x86_subdirs():
    assert arch_registry.arch_subdir("intel64") == "x86_64" == arch_registry.arch_subdir("x86_64")
    assert arch_registry.dylib_subdir("intel64") == "x86_64" == arch_registry.dylib_subdir("x86_64")
    assert arch_registry.kmod_subdir("aarch64") == "arm64"


def test_q_config_powerpc64le_and_fresh_dict():
    from penguin.q_config import load_q_config
    q = load_q_config({"core": {"arch": "powerpc64le"}})
    assert q["arch"] == "ppc64" and q["qemu_machine"] == "pseries"
    assert load_q_config({"core": {"arch": "ppc64el"}})["arch"] == "ppc64"  # alias
    # returns a fresh dict each call (old code mutated a shared module dict)
    a = load_q_config({"core": {"arch": "mipsel"}})
    a["arch"] = "ZZ"
    assert load_q_config({"core": {"arch": "mipsel"}})["arch"] == "mipsel"


def test_abi_info_rekeyed_and_normalizes():
    from penguin.abi_info import arch_abi_info, ARCH_ABI_INFO
    assert "x86_64" in ARCH_ABI_INFO and "intel64" not in ARCH_ABI_INFO
    assert arch_abi_info("intel64") is arch_abi_info("x86_64")


def test_dropin_dylib_dir_consolidated():
    from penguin.dropin_compile import _dylib_dir
    assert _dylib_dir("intel64") == "x86_64" == _dylib_dir("x86_64")
    assert _dylib_dir("aarch64") == "aarch64"


def test_load_config_arch_alias_normalized():
    """arch: intel64 and arch: x86_64 produce identical realized configs."""
    def realize(arch):
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp, "proj")
            (proj / "base").mkdir(parents=True)
            with tarfile.open(proj / "base" / "fs.tar.gz", "w"):
                pass
            (proj / "config.yaml").write_text(textwrap.dedent(f"""
                core:
                  arch: {arch}
                  version: 2
                env: {{}}
                pseudofiles: {{}}
                nvram: {{}}
                lib_inject: {{}}
                static_files: {{}}
                plugins: {{}}
            """))
            return pc.load_config(
                str(proj), str(proj / "config.yaml"), validate=True,
                resolved_kernel="/igloo_static/kernels/6.13/zImage.x86_64",
            )
    a = realize("x86_64")
    b = realize("intel64")
    assert a["core"]["arch"] == "x86_64" and b["core"]["arch"] == "x86_64"
    assert a == b


def test_templating_arch_alias_canonical_and_derived():
    raw = {"core": {"arch": "intel64"}, "x": "{{ arch }} {{ arch_dir }} {{ dylib_dir }}"}
    out, _ = templating.render_config(raw)
    assert out["x"] == "x86_64 x86_64 x86_64"
    raw2 = {"core": {"arch": "arm64"}, "x": "{{ arch }} {{ dylib_dir }}"}
    out2, _ = templating.render_config(raw2)
    assert out2["x"] == "aarch64 aarch64"


# --------------------------------------------------------------------------- #
# Pseudofile model expansion (backwards-compatible additive work)
#
# Covers the new declarative model vocabulary, the broadened VFS-operation
# surface, the `custom` (register_model) escape variant, the per-variant
# `provenance` tag, and the per-path validation that rejects an op attached to
# a filesystem that can't service it. All of this validates at the schema layer
# (no emulator), so it runs in this host/CI unit suite.
# --------------------------------------------------------------------------- #
def _pf(pseudofiles):
    """Validate a pseudofiles block through the full Main schema."""
    return structure.Main(**base_config(pseudofiles=pseudofiles)).model_dump()


def _pf_error(pseudofiles):
    try:
        structure.Main(**base_config(pseudofiles=pseudofiles))
    except ValidationError as e:
        return e
    raise AssertionError("expected ValidationError")


# --- new read models -------------------------------------------------------- #
def test_read_cycle_validates():
    m = _pf({"/dev/a": {"read": {"model": "cycle", "val": "AB"}}})
    assert m["pseudofiles"]["/dev/a"]["read"]["val"] == "AB"


def test_read_stateful_validates_with_optional_initial():
    # stateful read paired with a recording write = a YAML read/write register
    m = _pf({"/dev/reg": {"read": {"model": "stateful", "initial": "0"},
                          "write": {"model": "default"}}})
    assert m["pseudofiles"]["/dev/reg"]["read"]["initial"] == "0"
    # initial is optional
    _pf({"/dev/reg": {"read": {"model": "stateful"}}})


def test_read_sequence_validates():
    m = _pf({"/proc/status": {"read": {"model": "sequence",
                                       "vals": ["busy\n", "busy\n", "ready\n"],
                                       "cycle": True}}})
    r = m["pseudofiles"]["/proc/status"]["read"]
    assert r["vals"][-1] == "ready\n" and r["cycle"] is True


# --- new write models ------------------------------------------------------- #
def test_write_return_const_validates():
    m = _pf({"/dev/a": {"write": {"model": "return_const", "const": -1}}})
    assert m["pseudofiles"]["/dev/a"]["write"]["const"] == -1


def test_write_unhandled_validates():
    _pf({"/dev/a": {"write": {"model": "unhandled"}}})


# --- new ioctl models ------------------------------------------------------- #
def test_ioctl_write_data_validates_in_command_map():
    m = _pf({"/dev/a": {"ioctl": {4660: {"model": "write_data",
                                         "data": "\x01\x00\x00\x00", "val": 0}}}})
    h = m["pseudofiles"]["/dev/a"]["ioctl"][4660]
    assert h["data"] == "\x01\x00\x00\x00" and h["val"] == 0


def test_ioctl_unhandled_validates_wildcard():
    _pf({"/dev/a": {"ioctl": {"*": {"model": "unhandled"}}}})


# --- broadened VFS operation surface ---------------------------------------- #
def test_lseek_default_and_unsupported_validate():
    _pf({"/dev/a": {"lseek": {"model": "default"}}})
    _pf({"/dev/a": {"lseek": {"model": "unsupported"}}})


def test_lseek_from_plugin_validates():
    _pf({"/dev/a": {"lseek": {"model": "from_plugin", "plugin": "p", "function": "seek"}}})


def test_compat_ioctl_same_as_ioctl_validates():
    _pf({"/dev/a": {"ioctl": {"*": {"model": "return_const", "val": 0}},
                    "compat_ioctl": {"model": "same_as_ioctl"}}})


@pytest.mark.parametrize("op", ["mmap", "open", "release", "flush", "fsync",
                                "fasync", "lock", "read_iter", "write_iter",
                                "get_unmapped_area"])
def test_plugin_op_domains_validate_on_dev(op):
    # every plugin-driven op domain accepts a from_plugin model on a /dev node
    _pf({"/dev/a": {op: {"model": "from_plugin", "plugin": "p"}}})


# --- custom (register_model) escape variant -------------------------------- #
def test_custom_read_model_accepts_model_name_and_extra_kwargs():
    # `model: custom` carries a model_name + free kwargs forwarded to the mixin
    m = _pf({"/dev/sensor": {"read": {"model": "custom", "model_name": "my_sensor",
                                      "scale": 10}}})
    r = m["pseudofiles"]["/dev/sensor"]["read"]
    assert r["model_name"] == "my_sensor" and r["scale"] == 10


# --- provenance ------------------------------------------------------------- #
def test_provenance_tag_accepted_on_any_variant():
    m = _pf({"/dev/d": {"read": {"model": "zero", "provenance": "default"},
                        "write": {"model": "discard", "provenance": "default"}}})
    assert m["pseudofiles"]["/dev/d"]["read"]["provenance"] == "default"


# --- strict validation preserved (extra="forbid") --------------------------- #
def test_unknown_field_in_variant_still_rejected():
    msg = format_validation_error(_pf_error({"/dev/a": {"read": {"model": "zero", "bogus": 1}}}))
    assert "bogus" in msg


# --- per-path validation (the most recent ask) ------------------------------ #
@pytest.mark.parametrize("path,op,model", [
    ("/proc/x", "flush", {"model": "from_plugin", "plugin": "p"}),
    ("/sys/x", "lseek", {"model": "default"}),
    ("/proc/sys/x", "mmap", {"model": "from_plugin", "plugin": "p"}),
    ("/proc/x", "write_iter", {"model": "from_plugin", "plugin": "p"}),
    ("/sys/x", "fsync", {"model": "from_plugin", "plugin": "p"}),
])
def test_op_rejected_on_unsupported_filesystem(path, op, model):
    msg = format_validation_error(_pf_error({path: {op: model}}))
    assert op in msg and path in msg


@pytest.mark.parametrize("path,op,model", [
    ("/dev/a", "flush", {"model": "from_plugin", "plugin": "p"}),  # /dev-only op on /dev
    ("/dev/a", "write_iter", {"model": "from_plugin", "plugin": "p"}),
    ("/dev/a", "lseek", {"model": "default"}),
    ("/proc/a", "lseek", {"model": "default"}),                    # broader op on /proc
    ("/proc/a", "mmap", {"model": "from_plugin", "plugin": "p"}),
])
def test_op_allowed_on_supported_filesystem(path, op, model):
    _pf({path: {op: model}})


def test_read_write_ioctl_poll_unconstrained_by_path():
    # the legacy domains are wired everywhere — never path-restricted
    for path in ("/dev/a", "/proc/a", "/proc/sys/a", "/sys/a"):
        _pf({path: {"read": {"model": "zero"},
                    "write": {"model": "discard"},
                    "ioctl": {"*": {"model": "return_const", "val": 0}}}})


# --- backwards compatibility ------------------------------------------------ #
def test_legacy_pseudofile_config_unchanged():
    # a pre-expansion config validates and round-trips with no new keys leaking in
    legacy = {"/dev/leg": {"read": {"model": "const_buf", "val": "x"},
                           "write": {"model": "discard"},
                           "ioctl": {"*": {"model": "return_const", "val": 0}}}}
    m = _pf(legacy)
    node = m["pseudofiles"]["/dev/leg"]
    assert node["read"]["val"] == "x"
    # the new optional op domains all default to None (absent) — purely additive
    for op in ("lseek", "mmap", "open", "release", "compat_ioctl", "flush",
               "fsync", "fasync", "lock", "read_iter", "write_iter",
               "get_unmapped_area"):
        assert node[op] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
