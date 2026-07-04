"""
Unit tests for the init plugin engine (penguin.init_plugin / penguin.init_runner):
compute-once cached analyses, cycle detection, failure isolation (no plugin
failure stops the run), the consumes_patches post phase, and deterministic
patch render order.
"""

import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from penguin.init_plugin import (
    InitAnalysisCycleError,
    InitContext,
    InitPlugin,
    cached_analysis,
)
from penguin.init_runner import InitPluginRunner


def fresh_manager():
    """A clean IGLOOPluginManager (drops the singleton so attribute caches
    from previous tests can't leak)."""
    from penguin.plugin_manager import IGLOOPluginManager

    if hasattr(IGLOOPluginManager, "instance"):
        del IGLOOPluginManager.instance
    return IGLOOPluginManager()


def make_ctx(tmp):
    tmp = Path(tmp)
    tar_path = tmp / "fs.tar.gz"
    with tarfile.open(tar_path, "w:gz") as t:
        info = tarfile.TarInfo("./etc")
        info.type = tarfile.DIRTYPE
        t.addfile(info)
    extracted = tmp / "fs"
    extracted.mkdir()
    return InitContext(tar_path, extracted, tmp, tmp / "static", tmp / "static_patches")


def run_plugins(classes, tmp, jobs=4):
    ctx = make_ctx(tmp)
    runner = InitPluginRunner(classes, ctx, manager=fresh_manager(), jobs=jobs)
    return runner, runner.run(), ctx


class TestCachedAnalysis(unittest.TestCase):
    def test_computed_once_across_threads(self):
        counts = {"n": 0}

        class Shared(InitPlugin):
            @cached_analysis
            def value(self):
                counts["n"] += 1
                time.sleep(0.1)
                return 42

        class UserA(InitPlugin):
            patch_name = "user_a"
            order = 10

            def patch(self, ctx):
                return {"core": {"a": self.plugins.Shared.value}}

        class UserB(InitPlugin):
            patch_name = "user_b"
            order = 20

            def patch(self, ctx):
                return {"core": {"b": self.plugins.Shared.value}}

        with tempfile.TemporaryDirectory() as tmp:
            _, patches, _ = run_plugins([Shared, UserA, UserB], tmp)
        self.assertEqual(counts["n"], 1)
        self.assertEqual(patches["user_a"][0]["core"]["a"], 42)
        self.assertEqual(patches["user_b"][0]["core"]["b"], 42)

    def test_exception_cached_and_reraised(self):
        counts = {"n": 0}

        class Failing(InitPlugin):
            @cached_analysis
            def value(self):
                counts["n"] += 1
                raise ValueError("nope")

        class User1(InitPlugin):
            patch_name = "u1"

            def patch(self, ctx):
                return {"v": self.plugins.Failing.value}

        class User2(InitPlugin):
            patch_name = "u2"

            def patch(self, ctx):
                return {"v": self.plugins.Failing.value}

        with tempfile.TemporaryDirectory() as tmp:
            runner, patches, _ = run_plugins([Failing, User1, User2], tmp)
        self.assertEqual(counts["n"], 1)  # computed once, failure cached
        self.assertNotIn("u1", patches)
        self.assertNotIn("u2", patches)
        self.assertEqual(runner.manifest["User1"]["status"], "failed")
        self.assertEqual(runner.manifest["User2"]["status"], "failed")

    def test_cycle_detected(self):
        class CycA(InitPlugin):
            @cached_analysis
            def x(self):
                return self.plugins.CycB.y

        class CycB(InitPlugin):
            @cached_analysis
            def y(self):
                return self.plugins.CycA.x

        class CycUser(InitPlugin):
            patch_name = "cyc"

            def patch(self, ctx):
                return {"v": self.plugins.CycA.x}

        with tempfile.TemporaryDirectory() as tmp:
            runner, patches, _ = run_plugins([CycA, CycB, CycUser], tmp)
        self.assertNotIn("cyc", patches)
        self.assertIn("cycle", runner.manifest["CycUser"]["error"])

    def test_direct_cycle_raises_for_caller(self):
        class SelfRef(InitPlugin):
            @cached_analysis
            def x(self):
                return self.x

        plugin = SelfRef.__new__(SelfRef)
        with self.assertRaises(InitAnalysisCycleError):
            plugin.x


class TestRunner(unittest.TestCase):
    def test_failed_core_analysis_does_not_stop_init(self):
        """Even an ArchId-style failure (analysis everything depends on) must
        not abort the run - consumers fail and are skipped, the rest of init
        completes."""

        class Arch(InitPlugin):
            @cached_analysis
            def arch(self):
                raise NotImplementedError("unsupported arch")

            def static_result(self):
                return self.arch

        class Base(InitPlugin):
            patch_name = "base"
            order = 10

            def patch(self, ctx):
                return {"core": {"arch": self.plugins.Arch.arch}}

        class Unrelated(InitPlugin):
            patch_name = "unrelated"
            order = 20

            def patch(self, ctx):
                return {"nvram": {"k": "v"}}

        with tempfile.TemporaryDirectory() as tmp:
            runner, patches, _ = run_plugins([Arch, Base, Unrelated], tmp)
        self.assertNotIn("base", patches)
        self.assertIn("unrelated", patches)
        self.assertEqual(runner.manifest["Arch"]["status"], "failed")
        self.assertEqual(runner.manifest["Base"]["status"], "failed")
        self.assertEqual(runner.manifest["Unrelated"]["status"], "ok")

    def test_nonfatal_failure_skips_plugin_only(self):
        class Broken(InitPlugin):
            patch_name = "broken"

            def patch(self, ctx):
                raise RuntimeError("boom")

        class Fine(InitPlugin):
            patch_name = "fine"

            def patch(self, ctx):
                return {"core": {"ok": True}}

        with tempfile.TemporaryDirectory() as tmp:
            runner, patches, _ = run_plugins([Broken, Fine], tmp)
        self.assertIn("fine", patches)
        self.assertNotIn("broken", patches)
        self.assertEqual(runner.manifest["Broken"]["status"], "failed")

    def test_render_order_is_order_attribute_not_completion(self):
        class Slow(InitPlugin):
            patch_name = "aaa_slow"
            order = 10

            def patch(self, ctx):
                time.sleep(0.2)
                return {"core": {"s": 1}}

        class Fast(InitPlugin):
            patch_name = "zzz_fast"
            order = 20

            def patch(self, ctx):
                return {"core": {"f": 1}}

        with tempfile.TemporaryDirectory() as tmp:
            _, patches, _ = run_plugins([Fast, Slow], tmp)
        self.assertEqual(list(patches), ["aaa_slow", "zzz_fast"])

    def test_consumes_patches_post_phase(self):
        class Producer(InitPlugin):
            patch_name = "prod"
            order = 10

            def patch(self, ctx):
                return {"static_files": {"/tmp/x": {"type": "dir"}}}

        class Consumer(InitPlugin):
            patch_name = "cons"
            order = 30
            consumes_patches = True

            def patch(self, ctx):
                snap = ctx.patches_snapshot()
                seen = [k for p in snap.values() for k in p[0].get("static_files", {})]
                return {"meta": {"saw": sorted(seen)}}

        with tempfile.TemporaryDirectory() as tmp:
            _, patches, ctx = run_plugins([Producer, Consumer], tmp)
        self.assertEqual(patches["cons"][0]["meta"]["saw"], ["/tmp/x"])
        # snapshot unavailable outside the post phase
        with self.assertRaises(RuntimeError):
            ctx.patches_snapshot()

    def test_disabled_patch_rendered_but_not_enabled(self):
        class Disabled(InitPlugin):
            patch_name = "dis"
            enabled = False

            def patch(self, ctx):
                return {"core": {"d": 1}}

        with tempfile.TemporaryDirectory() as tmp:
            runner, patches, ctx = run_plugins([Disabled], tmp)
            runner.render_patches(patches)
            rendered = sorted(p.name for p in ctx.patch_dir.iterdir())
        self.assertEqual(patches["dis"][1], False)
        self.assertEqual(rendered, ["dis.yaml"])

    def test_empty_patches_not_rendered(self):
        class Empty(InitPlugin):
            patch_name = "empty"

            def patch(self, ctx):
                return {"static_files": {}}

        with tempfile.TemporaryDirectory() as tmp:
            runner, patches, ctx = run_plugins([Empty], tmp)
            runner.render_patches(patches)
            rendered = list(ctx.patch_dir.iterdir()) if ctx.patch_dir.exists() else []
        # patch is tracked (historic behavior) but no file is written
        self.assertIn("empty", patches)
        self.assertEqual(rendered, [])

    def test_manifest_written(self):
        class P(InitPlugin):
            patch_name = "p"

            def patch(self, ctx):
                return {"core": {}}

            def static_result(self):
                return {"k": "v"}

        with tempfile.TemporaryDirectory() as tmp:
            _, _, ctx = run_plugins([P], tmp)
            self.assertTrue((ctx.static_dir / "manifest.yaml").exists())
            self.assertTrue((ctx.static_dir / "P.yaml").exists())


if __name__ == "__main__":
    unittest.main()
