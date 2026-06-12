"""
Unit tests for penguin refresh internals: runner skip sets, user-edited patch
preservation, manifest carry-forward, and config reconciliation.
"""

import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml

from penguin.gen_config import _reconcile_config
from penguin.init_plugin import InitContext, InitPlugin
from penguin.init_runner import InitPluginRunner, load_manifest


def fresh_manager():
    from penguin.plugin_manager import IGLOOPluginManager

    if hasattr(IGLOOPluginManager, "instance"):
        del IGLOOPluginManager.instance
    return IGLOOPluginManager()


def make_ctx(tmp):
    tmp = Path(tmp)
    tar_path = tmp / "fs.tar.gz"
    if not tar_path.exists():
        with tarfile.open(tar_path, "w:gz") as t:
            info = tarfile.TarInfo("./etc")
            info.type = tarfile.DIRTYPE
            t.addfile(info)
    (tmp / "fs").mkdir(exist_ok=True)
    return InitContext(tar_path, tmp / "fs", tmp, tmp / "static", tmp / "static_patches")


class TestRunnerSkip(unittest.TestCase):
    def test_skipped_plugin_loaded_but_not_executed(self):
        ran = []

        class Shared(InitPlugin):
            def static_result(self):
                ran.append("Shared")
                return {"k": 1}

        class Consumer(InitPlugin):
            patch_name = "consumer"

            def patch(self, ctx):
                ran.append("Consumer")
                return {"core": {"x": 1}}

        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_ctx(tmp)
            runner = InitPluginRunner(
                [Shared, Consumer], ctx, manager=fresh_manager(), jobs=2,
                skip=["shared"],
            )
            patches = runner.run()
        self.assertIn("consumer", patches)
        self.assertEqual(ran, ["Consumer"])  # Shared loaded, never executed
        self.assertNotIn("Shared", runner.manifest)

    def test_manifest_carry_forward(self):
        class P(InitPlugin):
            patch_name = "p"

            def patch(self, ctx):
                return {"core": {}}

        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_ctx(tmp)
            runner = InitPluginRunner([P], ctx, manager=fresh_manager(), jobs=1)
            runner.run()
            runner.merge_previous_manifest({"Old": {"status": "ok", "order": 5}})
            runner._write_manifest()
            manifest = load_manifest(ctx.static_dir)
        self.assertIn("Old", manifest)
        self.assertIn("P", manifest)


class TestRenderOwnership(unittest.TestCase):
    def _run_once(self, tmp):
        class Owned(InitPlugin):
            patch_name = "owned"

            def patch(self, ctx):
                return {"core": {"v": 1}}

        ctx = make_ctx(tmp)
        runner = InitPluginRunner([Owned], ctx, manager=fresh_manager(), jobs=1)
        patches = runner.run()
        runner.render_patches(patches)
        return ctx, Owned

    def test_unedited_patch_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx, Owned = self._run_once(tmp)
            prev = load_manifest(ctx.static_dir)
            runner = InitPluginRunner([Owned], ctx, manager=fresh_manager(), jobs=1)
            patches = runner.run()
            outcome = runner.render_patches(patches, previous_manifest=prev)
            self.assertEqual(outcome["written"], ["owned"])
            self.assertEqual(outcome["preserved"], [])
            self.assertFalse((ctx.patch_dir / "owned.yaml.new").exists())

    def test_user_edited_patch_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx, Owned = self._run_once(tmp)
            prev = load_manifest(ctx.static_dir)
            target = ctx.patch_dir / "owned.yaml"
            target.write_text(target.read_text() + "# my tweak\n")
            edited = target.read_text()

            runner = InitPluginRunner([Owned], ctx, manager=fresh_manager(), jobs=1)
            patches = runner.run()
            outcome = runner.render_patches(patches, previous_manifest=prev)
            self.assertEqual(outcome["preserved"], ["owned"])
            self.assertEqual(target.read_text(), edited)  # untouched
            self.assertTrue((ctx.patch_dir / "owned.yaml.new").exists())


class TestReconcileConfig(unittest.TestCase):
    def _setup(self, tmp, patches_list):
        proj = Path(tmp)
        (proj / "static_patches").mkdir(exist_ok=True)
        config_path = proj / "config.yaml"
        config = {
            "core": {"arch": "armel"},
            "patches": list(patches_list),
            "init_plugins": {"A": {"enabled": True}},
        }
        for entry in patches_list:
            p = proj / entry
            if entry.startswith("static_patches/"):
                p.write_text("core: {}\n")
        config_path.write_text(yaml.dump(config, sort_keys=False))
        return proj, config_path, config

    def test_addition_inserted_by_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj, config_path, config = self._setup(
                tmp, ["static_patches/aa.yaml", "static_patches/zz.yaml"]
            )
            (proj / "static_patches" / "new.yaml").write_text("core: {}\n")
            manifest = {
                "PluginAA": {"patch_file": "aa.yaml", "order": 10},
                "PluginZZ": {"patch_file": "zz.yaml", "order": 300},
                "PluginNew": {"patch_file": "new.yaml", "order": 50},
            }
            _reconcile_config(
                config_path, config,
                patches={"new": ({"core": {}}, True)},
                rendered={"written": ["new"], "preserved": []},
                manifest=manifest,
                all_classes=[],
                skip=set(),
                recorded=config["init_plugins"],
            )
            updated = yaml.safe_load(config_path.read_text())
            self.assertEqual(
                updated["patches"],
                ["static_patches/aa.yaml", "static_patches/new.yaml", "static_patches/zz.yaml"],
            )
            self.assertTrue(config_path.with_suffix(".yaml.bak").exists())

    def test_dead_entries_removed_user_entries_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj, config_path, config = self._setup(
                tmp, ["static_patches/aa.yaml", "static_patches/gone.yaml", "mypatch.yaml"]
            )
            (proj / "static_patches" / "gone.yaml").unlink()
            _reconcile_config(
                config_path, config,
                patches={}, rendered={"written": [], "preserved": []},
                manifest={"PluginAA": {"patch_file": "aa.yaml", "order": 10}},
                all_classes=[], skip=set(), recorded=config["init_plugins"],
            )
            updated = yaml.safe_load(config_path.read_text())
        # user's mypatch.yaml entry untouched even though file doesn't exist
        self.assertEqual(updated["patches"], ["static_patches/aa.yaml", "mypatch.yaml"])

    def test_new_plugin_recorded(self):
        class B(InitPlugin):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            proj, config_path, config = self._setup(tmp, ["static_patches/aa.yaml"])
            _reconcile_config(
                config_path, config,
                patches={}, rendered={"written": [], "preserved": []},
                manifest={}, all_classes=[B], skip=set(),
                recorded=dict(config["init_plugins"]),
            )
            updated = yaml.safe_load(config_path.read_text())
        self.assertEqual(updated["init_plugins"]["B"], {"enabled": True})
        self.assertEqual(updated["init_plugins"]["A"], {"enabled": True})

    def test_no_changes_no_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj, config_path, config = self._setup(tmp, ["static_patches/aa.yaml"])
            before = config_path.read_text()
            _reconcile_config(
                config_path, config,
                patches={}, rendered={"written": [], "preserved": []},
                manifest={}, all_classes=[], skip=set(),
                recorded=dict(config["init_plugins"]),
            )
            self.assertEqual(config_path.read_text(), before)
            self.assertFalse(config_path.with_suffix(".yaml.bak").exists())


if __name__ == "__main__":
    unittest.main()
