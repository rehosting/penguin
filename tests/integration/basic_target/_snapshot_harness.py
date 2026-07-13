"""Shared machinery for basic_target snapshot re-attach smoke tests.

Every snapshot re-attach smoke drives the same two-run shape over the
busybox-only ``empty_fs`` project:

  1. SAVE run    : ``core.snapshot.save_at=readiness`` — the guest boots, a
                   stay-alive init keeps exercising some modeled resource, and a
                   snapshot is taken at readiness.
  2. RESTORE run : ``penguin run --from-snapshot`` — a fresh, cross-process boot
                   from that snapshot. The modeled resource's guest-side state
                   survives savevm; the smoke checks that the host side re-binds
                   so the resource keeps working (rather than hitting a dead
                   trampoline / empty callback map).

The smokes differ only in: an optional project-local probe plugin, the init
loop body, which plugins are enabled, extra ``core`` config, and the per-run
assertions. :class:`ReattachSmoke` bundles those; :func:`run_reattach_smoke`
and :func:`cli` drive one. See ``snapshots.py`` for the aggregate runner.
"""
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List

import click
import yaml

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("penguin.snapsmoke")

TEST_DIR = Path(__file__).resolve().parent
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")  # repo-root ./penguin
FS_DIR = TEST_DIR / "fs"
TAG = "boot"

# Penguin colorizes log output with ANSI escapes that can land mid-token (e.g.
# between a quote and a path); strip them before substring matching.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _run(cmd, **kw):
    logger.info(f"$ {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kw)


def penguin(image, *args, log):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    logger.info(f"$ {cmd}")
    try:
        subprocess.run(cmd, cwd=TEST_DIR, shell=True, check=True,
                       stdout=open(TEST_DIR / log, "w"), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        subprocess.run(["tail", "-n", "80", str(TEST_DIR / log)])
        raise


def build_empty_fs_project(image, arch, probe_srcs=()):
    """Init a fresh busybox-only empty_fs project and drop any project-local
    probe plugins into its plugins.d/. Returns the project path."""
    if (TEST_DIR / "projects").exists():
        shutil.rmtree(TEST_DIR / "projects")
    FS_DIR.mkdir(exist_ok=True)
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    _run(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox")
    _run(f"docker rm -v {cid}")
    _run(f"tar -czf {TEST_DIR}/empty_fs.tar.gz -C {FS_DIR} .")
    penguin(image, "init", f"{TEST_DIR}/empty_fs.tar.gz", "--force", log="snap_init.txt")
    project = TEST_DIR / "projects/empty_fs"
    if probe_srcs:
        (project / "plugins.d").mkdir(exist_ok=True)
        for src in probe_srcs:
            shutil.copy(TEST_DIR / src, project / "plugins.d" / Path(src).name)
    return project


def write_patch(project, kernel, snapshot, *, init_sh, plugins=None, extra_core=None):
    """Write patch_snap.yaml (stay-alive init + snapshot config + optional
    plugins/extra core) and append it to the project's config patches."""
    core = {"kernel": str(kernel), "timeout": 45, "snapshot": snapshot}
    if extra_core:
        core.update(extra_core)
    patch = {
        "env": {"igloo_init": "/snap_init.sh"},
        "core": core,
        "static_files": {"/snap_init.sh": {"type": "inline_file", "mode": 73,
                                           "contents": init_sh}},
    }
    if plugins:
        patch["plugins"] = {name: {} for name in plugins}
    (project / "patch_snap.yaml").write_text(yaml.dump(patch, sort_keys=False))
    cfg_path = project / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg.setdefault("patches", [])
    if "patch_snap.yaml" not in cfg["patches"]:
        cfg["patches"].append("patch_snap.yaml")
    cfg_path.write_text(yaml.dump(cfg, sort_keys=False))
    return str(cfg_path)


# --- assertion helpers usable by a smoke's check_save / check_restore -------

def read_count(project, run_idx, fname):
    """Integer contents of results/<run_idx>/<fname>, or 0 if absent."""
    f = project / "results" / str(run_idx) / fname
    return int(f.read_text().strip()) if f.exists() else 0


def read_text(project, run_idx, fname):
    """Stripped text contents of results/<run_idx>/<fname>, or None if absent."""
    f = project / "results" / str(run_idx) / fname
    return f.read_text().strip() if f.exists() else None


def log_contains(log_name, needle):
    """True if the (ANSI-stripped) run log contains needle."""
    text = _ANSI.sub("", (TEST_DIR / log_name).read_text(errors="replace"))
    return needle in text


@dataclass
class SmokeCtx:
    project: Path
    save_log: str
    restore_log: str


@dataclass
class ReattachSmoke:
    """One snapshot re-attach smoke. ``check_save``/``check_restore`` receive a
    :class:`SmokeCtx` and raise AssertionError on failure."""
    name: str
    init_sh: str
    check_save: Callable[[SmokeCtx], None]
    check_restore: Callable[[SmokeCtx], None]
    probe_srcs: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    extra_core: dict = field(default_factory=dict)


def run_reattach_smoke(spec: ReattachSmoke, image, arch, kernel):
    save_log = f"{spec.name}_save.txt"
    restore_log = f"{spec.name}_restore.txt"
    ctx = SmokeCtx(project=None, save_log=save_log, restore_log=restore_log)

    logger.info(f"[{spec.name}] build project")
    ctx.project = build_empty_fs_project(image, arch, spec.probe_srcs)

    logger.info(f"[{spec.name}] === SAVE run (save_at=readiness) ===")
    cfg = write_patch(ctx.project, kernel, {"save_at": "readiness", "tag": TAG},
                      init_sh=spec.init_sh, plugins=spec.plugins,
                      extra_core=spec.extra_core)
    penguin(image, "run", cfg, log=save_log)
    spec.check_save(ctx)

    logger.info(f"[{spec.name}] === RESTORE run (--from-snapshot) ===")
    cfg = write_patch(ctx.project, kernel, {"boot_from": TAG},
                      init_sh=spec.init_sh, plugins=spec.plugins,
                      extra_core=spec.extra_core)
    penguin(image, "run", cfg, "--from-snapshot", TAG, log=restore_log)
    spec.check_restore(ctx)
    logger.info(f"[{spec.name}] OK")


def cli(spec: ReattachSmoke):
    """Build a click command that runs this one smoke standalone."""
    @click.command()
    @click.option("--image", "-i", required=True)
    @click.option("--arch", "-a", default="armel")
    @click.option("--kernel", "-k", default="4.10")
    def main(image, arch, kernel):
        run_reattach_smoke(spec, image, arch, kernel)
    return main
