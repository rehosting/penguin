#!/usr/bin/env python3
"""
Cross-process snapshot test exercising the *complex* restore paths:

  * vhost-user-vsock chardev reconnect into a freshly-launched QEMU (increment 3)
  * VPN bridge replay after restore (VPN.on_restore -> same host port)
  * the vsock data plane working again post-restore (HTTP through the bridge)

Shape:
  1. SAVE run  : boot the guest, start `busybox httpd` on :8000, wait for the
     bind to be bridged host-side, then fire the `snapshot_save` hypercall from
     inside the guest (when=now) and stay alive. The bridge is live at snapshot
     time, so it lands in the host-side sidecar.
  2. RESTORE   : `penguin run --from-snapshot boot` in a *fresh* process.
     -loadvm restores RAM+devices (httpd still running), the vsock device
     reconnects to a new vhost-device-vsock, VPN.on_restore replays the bridge
     on the SAME host port and re-publishes on_bind, and the bundled vpn_test
     plugin re-connects through the bridge -> proves the whole vsock path is
     alive again across processes.

Run via --pydev so the VPN/snapshot pyplugin changes apply without an image
rebuild:  python3 snapshot_vpn_test.py -i <image> [-a armel] [-k 4.10]
"""
import logging
from pathlib import Path
import click
import shutil
import subprocess
import yaml

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("penguin.snapvpn")

TEST_DIR = Path(__file__).resolve().parent
proj_dir = TEST_DIR
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")  # repo-root ./penguin
TAG = "boot"

# Guest init: serve the rootfs over httpd:8000 (so vpn_test's GET of
# /igloo/boot/preinit resolves, exactly as the netbinds test expects), wait for
# the bind to appear (8000 == 0x1F40 in /proc/net/tcp*), give the host a moment
# to bridge it, then take a snapshot from inside the guest and stay alive.
INIT_SH = """#!/igloo/utils/sh
/igloo/utils/busybox echo "snap-vpn init up"
/igloo/utils/busybox httpd -f -p 8000 -h / &
i=0
while [ $i -lt 25 ]; do
  if /igloo/utils/busybox grep -qi ":1F40" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
    /igloo/utils/busybox echo "snap-vpn httpd bound :8000"
    break
  fi
  /igloo/utils/busybox sleep 1
  i=$((i + 1))
done
# Let NetBinds -> VPN bridge the listener host-side before we capture.
/igloo/utils/busybox sleep 4
/igloo/utils/busybox echo "snap-vpn requesting snapshot"
/igloo/utils/send_hypercall snapshot_save boot now
while true; do /igloo/utils/busybox sleep 1; done
"""


def run_cmd(cmd, **kw):
    logger.info(f"$ {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kw)


def penguin(image, *args, log="snapvpn_log.txt"):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    logger.info(f"$ {cmd}")
    try:
        subprocess.run(cmd, cwd=proj_dir, shell=True, check=True,
                       stdout=open(proj_dir / log, "w"), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        subprocess.run(["tail", "-n", "150", str(proj_dir / log)])
        raise


def build_project(image, arch, slug):
    """Build a per-arch empty_fs project (named ``empty_fs_<slug>``)."""
    fs_dir = Path(proj_dir, f"fs_{slug}")
    if fs_dir.exists():
        shutil.rmtree(fs_dir)
    fs_dir.mkdir()
    (fs_dir / "bin").mkdir()
    # A real arch-bearing binary so `penguin init` can detect the architecture.
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    run_cmd(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs_dir}/busybox")
    run_cmd(f"docker rm -v {cid}")
    tarball = Path(TEST_DIR, f"empty_fs_{slug}.tar.gz")
    run_cmd(f"tar -czf {tarball} -C {fs_dir} .")
    penguin(image, "init", str(tarball), "--force", log=f"snapvpn_{slug}_init.txt")
    return Path(proj_dir, f"projects/empty_fs_{slug}")


def write_patch(project_path, kernel, snapshot, plugins=None):
    """Pin kernel, stay-alive httpd init, and snapshot config.

    ``plugins`` lets a caller control the non-default plugin set; the restore
    run deliberately omits vpn_test so that vpn_test running anyway proves the
    snapshot's *saved* config (which had it) was used, not this provided one.
    """
    patch = {
        "env": {"igloo_init": "/snap_init.sh"},
        "core": {"kernel": str(kernel), "timeout": 90, "snapshot": snapshot},
        "static_files": {
            "/snap_init.sh": {"type": "inline_file", "mode": 73, "contents": INIT_SH},
        },
        "plugins": plugins if plugins is not None else {"vpn_test": {}},
    }
    patch_path = project_path / "patch_snapvpn.yaml"
    with open(patch_path, "w") as f:
        yaml.dump(patch, f, sort_keys=False)

    cfg_path = project_path / "config.yaml"
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    patches = cfg.setdefault("patches", [])
    if "patch_snapvpn.yaml" not in patches:
        patches.append("patch_snapvpn.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump(cfg, f, sort_keys=False)
    return str(cfg_path)


def read_bridges(results_dir):
    """Parse vpn_bridges.csv -> list of dicts."""
    csv = results_dir / "vpn_bridges.csv"
    if not csv.is_file():
        return []
    rows = []
    lines = csv.read_text().strip().splitlines()
    for line in lines[1:]:
        parts = line.split(",")
        if len(parts) == 6:
            rows.append(dict(zip(
                ["procname", "ipvn", "domain", "guest_ip", "guest_port", "host_port"],
                parts)))
    return rows


def http_bridge_port(rows):
    for r in rows:
        if r["guest_port"] == "8000" and r["domain"] == "tcp":
            return int(r["host_port"])
    return None


def _save_run(image, arch, slug, kernel):
    """Shared SAVE phase: boot, bridge httpd, guest-driven snapshot. Returns
    (project, save_port)."""
    project = build_project(image, arch, slug)
    qcows = project / "qcows"

    logger.info(f"[{slug}] === SAVE run (guest-driven snapshot_save after bind) ===")
    # SAVE config carries vpn_test; the restore configs below deliberately omit it.
    config = write_patch(project, kernel, {"save_at": "manual", "tag": TAG},
                         plugins={"vpn_test": {}})
    penguin(image, "run", config, log=f"snapvpn_{slug}_save.txt")

    overlay = qcows / f"snapshot_{TAG}.qcow2"
    host_sidecar = qcows / f"snapshot_{TAG}.host.json"
    saved_cfg = qcows / f"snapshot_{TAG}.config.yaml"
    for p in (overlay, host_sidecar, saved_cfg):
        if not p.is_file():
            subprocess.run(["tail", "-n", "80", str(proj_dir / f"snapvpn_{slug}_save.txt")])
            raise AssertionError(f"expected snapshot artifact missing: {p}")
    logger.info(f"[{slug}] OK: overlay={overlay.stat().st_size}B, saved config persisted")
    if '"VPN"' not in host_sidecar.read_text():
        raise AssertionError("host sidecar did not capture VPN bridge state")
    if "vpn_test" not in saved_cfg.read_text():
        raise AssertionError("saved config did not capture the resolved plugin set")

    save_results = project / "results" / "latest"
    save_port = http_bridge_port(read_bridges(save_results))
    if save_port is None:
        raise AssertionError("SAVE run never bridged the guest httpd :8000")
    save_vpn_txt = save_results / "vpn_test.txt"
    if not (save_vpn_txt.is_file() and "successful" in save_vpn_txt.read_text()):
        raise AssertionError("SAVE run VPN data-plane check failed (pre-snapshot)")
    logger.info(f"[{slug}] OK: SAVE bridged httpd :8000 -> host :{save_port}, "
                "data plane works (pre-snapshot)")
    return project, save_port


def run_one(image, arch, kernel):
    """SAVE + cross-process RESTORE that DEFAULTS to the snapshot's saved config.

    The restore is launched with a config that *omits* vpn_test; vpn_test
    running anyway proves the snapshot's saved config (which had it) was loaded.
    """
    slug = f"{arch}_{kernel}"
    project, save_port = _save_run(image, arch, slug, kernel)

    logger.info(f"[{slug}] === RESTORE (default to saved config; provided omits vpn_test) ===")
    config = write_patch(project, kernel, {"boot_from": TAG, "tag": TAG}, plugins={})
    penguin(image, "run", config, "--from-snapshot", TAG,
            log=f"snapvpn_{slug}_restore.txt")
    rlog = (proj_dir / f"snapvpn_{slug}_restore.txt").read_text(errors="replace")

    if "Booting from snapshot" not in rlog:
        raise AssertionError("restore did not boot from the snapshot overlay")
    if "Loaded the config this snapshot was saved with" not in rlog:
        raise AssertionError("restore did not default to the snapshot's saved config")
    if "Re-establishing" not in rlog:
        raise AssertionError("VPN.on_restore did not replay bridges")
    logger.info(f"[{slug}] OK: restore loaded SAVED config and replayed bridges")

    restore_results = project / "results" / "latest"
    restore_port = http_bridge_port(read_bridges(restore_results))
    if restore_port is None:
        raise AssertionError("RESTORE run did not re-establish the httpd bridge")
    if restore_port != save_port:
        raise AssertionError(
            f"bridge host port not stable across restore: "
            f"save={save_port} restore={restore_port}")
    logger.info(f"[{slug}] OK: bridge replayed on SAME host port :{restore_port}")

    # vpn_test was NOT in the provided restore config — if it ran, the saved
    # config was used. It also exercises the restored vsock data plane end-to-end.
    restore_vpn_txt = restore_results / "vpn_test.txt"
    if not (restore_vpn_txt.is_file() and "successful" in restore_vpn_txt.read_text()):
        subprocess.run(["tail", "-n", "150", str(proj_dir / f"snapvpn_{slug}_restore.txt")])
        raise AssertionError(
            "vpn_test did not run/succeed after restore: saved config was not "
            "used, or the restored vsock data plane is broken")
    logger.info(f"[{slug}] OK: vpn_test ran from SAVED config + data plane works "
                "after cross-process restore")


def run_optout(image, arch, kernel):
    """SAVE + RESTORE with --ignore-saved-config: the provided config (which
    omits vpn_test) must win, so vpn_test must NOT run, while the snapshot
    still restores and VPN bridges still replay."""
    slug = f"{arch}_{kernel}_optout"
    project, save_port = _save_run(image, arch, slug, kernel)

    logger.info(f"[{slug}] === RESTORE --ignore-saved-config (provided config wins) ===")
    config = write_patch(project, kernel, {"boot_from": TAG, "tag": TAG}, plugins={})
    penguin(image, "run", config, "--from-snapshot", TAG, "--ignore-saved-config",
            log=f"snapvpn_{slug}_restore.txt")
    rlog = (proj_dir / f"snapvpn_{slug}_restore.txt").read_text(errors="replace")

    if "--ignore-saved-config" not in rlog:
        raise AssertionError("opt-out path did not log ignoring the saved config")
    if "Booting from snapshot" not in rlog or "Re-establishing" not in rlog:
        raise AssertionError("opt-out restore did not boot/replay as expected")

    restore_results = project / "results" / "latest"
    if (restore_results / "vpn_test.txt").is_file():
        raise AssertionError(
            "vpn_test ran despite --ignore-saved-config + provided config "
            "omitting it: the saved config was NOT correctly overridden")
    logger.info(f"[{slug}] OK: provided config honored (vpn_test absent), "
                "snapshot still restored + bridges replayed")


# Mirror tests/integration/test_target/test.py's known-good arch/kernel matrix.
DEFAULT_KERNELS = ["4.10", "6.13"]
DEFAULT_ARCHES = ["armel", "aarch64", "mipsel", "mipseb",
                  "mips64el", "mips64eb", "x86_64"]
# Arches that only boot under specific kernels.
NONDEFAULT_KERNEL_ARCHES = {"6.13": ["powerpc64", "loongarch64", "riscv64"]}


@click.command()
@click.option("--image", "-i", required=True)
@click.option("--arch", "-a", multiple=True, default=DEFAULT_ARCHES)
@click.option("--kernel", "-k", multiple=True, default=DEFAULT_KERNELS)
@click.option("--mode", "-m", type=click.Choice(["default", "optout"]), default="default",
              help="default: restore loads the snapshot's saved config. "
                   "optout: restore with --ignore-saved-config (provided config wins).")
def main(image, arch, kernel, mode):
    if proj_dir.joinpath("projects").exists():
        shutil.rmtree(proj_dir / "projects")
    run_fn = run_one if mode == "default" else run_optout

    allowed = set(DEFAULT_ARCHES)
    for arches in NONDEFAULT_KERNEL_ARCHES.values():
        allowed.update(arches)
    if any(a not in allowed for a in arch):
        raise SystemExit(f"Unsupported arch; allowed: {sorted(allowed)}")

    combos = []
    for k in kernel:
        for a in arch:
            restricted = {kern for kern, arches in NONDEFAULT_KERNEL_ARCHES.items()
                          if a in arches}
            if restricted and k not in restricted:
                continue
            combos.append((a, k))

    results = {}
    for a, k in combos:
        slug = f"{a}_{k}_{mode}"
        logger.info(f"########## {slug} ##########")
        try:
            run_fn(image, a, k)
            results[slug] = "PASS"
            logger.info(f"########## {slug}: PASS ##########")
        except Exception as e:
            results[slug] = f"FAIL: {e}"
            logger.error(f"########## {slug}: FAIL: {e} ##########")

    logger.info("================ SUMMARY ================")
    for slug, status in results.items():
        logger.info(f"  {slug:24} {status}")
    failed = [s for s, st in results.items() if not st.startswith("PASS")]
    if failed:
        raise SystemExit(f"{len(failed)}/{len(results)} combos FAILED: {failed}")
    logger.info(f"ALL {len(results)} combos PASSED")


if __name__ == "__main__":
    main()
