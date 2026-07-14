#!/usr/bin/env python3
"""
Validate the previously-unverified snapshot paths:

  pack   : `pack --with-snapshot` -> unpack into a *different* dir -> run
           --from-snapshot.  Exercises the portable bundle (overlay rebased to a
           relative backing + base image + sidecars + saved config) surviving
           relocation.
  socket : host-driven trigger.  A run stays alive (no guest-side save); a
           `snapshot save --when now` command sent over the RemoteCtrl unix
           socket (`_handle_snapshot` -> Snapshot.request_save) produces the
           snapshot, which a fresh `--from-snapshot` run then restores.
  syscall: safe-spot arming.  `snapshot save --when next_syscall` over the
           socket must ARM at the next syscall boundary (one-shot syscalls-API
           hook) rather than fire instantly, then fire and produce a restorable
           snapshot.
  guestcmd: guesthopper control plane post-restore.  After a cross-process
           `--from-snapshot` restore, the vsock chardev reconnects to a fresh
           vhost-device-vsock so `guest_cmd` (guesthopper over vsock) still
           reaches the restored guest.

Usage: python3 snapshot_paths_test.py -i <image> [-a armel] [-k 4.10]
                                       [-m pack|socket|syscall|guestcmd|all]
"""
import logging
import os
import subprocess
import shutil
import time
from pathlib import Path

import click
import yaml

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("penguin.snappaths")

TEST_DIR = Path(__file__).resolve().parent
proj_dir = TEST_DIR
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")
# Live-mount src/ and pyplugins/ so local edits apply without an image rebuild.
DEV = os.environ.get("SNAP_TEST_DEV", os.environ.get("SNAP_TEST_PYDEV", "1")) == "1"
WRAPPER_FLAGS = ["--dev"] if DEV else []

# httpd on :8000, wait for the bind, then guest-driven snapshot, then stay alive.
INIT_SELFSAVE = """#!/igloo/utils/sh
/igloo/utils/busybox echo "snap-init up"
/igloo/utils/busybox httpd -f -p 8000 -h / &
i=0
while [ $i -lt 25 ]; do
  /igloo/utils/busybox grep -qi ":1F40" /proc/net/tcp /proc/net/tcp6 2>/dev/null && break
  /igloo/utils/busybox sleep 1; i=$((i + 1))
done
/igloo/utils/busybox sleep 4
/igloo/utils/send_hypercall snapshot_save TAG now
while true; do /igloo/utils/busybox sleep 1; done
"""

# httpd on :8000 then just stay alive; the host triggers the snapshot via socket.
INIT_STAYALIVE = """#!/igloo/utils/sh
/igloo/utils/busybox echo "snap-init up"
/igloo/utils/busybox httpd -f -p 8000 -h / &
while true; do /igloo/utils/busybox sleep 1; done
"""


def run_cmd(cmd, **kw):
    logger.info(f"$ {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kw)


def penguin(image, *args, log, name=None, check=True):
    cmd = [PENGUIN, "--image", image] + WRAPPER_FLAGS
    if name:
        cmd += ["--name", name]
    cmd += list(args)
    logger.info("$ " + " ".join(cmd))
    with open(proj_dir / log, "w") as f:
        r = subprocess.run(cmd, cwd=proj_dir, stdout=f, stderr=subprocess.STDOUT)
    if check and r.returncode != 0:
        subprocess.run(["tail", "-n", "120", str(proj_dir / log)])
        raise RuntimeError(f"penguin {args[0]} failed ({r.returncode}); see {log}")
    return r.returncode


def docker_penguin(image, hostdir, *args, log):
    """Run the penguin CLI directly in a container with `hostdir` mounted at
    /work — deterministic paths for pure file ops (pack/unpack) without the
    wrapper's path-mapping heuristics."""
    cmd = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
           "-e", "HOME=/tmp", "-v", f"{hostdir}:/work", image, "penguin", *args]
    logger.info("$ " + " ".join(cmd))
    with open(proj_dir / log, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        subprocess.run(["tail", "-n", "80", str(proj_dir / log)])
        raise RuntimeError(f"docker penguin {args[0]} failed ({r.returncode}); see {log}")


def build_project(image, arch, slug):
    fs = Path(proj_dir, f"fs_{slug}")
    if fs.exists():
        shutil.rmtree(fs)
    fs.mkdir()
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    run_cmd(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs}/busybox")
    run_cmd(f"docker rm -v {cid}")
    tarball = Path(TEST_DIR, f"empty_fs_{slug}.tar.gz")
    run_cmd(f"tar -czf {tarball} -C {fs} .")
    penguin(image, "init", str(tarball), "--force", log=f"snappaths_{slug}_init.txt")
    return Path(proj_dir, f"projects/empty_fs_{slug}")


def write_config(project, kernel, snapshot, init_contents, plugins, core_extra=None):
    core = {"kernel": str(kernel), "timeout": 90, "snapshot": snapshot}
    if core_extra:
        core.update(core_extra)
    patch = {
        "env": {"igloo_init": "/snap_init.sh"},
        "core": core,
        "static_files": {
            "/snap_init.sh": {"type": "inline_file", "mode": 73, "contents": init_contents},
        },
        "plugins": plugins,
    }
    patch_path = project / "patch_snappaths.yaml"
    with open(patch_path, "w") as f:
        yaml.dump(patch, f, sort_keys=False)
    cfg_path = project / "config.yaml"
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    cfg.setdefault("patches", [])
    if "patch_snappaths.yaml" not in cfg["patches"]:
        cfg["patches"].append("patch_snappaths.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump(cfg, f, sort_keys=False)
    return str(cfg_path)


def read_bridges(results_dir):
    csv = results_dir / "vpn_bridges.csv"
    if not csv.is_file():
        return []
    rows = []
    for line in csv.read_text().strip().splitlines()[1:]:
        p = line.split(",")
        if len(p) == 6:
            rows.append(dict(zip(["procname", "ipvn", "domain", "guest_ip",
                                  "guest_port", "host_port"], p)))
    return rows


def assert_restore(image, config, tag, slug, extra=()):
    """Run --from-snapshot and assert it booted from the snapshot + replayed VPN."""
    penguin(image, "run", config, "--from-snapshot", tag, *extra,
            log=f"snappaths_{slug}_restore.txt", name=f"{slug}_r")
    rlog = (proj_dir / f"snappaths_{slug}_restore.txt").read_text(errors="replace")
    if "Booting from snapshot" not in rlog:
        raise AssertionError("restore did not boot from the snapshot overlay")
    if "Re-establishing" not in rlog:
        raise AssertionError("VPN.on_restore did not replay bridges")
    return rlog


# --------------------------------------------------------------------------
PLUGINS = {"vpn_test": {}, "remotectrl": {}}


def run_pack(image, arch, kernel):
    slug = f"{arch}_{kernel}_pack"
    project = build_project(image, arch, slug)
    qcows = project / "qcows"

    logger.info(f"[{slug}] SAVE run (guest-driven) to produce a snapshot")
    cfg = write_config(project, kernel, {"save_at": "manual", "tag": "boot"},
                       INIT_SELFSAVE.replace("TAG", "boot"), {"vpn_test": {}})
    penguin(image, "run", cfg, log=f"snappaths_{slug}_save.txt", name=f"{slug}_s")
    for n in ("snapshot_boot.qcow2", "snapshot_boot.meta.json",
              "snapshot_boot.host.json", "snapshot_boot.config.yaml"):
        if not (qcows / n).is_file():
            raise AssertionError(f"save did not produce {n}")
    logger.info(f"[{slug}] OK: snapshot + sidecars + saved config present")

    # --- pack --with-snapshot (run penguin directly; deterministic paths) --
    host_projects = str(proj_dir / "projects")
    bundle = Path(proj_dir, "projects", f"bundle_{slug}.tar.gz")
    if bundle.exists():
        bundle.unlink()
    docker_penguin(image, host_projects, "pack", f"/work/empty_fs_{slug}",
                   "-o", f"/work/{bundle.name}", "--with-snapshot", "boot",
                   log=f"snappaths_{slug}_pack.txt")
    if not bundle.is_file():
        raise AssertionError(f"pack did not produce {bundle}")
    listing = subprocess.check_output(f"tar -tzf {bundle}", shell=True).decode()
    need = ["qcows/snapshot_boot.qcow2", "qcows/snapshot_boot.config.yaml",
            "qcows/snapshot_boot.host.json", "config.yaml"]
    for n in need:
        if n not in listing:
            raise AssertionError(f"bundle missing {n}")
    if "qcows/image_" not in listing:
        raise AssertionError("bundle missing the base image (overlay backing)")
    logger.info(f"[{slug}] OK: portable bundle contains overlay+base+sidecars+config")

    # --- unpack into a DIFFERENT dir under projects/ ----------------------
    unpack_dir = Path(proj_dir, "projects", f"unpacked_{slug}")
    if unpack_dir.exists():
        shutil.rmtree(unpack_dir)
    docker_penguin(image, host_projects, "unpack", f"/work/{bundle.name}",
                   "-o", f"/work/unpacked_{slug}", "--force",
                   log=f"snappaths_{slug}_unpack.txt")
    unpacked = unpack_dir / f"empty_fs_{slug}"
    if not (unpacked / "config.yaml").is_file():
        # Fall back to whatever project dir the bundle laid down.
        cands = [p for p in unpack_dir.iterdir() if (p / "config.yaml").is_file()]
        if not cands:
            raise AssertionError(f"unpack produced no project under {unpack_dir}")
        unpacked = cands[0]
    logger.info(f"[{slug}] OK: unpacked to {unpacked}")

    # --- restore from the relocated bundle --------------------------------
    assert_restore(image, str(unpacked / "config.yaml"), "boot", slug)
    rb = read_bridges(unpacked / "results" / "latest")
    if not any(r["guest_port"] == "8000" for r in rb):
        raise AssertionError("relocated restore did not replay the httpd bridge")
    logger.info(f"[{slug}] OK: pack->unpack(elsewhere)->--from-snapshot RESTORED")


def _container_running(name):
    out = subprocess.run(["docker", "ps", "--filter", f"name=^{name}$",
                          "--format", "{{.Names}}"], capture_output=True, text=True)
    return name in out.stdout.split()


def _bg_run(image, cfg, cname, log, *extra,
            ready_markers=("RemoteCtrl: Listening", ":8000"), timeout_s=90):
    """Launch a `penguin run` in the background and wait until `ready_markers`
    all appear in its (host stdout) log. Returns the Popen so the caller can
    poke the container, then must clean it up."""
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    cmd = [PENGUIN, "--image", image, *WRAPPER_FLAGS, "--name", cname,
           "run", cfg, *extra]
    logger.info("$ (bg) " + " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=proj_dir, stdout=open(log, "w"),
                            stderr=subprocess.STDOUT)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        blob = Path(log).read_text(errors="replace")
        if all(m in blob for m in ready_markers):
            return proc
        if proc.poll() is not None:
            subprocess.run(["tail", "-n", "60", str(log)])
            raise AssertionError(f"run {cname} exited before ready; see {log}")
        time.sleep(2)
    raise AssertionError(f"run {cname} never reached {ready_markers}; see {log}")


def _kill_bg(cname, proc):
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()


def _find_in_container(cname, pattern):
    out = subprocess.run(
        ["docker", "exec", cname, "sh", "-c",
         f"find / -name {pattern} 2>/dev/null | head -1"],
        capture_output=True, text=True)
    return out.stdout.strip()


def run_syscall(image, arch, kernel):
    """Safe-spot arming: a host-driven `snapshot save --when next_syscall`
    must ARM at the next syscall boundary (not fire instantly), then fire and
    produce a restorable snapshot."""
    slug = f"{arch}_{kernel}_syscall"
    cname = f"{slug}_s"
    project = build_project(image, arch, slug)
    qcows = project / "qcows"
    cfg = write_config(project, kernel, {"save_at": "manual", "tag": "warm"},
                       INIT_STAYALIVE, PLUGINS)
    save_log = proj_dir / f"snappaths_{slug}_save.txt"
    proc = _bg_run(image, cfg, cname, save_log)
    try:
        time.sleep(5)  # let httpd bind + VPN bridge
        sock = _find_in_container(cname, "remotectrl.sock")
        if not sock:
            raise AssertionError("remotectrl.sock not found in container")
        logger.info(f"[{slug}] socket: {sock}; arming `snapshot save --when next_syscall`")
        out = subprocess.run(
            ["docker", "exec", cname, "snapshot", "save", "--tag", "warm",
             "--when", "next_syscall", "--sock", sock],
            capture_output=True, text=True)
        logger.info(f"[{slug}] cli_snapshot rc={out.returncode} out={out.stdout.strip()} "
                    f"err={out.stderr.strip()}")
        if out.returncode != 0:
            raise AssertionError("cli_snapshot --when next_syscall failed")

        # The save must ARM at the syscall boundary, then fire (the guest's
        # sleep loop hits syscalls constantly, so it fires within seconds).
        deadline = time.time() + 40
        while time.time() < deadline:
            if (qcows / "snapshot_warm.host.json").is_file():
                break
            time.sleep(2)
        else:
            subprocess.run(["tail", "-n", "60", str(save_log)])
            raise AssertionError("next_syscall-armed save never fired")
        blob = save_log.read_text(errors="replace")
        if "Armed snapshot" not in blob or "at syscall" not in blob:
            raise AssertionError("log does not show syscall-boundary arming")
        logger.info(f"[{slug}] OK: armed at syscall boundary, fired, snapshot saved")
    finally:
        _kill_bg(cname, proc)

    for n in ("snapshot_warm.qcow2", "snapshot_warm.config.yaml"):
        if not (qcows / n).is_file():
            raise AssertionError(f"syscall save missing {n}")
    assert_restore(image, cfg, "warm", slug)
    logger.info(f"[{slug}] OK: next_syscall snapshot RESTORED cross-process")


def run_guestcmd(image, arch, kernel):
    """guesthopper control plane post-restore: after a cross-process restore,
    the vsock chardev must reconnect to a fresh vhost-device-vsock so
    `guest_cmd` (guesthopper over vsock) still works against the restored
    guest."""
    slug = f"{arch}_{kernel}_guestcmd"
    project = build_project(image, arch, slug)
    qcows = project / "qcows"
    # guest_cmd: true starts guesthopper in the guest; it is captured in the
    # snapshot's frozen RAM and must talk over a reconnected vsock on restore.
    cfg = write_config(project, kernel, {"save_at": "manual", "tag": "warm"},
                       INIT_SELFSAVE.replace("TAG", "warm"), {"vpn_test": {}},
                       core_extra={"guest_cmd": True})

    logger.info(f"[{slug}] SAVE run (guest-driven) with guesthopper running")
    penguin(image, "run", cfg, log=f"snappaths_{slug}_save.txt", name=f"{slug}_s")
    for n in ("snapshot_warm.qcow2", "snapshot_warm.config.yaml"):
        if not (qcows / n).is_file():
            raise AssertionError(f"save did not produce {n}")
    logger.info(f"[{slug}] OK: snapshot saved with guesthopper in frozen RAM")

    cname = f"{slug}_r"
    rlog = proj_dir / f"snappaths_{slug}_restore.txt"
    proc = _bg_run(image, cfg, cname, rlog, "--from-snapshot", "warm",
                   ready_markers=("Booting from snapshot", "Re-establishing"))
    try:
        # Wait for the host vsock UDS to come up, then let guesthopper's vsock
        # reconnect after the chardev re-attaches.
        deadline = time.time() + 40
        vsock = ""
        while time.time() < deadline:
            vsock = _find_in_container(cname, "vsocket")
            if vsock:
                break
            time.sleep(2)
        if not vsock:
            raise AssertionError("vsocket not found in restore container")
        logger.info(f"[{slug}] vsocket: {vsock}; running guest_cmd post-restore")
        time.sleep(5)

        marker = "HELLO_FROM_RESTORED_GUEST"
        out = subprocess.run(
            ["docker", "exec", cname, "guest_cmd", "--socket", vsock,
             f"/igloo/utils/busybox echo {marker}"],
            capture_output=True, text=True, timeout=60)
        logger.info(f"[{slug}] guest_cmd rc={out.returncode} out={out.stdout.strip()!r} "
                    f"err={out.stderr.strip()!r}")
        if out.returncode != 0 or marker not in out.stdout:
            raise AssertionError("guest_cmd failed post-restore (vsock did not "
                                 "reconnect to guesthopper)")
        logger.info(f"[{slug}] OK: guest_cmd works post-restore (vsock reconnected)")
    finally:
        _kill_bg(cname, proc)


def run_socket(image, arch, kernel):
    slug = f"{arch}_{kernel}_socket"
    cname = f"{slug}_s"
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    project = build_project(image, arch, slug)
    qcows = project / "qcows"

    cfg = write_config(project, kernel, {"save_at": "manual", "tag": "warm"},
                       INIT_STAYALIVE, PLUGINS)

    # Launch the run in the background so we can poke its socket while it's up.
    save_log = proj_dir / f"snappaths_{slug}_save.txt"
    cmd = [PENGUIN, "--image", image, *WRAPPER_FLAGS, "--name", cname, "run", cfg]
    logger.info("$ (bg) " + " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=proj_dir, stdout=open(save_log, "w"),
                            stderr=subprocess.STDOUT)
    try:
        # Wait for the guest to be up and RemoteCtrl listening.
        deadline = time.time() + 75
        ready = False
        while time.time() < deadline:
            blob = save_log.read_text(errors="replace")
            # RemoteCtrl socket up + the guest httpd bound & bridged (:8000 in
            # the VPN bind line). The init's "snap-init up" echo goes to the
            # guest console, not this (host stdout) log, so don't wait on it.
            if "RemoteCtrl: Listening" in blob and ":8000" in blob:
                ready = True
                break
            if proc.poll() is not None:
                raise AssertionError("run exited before becoming ready")
            time.sleep(2)
        if not ready:
            raise AssertionError("run never reached RemoteCtrl-listening + init-up")
        time.sleep(5)  # let httpd bind + VPN bridge

        # Find the socket inside the container and trigger a save over it.
        sock = subprocess.check_output(
            ["docker", "exec", cname, "sh", "-c",
             "find / -name remotectrl.sock 2>/dev/null | head -1"]).decode().strip()
        if not sock:
            raise AssertionError("remotectrl.sock not found in container")
        logger.info(f"[{slug}] socket: {sock}; sending `snapshot save`")
        out = subprocess.run(
            ["docker", "exec", cname, "snapshot", "save", "--tag", "warm",
             "--when", "now", "--sock", sock],
            capture_output=True, text=True)
        logger.info(f"[{slug}] cli_snapshot rc={out.returncode} out={out.stdout.strip()} "
                    f"err={out.stderr.strip()}")
        if out.returncode != 0:
            raise AssertionError("cli_snapshot save command failed")

        # Wait for the save to land in the overlay (host sidecar appears on save).
        deadline = time.time() + 40
        while time.time() < deadline:
            if (qcows / "snapshot_warm.host.json").is_file():
                break
            time.sleep(2)
        else:
            subprocess.run(["tail", "-n", "60", str(save_log)])
            raise AssertionError("socket-triggered save did not produce the snapshot")
        logger.info(f"[{slug}] OK: socket-triggered snapshot saved")
    finally:
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()

    for n in ("snapshot_warm.qcow2", "snapshot_warm.config.yaml"):
        if not (qcows / n).is_file():
            raise AssertionError(f"socket save missing {n}")

    # Confirm the socket-made snapshot is restorable.
    assert_restore(image, cfg, "warm", slug)
    logger.info(f"[{slug}] OK: socket-triggered snapshot RESTORED cross-process")


@click.command()
@click.option("--image", "-i", required=True)
@click.option("--arch", "-a", default="armel")
@click.option("--kernel", "-k", default="4.10")
@click.option("--mode", "-m",
              type=click.Choice(["pack", "socket", "syscall", "guestcmd", "all"]),
              default="all")
def main(image, arch, kernel, mode):
    if proj_dir.joinpath("projects").exists():
        shutil.rmtree(proj_dir / "projects")
    runners = {"pack": run_pack, "socket": run_socket,
               "syscall": run_syscall, "guestcmd": run_guestcmd}
    modes = list(runners) if mode == "all" else [mode]
    results = {}
    for m in modes:
        logger.info(f"########## {m} ({arch}/{kernel}) ##########")
        try:
            runners[m](image, arch, kernel)
            results[m] = "PASS"
        except Exception as e:
            results[m] = f"FAIL: {e}"
            logger.error(f"########## {m}: FAIL: {e} ##########")
    logger.info("================ SUMMARY ================")
    for m, st in results.items():
        logger.info(f"  {m:8} {st}")
    if any(not s.startswith("PASS") for s in results.values()):
        raise SystemExit(1)
    logger.info("ALL PASSED")


if __name__ == "__main__":
    main()
