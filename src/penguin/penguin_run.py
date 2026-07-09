#!/usr/bin/env python3
import os
import json
import shutil
import shlex
import subprocess
import sys
import tempfile
import socket
from contextlib import contextmanager, closing
from pathlib import Path
from time import sleep
from penguin import getColoredLogger, plugins

from .common import yaml, style_config_for_dump
from yamlcore import CoreDumper, CoreLoader
from .defaults import default_plugin_path, vnc_password
from penguin.penguin_config import load_config
from .plugin_manager import ArgsBox
from .utils import hash_image_inputs, get_penguin_kernel_version, boot_fingerprint
from .q_config import load_q_config, ROOTFS
from .boot_env import partition_boot_env
from . import arch_registry


def _env_int(name: str, default: int, min_value: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as e:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from e
    if value < min_value:
        raise ValueError(f"{name} must be >= {min_value}, got {value}")
    return value


def _runtime_path(value) -> str | None:
    return str(value) if value is not None else None


def render_kernel_append(append_parts: list[str], env: dict, extra_cmdline: str = "") -> str:
    """Assemble the kernel ``-append`` string.

    ``append_parts`` is the original whitespace-split append (e.g. ``root=…``,
    ``console=…`` that QEMU/penguin already put there); ``env`` is the full
    ``conf["env"]``; ``extra_cmdline`` is ``core.kernel_cmdline_append`` (raw
    tokens the user wants on the cmdline verbatim).

    Only the *firmware-expected* portion of the env reaches the cmdline:
    :func:`penguin.boot_env.partition_boot_env` strips penguin's internal knobs
    (``ROOT_SHELL``, ``igloo_init``, ``IGLOO_*``, …), which are instead
    delivered over the portal as an early-boot env blob (see
    ``pyplugins/core/live_image.py`` + ``preinit.sh``). What remains on the
    cmdline is user/config ``env:`` entries that a vendor init may read from
    ``/proc/cmdline``.

    Layout is ``critical_args + config_args + extra_cmdline + rest_args``:
      * critical args (``root=``, ``init=``, ``panic=1``, any ``console=``, ``rw``)
        go first and cannot be clobbered by config;
      * then the firmware-expected env;
      * then ``core.kernel_cmdline_append`` tokens, verbatim and never diverted
        to the env blob (the explicit "put this on the kernel cmdline" channel);
      * then whatever else was originally on the append.

    Pure / side-effect free so it can be unit-tested and length-checked
    (see :func:`check_cmdline_size`) before it is handed to the kernel.
    """
    cmdline_env, _blob_env = partition_boot_env(env)
    config_args = [
        f"{k}" + (f"={v}" if v is not None else "") for k, v in cmdline_env.items()
    ]
    extra_args = shlex.split(extra_cmdline) if extra_cmdline else []

    root_str = f"root={ROOTFS}"
    critical_args = [root_str, "init=/igloo/boot/preinit", "panic=1"]
    critical_args.extend(part for part in append_parts if part.startswith("console="))
    if "rw" in append_parts:
        critical_args.append("rw")
    critical_seen = set(critical_args)
    rest_args = [part for part in append_parts if part not in critical_seen]
    return " ".join(critical_args + config_args + extra_args + rest_args)


def check_cmdline_size(cmdline: str, archend: str, logger) -> None:
    """Guard against silent kernel-cmdline truncation.

    The kernel copies at most ``COMMAND_LINE_SIZE - 1`` bytes of ``-append`` into
    ``boot_command_line`` (one byte reserved for the NUL terminator) and
    **silently drops the rest** — so an over-long cmdline quietly loses env
    knobs and produces a baffling rehost. We warn as we approach the cap and
    raise once we'd exceed it, rather than letting the kernel truncate in
    silence. See the per-arch ``command_line_size`` in :mod:`penguin.arch_registry`.
    """
    try:
        cap = arch_registry.spec(archend).command_line_size
    except KeyError:
        # Unknown arch: load_q_config would already have failed; nothing to check.
        return
    usable = cap - 1  # kernel reserves one byte for the trailing NUL
    length = len(cmdline)
    if length > usable:
        raise RuntimeError(
            f"Kernel cmdline is {length} bytes but {archend} kernels cap it at "
            f"COMMAND_LINE_SIZE={cap} ({usable} usable); the kernel would silently "
            "truncate it and drop boot env, breaking the rehost. Reduce the env "
            "passed on the cmdline (see the env-off-cmdline work). Cmdline was:\n"
            f"{cmdline}"
        )
    if length > usable * 9 // 10:
        logger.warning(
            "Kernel cmdline is %d/%d usable bytes for %s "
            "(COMMAND_LINE_SIZE=%d); approaching the limit at which the kernel "
            "silently truncates it.",
            length, usable, archend, cap,
        )


def _write_runtime_metadata(out_dir: str, metadata: dict) -> None:
    paths = []
    requested = os.environ.get("PENGUIN_RUNTIME_METADATA")
    if requested:
        paths.append(requested)
    paths.append(os.path.join(out_dir, "runtime.yaml"))

    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(metadata, f, default_flow_style=False)


# In-container path where the run publishes its serial-root-shell telnet port,
# so the image's `rootshell` helper reaches the actual (dynamically chosen)
# console port instead of a hardcoded guess.
ROOT_SHELL_PORT_FILE = "/tmp/.penguin_root_shell_port"


def _render_connect_script(container_name, telnet_port, root_shell, guest_cmd) -> str:
    """Render the results/<n>/connect.sh helper.

    connect.sh is the one-glance "get me into this device" script. It talks to
    the guest's *serial root shell* over the container's localhost
    (``<engine> exec <container> telnet localhost <telnet_port>``), which is why
    it never needs the container's IP address -- that is re-allocated per run,
    but localhost inside the container always reaches the console. The container
    image ships telnet even when the host lacks it.

    - no args  -> attach to the serial console.
    - ``connect.sh CMD...`` -> run CMD on the serial console and print its output
      (marker-delimited capture; distinct from the vsock ``penguin guest_cmd``).

    Requires ``core.root_shell: true`` (there is no serial console otherwise).
    """
    guest_cmd_hint = (
        'echo "  For scripted commands without a serial shell: '
        'penguin guest_cmd \\"<cmd>\\"" >&2'
        if guest_cmd else ':'
    )
    tmpl = r'''#!/bin/sh
# Connect to this penguin run's guest. GENERATED by penguin -- re-run the
# project to refresh it. Reaches the guest's serial root shell inside the
# container over localhost, so it does NOT depend on the (per-run) container IP.
set -u

CONTAINER="@@CONTAINER@@"
TELNET_PORT="@@PORT@@"
ROOT_SHELL="@@ROOT_SHELL@@"   # true|false

if [ "$ROOT_SHELL" != "true" ]; then
  echo "This run has no serial root shell (core.root_shell is off)." >&2
  echo "Re-run with 'core.root_shell: true' to use connect.sh." >&2
  @@GUEST_CMD_HINT@@
  exit 1
fi

ENGINE=""
for e in docker podman; do
  if command -v "$e" >/dev/null 2>&1; then ENGINE="$e"; break; fi
done
if [ -z "$ENGINE" ]; then
  echo "connect.sh needs docker or podman on PATH." >&2
  exit 1
fi

if [ -z "$CONTAINER" ] || ! "$ENGINE" ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "Container '$CONTAINER' is not running -- start the run first." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  # Interactive serial console.
  exec "$ENGINE" exec -it "$CONTAINER" telnet localhost "$TELNET_PORT"
fi

# Command mode: run "$*" over the serial console and print its output.
# The markers are printed by an assembled variable so they appear only in the
# command *output*, not in the console's echo of the typed line (which shows
# the split literals) -- that lets us slice out exactly the command's output.
CMD="$*"
TAG="$$"
printf 'B="__PENGUIN""_B_%s__"; E="__PENGUIN""_E_%s__"; echo "$B"; %s; echo "$E"\r\n' \
  "$TAG" "$TAG" "$CMD" \
  | "$ENGINE" exec -i "$CONTAINER" telnet localhost "$TELNET_PORT" 2>/dev/null \
  | awk -v b="__PENGUIN_B_${TAG}__" -v e="__PENGUIN_E_${TAG}__" '
      $0 ~ b { grab=1; next }
      $0 ~ e { grab=0 }
      grab   { print }'
'''
    return (tmpl
            .replace("@@CONTAINER@@", str(container_name or ""))
            .replace("@@PORT@@", str(telnet_port))
            .replace("@@ROOT_SHELL@@", "true" if root_shell else "false")
            .replace("@@GUEST_CMD_HINT@@", guest_cmd_hint))


def _write_connect_script(out_dir, container_name, telnet_port, root_shell,
                          guest_cmd) -> None:
    """Write results/<n>/connect.sh (executable) for this run."""
    path = os.path.join(out_dir, "connect.sh")
    with open(path, "w") as f:
        f.write(_render_connect_script(container_name, telnet_port, root_shell,
                                       guest_cmd))
    os.chmod(path, 0o755)


def _write_root_shell_port(telnet_port) -> None:
    """Publish the serial-root-shell telnet port to a fixed in-container path so
    the image's `rootshell` helper connects to the real (dynamically chosen)
    port. Only meaningful when core.root_shell is enabled."""
    with open(ROOT_SHELL_PORT_FILE, "w") as f:
        f.write(str(telnet_port) + "\n")


@contextmanager
def print_to_log(out, err):
    original_stdout = sys.stdout  # Save the original stdout
    original_stderr = sys.stderr  # Save the original stderr
    sys.stdout = open(out, "w")  # Redirect stdout to devnull
    sys.stderr = open(err, "w")  # Redirect stderr to devnull
    try:
        yield
    finally:
        sys.stdout.close()  # close the file
        sys.stderr.close()  # close the file
        sys.stdout = original_stdout  # Restore stdout
        sys.stderr = original_stderr  # Restore stderr


@contextmanager
def redirect_stdout_stderr(stdout_path, stderr_path):
    original_stdout_fd = sys.stdout.fileno()
    original_stderr_fd = sys.stderr.fileno()
    new_stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    new_stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)

    # Redirect stdout and stderr to the files
    os.dup2(new_stdout, original_stdout_fd)
    os.dup2(new_stderr, original_stderr_fd)

    try:
        yield
    finally:
        # Restore original stdout and stderr
        # XXX Check if we still have a valid stdout/stderr
        if sys.stdout is not None and sys.stderr is not None:
            os.dup2(original_stdout_fd, sys.stdout.fileno())
            os.dup2(original_stderr_fd, sys.stderr.fileno())

            # Close the file descriptors for the new stdout and stderr
            os.close(new_stdout)
            os.close(new_stderr)
        else:
            # Record that we failed to restore stdout/stderr, this goes into
            # the log file (not stdout/stderr)?
            print("stdout or stderr is None - cannot restore")


def run_config(
    proj_dir,
    conf_yaml,
    out_dir=None,
    logger=None,
    init=None,
    timeout=None,
    show_output=False,
    verbose=False,
    resolved_kernel=None,
):
    """
    conf_yaml a path to our config within proj_dir
    proj_dir contains config.yaml
    out_dir stores results and a copy of config.yaml
    """

    # Ensure config_yaml is directly in proj_dir
    # XXX did we remove this dependency correctly?
    # if os.path.dirname(conf_yaml) != proj_dir:
    #    raise ValueError(f"config_yaml must be in proj_dir: config directory {os.path.dirname(conf_yaml)} != {proj_dir}")

    if not os.path.isdir(proj_dir):
        raise ValueError(f"Project directory not found: {proj_dir}")

    if not os.path.isfile(conf_yaml):
        raise ValueError(f"Config file not found: {conf_yaml}")

    qcow_dir = os.path.join(proj_dir, "qcows")
    if not os.path.isdir(qcow_dir):
        os.makedirs(qcow_dir, exist_ok=True)

    if out_dir is None:
        out_dir = os.path.join(proj_dir, "output")
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    if logger is None:
        logger = getColoredLogger("penguin.run")

    # Image isn't in our config, but the path we use is a property
    # of configs files section - we'll hash it to get a path
    # Read input config and validate
    if resolved_kernel:
        logger.info(f"Using pre-resolved kernel: {resolved_kernel}")
        conf = load_config(proj_dir, conf_yaml, resolved_kernel=resolved_kernel, verbose=True)
    else:
        conf = load_config(proj_dir, conf_yaml, verbose=True)

    # `penguin run --from-snapshot <tag>` is sugar for core.snapshot.boot_from;
    # it crosses the subprocess boundary as an env var so we apply it here.
    boot_from_env = os.environ.get("PENGUIN_SNAPSHOT_BOOT_FROM")
    if boot_from_env:
        conf["core"].setdefault("snapshot", {})["boot_from"] = boot_from_env
        logger.info("Restoring from snapshot '%s' (--from-snapshot)", boot_from_env)

    # When restoring, default to the *exact config the snapshot was saved with*
    # (persisted next to the overlay at save time). The snapshot froze guest
    # state produced by that config, so reusing it is the coherent, low-surprise
    # default — running a restored guest under a different config is the kind of
    # mismatch the fingerprint exists to catch. A user can opt out with
    # `run --ignore-saved-config` to deliberately drive the restored guest with
    # the provided config instead (still fingerprint-gated).
    snap_cfg = conf["core"].get("snapshot") or {}
    boot_from = snap_cfg.get("boot_from")
    ignore_saved = bool(os.environ.get("PENGUIN_SNAPSHOT_IGNORE_SAVED_CONFIG"))
    if boot_from and not ignore_saved:
        snap_tag = snap_cfg.get("tag", "boot")
        saved_cfg_path = os.path.join(proj_dir, "qcows",
                                      f"snapshot_{snap_tag}.config.yaml")
        if os.path.isfile(saved_cfg_path):
            with open(saved_cfg_path) as f:
                saved_conf = yaml.load(f, Loader=CoreLoader)
            # Carry the restore intent onto the saved config.
            saved_conf.setdefault("core", {}).setdefault("snapshot", {})
            saved_conf["core"]["snapshot"]["boot_from"] = boot_from
            saved_conf["core"]["snapshot"]["tag"] = snap_tag
            conf = saved_conf
            logger.info("Loaded the config this snapshot was saved with (%s); "
                        "pass --ignore-saved-config to override", saved_cfg_path)
        else:
            logger.warning("Snapshot '%s' has no saved config (%s); restoring "
                           "with the provided config", snap_tag, saved_cfg_path)
    elif boot_from and ignore_saved:
        logger.info("--ignore-saved-config: restoring with the provided config "
                    "rather than the snapshot's saved config")

    pkversion = get_penguin_kernel_version(conf)

    if timeout is not None:
        # A --timeout argument overrides the config's core.timeout
        conf["core"]["timeout"] = timeout

    if "igloo_init" not in conf["env"]:
        if init:
            conf["env"]["igloo_init"] = init
        else:
            try:
                with open(
                    os.path.join(*[os.path.dirname(conf_yaml), "base", "env.yaml"]), "r"
                ) as f:
                    # Read yaml file, get 'igloo_init' key
                    inits = yaml.safe_load(f)["igloo_init"]
            except FileNotFoundError:
                inits = []
            raise RuntimeError(
                f"No init binary is specified in configuration, set one in config's env section as igloo_init. Static analysis identified the following: {inits}"
            )
    if conf["env"]["igloo_init"] == "UNKNOWN_FIX_ME":
        logger.error("No init binary specified in config, and static analysis did not identify any candidates")
        raise RuntimeError(
            "env.igloo_init in configuration is set to UNKNOWN_FIX_ME. This indicates that we could not find the correct init binary. Please determine the correct init binary and update the config value in static_files/base.yaml"
        )

    archend = conf["core"]["arch"]
    q_config = load_q_config(conf)
    config_fs = os.path.join(proj_dir, conf["core"]["fs"])  # Path to tar filesystem
    plugin_path = (
        conf["core"]["plugin_path"]
        if "plugin_path" in conf["core"]
        else default_plugin_path
    )
    # static_files = conf['static_files'] if 'static_files' in conf else {} # FS shims
    conf_plugins = conf["plugins"]  # {plugin_name: {enabled: False, other... opts}}

    if isinstance(conf_plugins, list):
        logger.info("Warning, expected dict of plugins, got list")
        conf_plugins = {plugin: {} for plugin in conf_plugins}

    if not os.path.isfile(conf["core"]["kernel"]):
        raise ValueError(f"Kernel file invalid: {conf['core']['kernel']}")

    if not os.path.isfile(config_fs):
        raise ValueError(f"Missing filesystem archive in base directory: {config_fs}")
    h = hash_image_inputs(proj_dir, conf)
    image_filename = f"image_{h}.qcow2"
    config_image = os.path.join(qcow_dir, image_filename)

    # Make sure we have a clean out_dir every time. XXX should we raise an error here instead?
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    # Make sure we have a qcows dir
    if not os.path.isdir(qcow_dir):
        os.makedirs(qcow_dir, exist_ok=True)

    lock_file = os.path.join(qcow_dir, f".{image_filename}.lock")
    while os.path.isfile(lock_file):
        # Stall while there's a lock
        logger.info("stalling on lock")
        sleep(1)

    # If image isn't in our out_dir already, generate it
    if not os.path.isfile(config_image):
        open(lock_file, "a").close()  # create lock file

        try:
            from .gen_image import make_image
            make_image(config_fs, config_image, qcow_dir, conf)
        except Exception as e:
            logger.error(
                f"Failed to make image: for {config_fs} / {os.path.dirname(qcow_dir)}"
            )
            logger.error(e, exc_info=True)
            if os.path.isfile(os.path.join(qcow_dir, image_filename)):
                os.remove(os.path.join(qcow_dir, image_filename))
            raise e
        finally:
            # Always remove lock file, even if we failed to make the image
            if os.path.isfile(lock_file):
                os.remove(lock_file)

        # We expect to have the image now
        if not os.path.isfile(config_image):
            raise ValueError(f"GenImage failed to produce {config_image}")

        # If the file is empty, something has gone wrong - delete it and abort
        if os.path.getsize(config_image) == 0:
            os.remove(config_image)
            raise ValueError(f"GenImage produced empty image file: {config_image}")

    # We have to set up vsock args for qemu CLI arguments if we're using the vpn. We
    # special case this here and add the arguments to the plugin later
    vpn_enabled = conf_plugins.get("vpn", {"enabled": False}).get("enabled", True)
    vsock_args = []
    vpn_args = {}

    if vpn_enabled:
        vpn_tmpdir = tempfile.TemporaryDirectory()
        path = Path(vpn_tmpdir.name)
        CID = _env_int("PENGUIN_VSOCK_CID", 4, min_value=3)
        socket_path = path / "socket"
        uds_path = path / "vsocket"
        mem_path = path / "mem_path"

        vpn_args = {"socket_path": socket_path, "uds_path": uds_path, "CID": CID}
        conf["env"]["CID"] = CID

        vsock_args = [
            "-object",
            f'memory-backend-file,id=mem0,mem-path={mem_path},size={conf["core"]["mem"]},share=on',
            "-chardev",
            f"socket,id=char0,path={socket_path}",
            "-device",
            "vhost-user-vsock-pci,chardev=char0",
        ]

        if "mips" not in q_config["arch"]:   # and "ppc" not in q_config["arch"]:
            vsock_args.extend(["-numa", "node,memdev=mem0"])

    append = f"root={ROOTFS} init=/igloo/boot/preinit console=ttyS0 rw panic=1"  # Required
    if "kernel_quiet" in conf["core"] and conf["core"]["kernel_quiet"]:
        append += " quiet"

    append += " rootfstype=ext4 norandmaps nokaslr"  # Nice to have
    append += (
        " clocksource=jiffies nohz_full nohz=off no_timer_check"  # Improve determinism?
    )

    if pkversion < (6, 13):
        append += (
            " systemd.unified_cgroup_hierarchy=0"
            " systemd.legacy_systemd_cgroup_controller=1"
            " IGLOO_CGROUP_MODE=v1"
            " IGLOO_IPTABLES_BACKEND=legacy"
        )
    else:
        append += " IGLOO_CGROUP_MODE=v2 IGLOO_IPTABLES_BACKEND=nft"

    # acpi=off blocks x86 secondary-CPU enumeration via MADT; only safe on
    # single-CPU old kernels where PANDA needs it for determinism.
    if pkversion < (6, 13) and conf["core"].get("smp", 1) <= 1:
        append += " idle=poll acpi=off nosoftlockup "
    else:
        append += " idle=poll nosoftlockup "
    if vpn_enabled:
        append += f" CID={vpn_args['CID']} "

    _console = arch_registry.spec(archend).console_replacement
    if _console is not None:
        append = append.replace(_console[0], _console[1])

    telnet_port = find_free_port()
    if telnet_port is None:
        raise OSError("No available port found in the specified range")

    # Resolve snapshot (savevm/loadvm) configuration. Snapshotting is *active*
    # whenever save_at or boot_from is set (no separate enable flag). When active
    # we cannot use QEMU's throwaway `snapshot=on` overlay (its internal
    # snapshots are discarded on exit); instead we run on a persistent qcow2
    # overlay backed by the cached base image so savevm state survives and a
    # later run can boot from it. See core.snapshot in the config schema.
    snap_cfg = conf["core"].get("snapshot") or {}
    snapshot_save_at = snap_cfg.get("save_at")
    snapshot_boot_from = snap_cfg.get("boot_from")
    snapshot_enabled = (snapshot_save_at is not None) or (snapshot_boot_from is not None)
    drive_image = config_image

    if snapshot_enabled and snap_cfg.get("backend", "internal") == "file":
        # The standalone migration-file backend (migrate file:/-incoming with
        # mapped-ram) is designed but not yet implemented — it is async and
        # captures only RAM+devices, needing the disk overlay bundled alongside.
        # Until then, only the qcow2-internal backend is wired.
        raise NotImplementedError(
            "core.snapshot.backend='file' is not implemented yet; use 'internal'")

    if snapshot_enabled:
        snap_tag = snap_cfg.get("tag", "boot")
        overlay_path = os.path.join(qcow_dir, f"snapshot_{snap_tag}.qcow2")
        meta_path = os.path.join(qcow_dir, f"snapshot_{snap_tag}.meta.json")
        # A snapshot freezes guest state produced by the boot-frozen inputs; a
        # restore is only coherent if those inputs still match.
        fingerprint = boot_fingerprint(proj_dir, conf)
        if snapshot_boot_from:
            # Restore mode: the overlay must already hold the named snapshot.
            if not os.path.isfile(overlay_path):
                raise ValueError(
                    f"snapshot.boot_from='{snapshot_boot_from}' requested but "
                    f"overlay {overlay_path} does not exist; run with "
                    f"snapshot.save_at set first to create it")
            saved_fp = None
            if os.path.isfile(meta_path):
                with open(meta_path) as f:
                    saved_fp = json.load(f).get("fingerprint")
            if saved_fp is None:
                logger.warning(
                    "Snapshot '%s' has no fingerprint metadata; cannot verify "
                    "it matches the current config — restoring anyway", snap_tag)
            elif saved_fp != fingerprint:
                raise ValueError(
                    f"snapshot.boot_from='{snapshot_boot_from}': the boot-frozen "
                    f"config (kernel, env/append, arch, machine, nvram, netdevs, "
                    f"pseudofile set) changed since this snapshot was saved, so "
                    f"the restored guest state would be incoherent. Re-create the "
                    f"snapshot (snapshot.save_at) or revert the config. "
                    f"(saved {saved_fp[:12]} != current {fingerprint[:12]})")
            logger.info("Booting from snapshot '%s' in %s",
                        snapshot_boot_from, overlay_path)
        else:
            # Save mode: start from a fresh overlay over the cached base so
            # the saved snapshot reflects a clean boot, and record the
            # boot-fingerprint so a later restore can verify it.
            if os.path.isfile(overlay_path):
                os.remove(overlay_path)
            subprocess.check_output([
                "qemu-img", "create", "-f", "qcow2",
                "-b", config_image, "-F", "qcow2", overlay_path,
            ])
            with open(meta_path, "w") as f:
                json.dump({"tag": snap_tag, "fingerprint": fingerprint}, f)
            # Persist the exact resolved config this snapshot is being saved
            # with, so a restore can default to it (see the boot_from handling
            # above). Travels with the overlay in qcows/ and is bundled by
            # `pack --with-snapshot`.
            saved_cfg_path = os.path.join(qcow_dir, f"snapshot_{snap_tag}.config.yaml")
            with open(saved_cfg_path, "w") as f:
                # Same rendering as dump_config (octal modes, hex addresses);
                # read back with CoreLoader on restore. The resolved conf is
                # already validated, so we don't re-validate here.
                yaml.dump(style_config_for_dump(conf), f, sort_keys=False,
                          default_flow_style=False, width=None, Dumper=CoreDumper)
            logger.info("Created snapshot overlay %s over %s (fingerprint %s)",
                        overlay_path, config_image, fingerprint[:12])
        drive_image = overlay_path

    # If core config specifes immutable: False we'll run without snapshot.
    # Snapshotting forces a persistent (non-throwaway) overlay regardless.
    no_snapshot_drive = f"file={drive_image},id=hd0"
    snapshot_drive = no_snapshot_drive + ",cache=unsafe,snapshot=on"
    if snapshot_enabled:
        drive = no_snapshot_drive + ",cache=unsafe"
    else:
        drive = snapshot_drive if conf["core"].get("immutable", True) else no_snapshot_drive
    if vpn_enabled and ("mips" in q_config["arch"]):  # and "ppc" not in q_config["arch"]):
        machine_args = q_config["qemu_machine"]+",memory-backend=mem0"
    else:
        machine_args = q_config["qemu_machine"]

    if q_config["arch"] == "arm" and pkversion <= (4, 19):
        machine_args += ",highmem=off,highmem-ecam=off,highmem-mmio=off"

    if q_config["arch"] in ["arm", "aarch64"]:
        drive += ",if=none"
        drive_args = [
            "-device", "virtio-blk-device,drive=hd0",
            "-drive", drive,
        ]
    elif "mips" in q_config["arch"]:
        drive += ",if=none"
        drive_args = [
            "-device", "virtio-blk-pci,drive=hd0,disable-modern=on,disable-legacy=off",
            "-drive", drive,
        ]
    else:
        drive += ",if=virtio"
        drive_args = [
            "-drive", drive,
        ]

    args = [
        "-M",
        machine_args,
        "-kernel",
        conf["core"]["kernel"],
        "-append",
        append,
        # "-device", "virtio-rng-pci",
        *drive_args,
    ]
    if q_config["arch"] == "loongarch64":
        args += ["-bios", "/usr/local/share/qemu/edk2-loongarch64-code.fd"]

    args += ["-no-reboot"]

    if snapshot_enabled and snapshot_boot_from:
        # Restore device + RAM state from the named internal snapshot at boot.
        args += ["-loadvm", snapshot_boot_from]

    if conf["core"].get("network", False):
        # Connect guest to network if specified
        if archend == "armel":
            logger.warning("UNTESTED network flags for arm")
        args.extend(
            ["-netdev", "user,id=user.0", "-device", "virtio-net,netdev=user.0"]
        )

    graphics = conf["core"].get("graphics", False)
    show_output_bool = conf["core"].get("show_output", False)
    root_shell_enabled = conf["core"].get("root_shell", False)

    _write_runtime_metadata(out_dir, {
        "pid": os.getpid(),
        "project": proj_dir,
        "config": conf_yaml,
        "output": out_dir,
        "container_ip": os.environ.get("CONTAINER_IP"),
        "container_name": os.environ.get("CONTAINER_NAME"),
        "root_shell": root_shell_enabled,
        "guest_cmd": conf["core"].get("guest_cmd", False),
        "telnet_port": telnet_port,
        "telnet_port_base": os.environ.get("PENGUIN_TELNET_PORT_BASE"),
        "telnet_port_range": os.environ.get("PENGUIN_TELNET_PORT_RANGE"),
        "vpn_enabled": vpn_enabled,
        "vsock_cid": vpn_args.get("CID"),
        "vsock_socket_path": _runtime_path(vpn_args.get("socket_path")),
        "vsock_uds_path": _runtime_path(vpn_args.get("uds_path")),
    })

    # A one-glance "get into the guest" helper next to runtime.yaml. Reaches the
    # serial root shell via the container's localhost (IP-agnostic); see
    # _render_connect_script.
    _write_connect_script(
        out_dir,
        os.environ.get("CONTAINER_NAME"),
        telnet_port,
        root_shell_enabled,
        conf["core"].get("guest_cmd", False),
    )
    if root_shell_enabled:
        # Let the image's `rootshell` helper find the real console port.
        _write_root_shell_port(telnet_port)

    if graphics and show_output_bool:
        logger.warning("Graphics and show_output are mutually exclusive. Using graphics")
        conf["core"]["show_output"] = False
        show_output_bool = False

    if graphics and root_shell_enabled:
        logger.warning("Graphics and root_shell are mutually exclusive. Using graphics")
        root_shell = False
        conf["core"]["root_shell"] = False

    root_shell = []
    if root_shell_enabled:
        root_shell = [
            "-serial",
            "telnet:0.0.0.0:" + str(telnet_port) + ",server,nowait",
        ]  # ttyS1: root shell

    if show_output_bool and not graphics:
        logger.info("Logging console output to stdout")
        console_out = [
                "-chardev", f"stdio,id=char1,logfile={out_dir}/console.log,signal=on",
                "-serial", "chardev:char1",
                "-display", "none",
                ]
    elif graphics:
        logger.info(f"Setting VNC password to {vnc_password}")
        args += [
            "-object", f'secret,id=vncpasswd,data={vnc_password}',
            "-vnc",    "0.0.0.0:0,password-secret=vncpasswd",
            "-device", "virtio-gpu",
            "-device", "virtio-keyboard-pci",
            "-device", "virtio-mouse-pci",
            "-k", "en-us",
        ]
        console_out = []
        # if we do not set show_output it breaks our logging
    else:
        logger.info(f"Logging console output to {out_dir}/console.log")
        console_out = [
            "-serial",
            f"file:{out_dir}/console.log",
            "-monitor",
            "null",
            "-display", "none",
        ]  # ttyS0: guest console output

    # Shared directory and core dumps both ride a single 9p mount at
    # /igloo/shared, so provision it when either is configured. shared_dir is
    # normalized to a dict (or absent) by the config schema.
    shared_dir_conf = conf["core"].get("shared_dir")
    if shared_dir_conf or conf["core"].get("core_dumps"):
        host_path = shared_dir_conf.get("host_path") if isinstance(shared_dir_conf, dict) else None
        if host_path:
            shared_dir = host_path
        else:
            rel = shared_dir_conf.get("path", "shared") if isinstance(shared_dir_conf, dict) else "shared"
            shared_dir = os.path.join(out_dir, rel.lstrip("/"))
        os.makedirs(shared_dir, exist_ok=True)
        args += [
            "-virtfs",
            ",".join(
                (
                    "local",
                    f"path={shared_dir}",
                    "mount_tag=igloo_shared_dir",
                    "security_model=mapped-xattr",
                )
            ),
        ]

    args = args + console_out + root_shell

    if conf["core"].get("cpu", None):
        args += ["-cpu", conf["core"]["cpu"]]
    elif q_config.get("cpu", None):
        args += ["-cpu", q_config["cpu"]]

    # ############ Reduce determinism ##############

    execution_mode = conf["core"].get("execution_mode", "qemu")
    if execution_mode == "panda":
        raise RuntimeError(
            "PANDA execution mode is no longer supported by this branch. "
            "Use core.execution_mode: qemu or kvm."
        )

    # Fixed clock time.
    args = args + ["-rtc", "base=2023-01-01T00:00:00"]

    # Add vsock args
    args += vsock_args

    if execution_mode == "kvm":
        args += ["-accel", "kvm"]

    # Add args from config
    args += shlex.split(conf["core"].get("extra_qemu_args", ""))

    # If we have network args
    if network := conf.get("network", None):
        if "external" in network:
            mac = network["external"]["mac"]
            arg_str = f"-netdev user,id=ext -device virtio-net-pci,netdev=ext,mac={mac}"
            # Supported in future versions of QEMU
            # if net := network["external"].get("net", None):
            #     arg_str += ",net={net}"
            if network["external"].get("pcap"):
                pcap_path = os.path.join(out_dir, "ext.pcap")
                logger.info(f"Logging external traffic to {pcap_path}")
                arg_str += f" -object filter-dump,id=fext,netdev=ext,file={pcap_path}"
            args += shlex.split(arg_str)
            conf["env"]["IGLOO_EXT_MAC"] = mac
            logger.info(f"Starting external network on interface {mac}. Host is available on 10.0.2.2")

    if conf['core']['smp'] > 1:
        args += ["-smp", str(conf['core']['smp'])]

    # Disable audio (allegedly speeds up emulation by avoiding running another thread)
    os.environ["QEMU_AUDIO_DRV"] = "none"

    # Setup PANDA or KVM. Do not let it print.
    # qemu stdout/stderr default to out_dir's parent. Compose runs override
    # this via PENGUIN_QEMU_LOG_DIR so logs land in the per-device meta dir
    # rather than alongside other devices' out_dirs.
    log_dir = os.environ.get("PENGUIN_QEMU_LOG_DIR") or os.path.dirname(out_dir)
    os.makedirs(log_dir, exist_ok=True)
    stdout_path = os.path.join(log_dir, "qemu_stdout.txt")
    stderr_path = os.path.join(log_dir, "qemu_stderr.txt")

    sys.path.append("/pyplugins")
    from compat.qemu_compat import KVMQemu

    with print_to_log(stdout_path, stderr_path):
        qemu_mode = "kvm" if execution_mode == "kvm" else "system"
        qemu_lib_arch = q_config["arch"] if qemu_mode == "kvm" else archend
        logger.info("Using %s execution mode for %s", execution_mode, qemu_lib_arch)
        panda = KVMQemu.from_installation(qemu_mode, qemu_lib_arch)
        args = ["-L", "/usr/local/share/qemu/"] + args
        panda.panda_args = [f"qemu-system-{q_config['arch']}", "-m", conf["core"]["mem"]] + args

    # Plugins names are given out of order (by nature of yaml and sorting),
    # but plugins may have dependencies. We sort by dependencies
    # to get a safe load order.

    # As we load each plugin, it may mutate conf. We only really allow
    # changes to conf['env'] as a plugin (pseudofiles) might want to
    # read in a config and update boot args based on them

    # Set umask so that plugin created files are o+rw. Since we're in a container
    # and we want host user to be able to read (and delete)
    os.umask(0o001)
    os.makedirs(out_dir, exist_ok=True)

    logger.info("Loading plugins")
    args = {
        "plugins": conf_plugins,
        "conf": ArgsBox(conf),
        "proj_name": os.path.basename(proj_dir).replace("host_", ""),
        "proj_dir": proj_dir,
        "plugin_path": plugin_path,
        "fs": config_fs,
        "fw": config_image,
        "outdir": out_dir,
        "verbose": verbose,
        "telnet_port": telnet_port,
    }
    args.update(vpn_args)

    plugins.initialize(panda, args)
    if execution_mode in {"qemu", "kvm"}:
        from apis.hypercall import Hypercall
        plugins.load(Hypercall, args)
    plugins.load_plugins(conf_plugins)

    # When booting from a snapshot, rehydrate host-side plugin state now that
    # all plugins are loaded but before the guest resumes (panda.run below).
    if snapshot_enabled and snapshot_boot_from:
        snap_plugin = plugins.get_plugin_by_name("Snapshot")
        if snap_plugin is not None:
            snap_plugin.dispatch_restore()

    # XXX HACK: normally panda args are set at the constructor. But we want to load
    # our plugins first and these need a handle to panda. So after we've constructed
    # our panda object, we'll directly insert our args into panda.panda_args in
    # the string entry after the "-append" argument which is a string list of
    # the kernel append args. We put our values at the start of this list

    # Find the argument after '-append' in the list and re-render it based on updated env
    append_idx = panda.panda_args.index("-append") + 1

    # We had some args originally (e.g., rootfs), not from our config, so we
    # need to keep those. render_kernel_append keeps the critical args
    # (root=/dev/vda, init=, panic=) first so config can't clobber them, then
    # the firmware-expected env, then the rest of the original append. Penguin's
    # internal knobs are stripped here and delivered over the portal instead
    # (LiveImage serves igloo_env.sh; preinit.sh sources it).
    append_parts = panda.panda_args[append_idx].split()
    rendered_append = render_kernel_append(
        append_parts, conf["env"], conf["core"].get("kernel_cmdline_append") or ""
    )
    # Never let the kernel silently truncate an over-long cmdline (MIPS caps it
    # at 256B); warn near the limit and fail loudly past it.
    check_cmdline_size(rendered_append, archend, logger)
    panda.panda_args[append_idx] = rendered_append

    @panda.cb_pre_shutdown
    def pre_shutdown():
        """
        Ensure pyplugins nicely clean up. Working around some panda bug
        """
        plugins.unload_all()

    while vpn_enabled and not os.path.exists(socket_path):
        logger.info(f"Waiting for socket {socket_path} to be created")
        sleep(0.1)

    logger.info("Launching rehosting")

    def _run():
        try:
            panda.run()
        except KeyboardInterrupt:
            logger.info("Stopping for ctrl-c")
        except Exception as e:
            logger.exception(e)
        finally:
            # think about this and maybe join on the thread
            plugins.unload_all()
            if vpn_enabled:
                shutil.rmtree(vpn_tmpdir.name, ignore_errors=True)

    if show_output:
        _run()
    else:
        with redirect_stdout_stderr(stdout_path, stderr_path):
            _run()


def _port_is_free(port: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            sock.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _random_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


def find_free_port():
    base = _env_int("PENGUIN_TELNET_PORT_BASE", 23, min_value=1)
    range_size = os.environ.get("PENGUIN_TELNET_PORT_RANGE")

    if range_size is not None:
        count = _env_int("PENGUIN_TELNET_PORT_RANGE", 1, min_value=1)
        for port in range(base, min(65535, base + count - 1) + 1):
            if _port_is_free(port):
                return port
        return _random_free_port()

    telnet_port = base
    while telnet_port <= 65535:
        if _port_is_free(telnet_port):
            return telnet_port
        telnet_port += 1000

    return _random_free_port()


def main():
    logger = getColoredLogger("penguin.runner")
    if verbose := any(x == "verbose" for x in sys.argv):
        logger.setLevel("DEBUG")

    if len(sys.argv) < 4:
        raise RuntimeError(f"USAGE {sys.argv[0]} [proj_dir] [config.yaml] [out_dir]")

    proj_dir = sys.argv[1]
    config = sys.argv[2]
    out_dir = sys.argv[3]

    # Two optional args: init and timeout
    init = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "None" else None
    timeout = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] != "None" else None
    show_output = sys.argv[6] == "show" if len(sys.argv) > 6 else False

    # Check for resolved kernel flag (internal use - passed from main process to subprocess)
    resolved_kernel = None
    if "--resolved-kernel" in sys.argv:
        idx = sys.argv.index("--resolved-kernel")
        if idx + 1 < len(sys.argv):
            resolved_kernel = sys.argv[idx + 1]

    logger.debug("penguin_run start:")
    logger.debug(f"proj_dir={proj_dir}")
    logger.debug(f"config={config}")
    logger.debug(f"out_dir={out_dir}")
    logger.debug(f"init={init}")
    logger.debug(f"timeout={timeout}")
    logger.debug(f"show_output={show_output}")
    logger.debug(f"resolved_kernel={resolved_kernel}")

    run_config(
        proj_dir, config, out_dir, logger, init, timeout, show_output, verbose=verbose, resolved_kernel=resolved_kernel
    )


if __name__ == "__main__":
    main()
