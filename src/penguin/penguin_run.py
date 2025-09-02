#!/usr/bin/env python3
import os
import shutil
import shlex
import sys
import tempfile
import socket
from contextlib import contextmanager, closing
from pathlib import Path
from time import sleep
from glob import glob

from pandare2 import Panda

from penguin import getColoredLogger, plugins

from .common import yaml
from .defaults import default_plugin_path, vnc_password
from penguin.penguin_config import load_config
from .plugin_manager import ArgsBox
from .utils import hash_image_inputs


# Note armel is just panda-system-arm and mipseb is just panda-system-mips
ROOTFS = "/dev/vda"  # Common to all
qemu_configs = {
    "armel": {
        "qemu_machine": "virt",
        "arch": "arm",
        "kernel_whole": "zImage.armel",
    },
    "aarch64": {
        "qemu_machine": "virt",
        "kconf_group": "arm64",
        "cpu": "cortex-a57",
        "kernel_whole": "zImage.arm64",
    },
    "loongarch64": {
        "qemu_machine": "virt",
        "cpu": "la464",
        "kernel_fmt": "vmlinuz.efi"
    },
    "mipsel": {
        "qemu_machine": "malta",
    },
    "mipseb": {
        "qemu_machine": "malta",
        "arch": "mips",
        "kernel_whole": "vmlinux.mipseb"
    },
    "mips64el": {
        "qemu_machine": "malta",
        "cpu": "MIPS64R2-generic",
        "kernel_whole": "vmlinux.mips64el",
    },
    "mips64eb": {
        "qemu_machine": "malta",
        "arch": "mips64",
        "kernel_whole": "vmlinux.mips64eb",
        "cpu": "MIPS64R2-generic",
    },
    "powerpc64el": {
        "qemu_machine": "pseries",
        "arch": "ppc64",
        "cpu": "power9",
    },
    "powerpc64": {
        "qemu_machine": "pseries",
        "arch": "ppc64",
        "cpu": "power9",
        "kconf_group": "powerpc64",
        "kernel_whole": "vmlinux.powerpc64"
    },
    "riscv64": {
        "qemu_machine": "virt",
        "kernel_fmt": "Image",
    },
    "intel64": {
        "qemu_machine": "pc",
        "arch": "x86_64",
        "kconf_group": "x86_64",
        "kernel_fmt": "bzImage",
    },
}


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


def get_kernel(conf, q_config):
    if kernel := conf["core"].get("kernel", None):
        return kernel

    kernel_fmt = q_config.get("kernel_fmt", "vmlinux")
    kernel_whole = q_config.get('kernel_whole', f"vmlinux.{q_config['arch']}")
    options = [
        f"/igloo_static/kernels/*/{kernel_fmt}.{q_config['arch']}",
        f"/igloo_static/kernels/*/{kernel_whole}",
    ]
    for opt in options:
        kernels = glob(opt)
        if len(kernels) == 1:
            return kernels[0]
        elif len(kernels) != 0:
            raise ValueError(f"Multiple kernels found for {q_config['arch']}: {kernels}")
    if len(kernels) == 0:
        raise ValueError(f"Kernel not found for {q_config['arch']}")


def run_config(
    proj_dir,
    conf_yaml,
    out_dir=None,
    logger=None,
    init=None,
    timeout=None,
    show_output=False,
    verbose=False,
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
    conf = load_config(proj_dir, conf_yaml)

    if timeout is not None and conf.get("plugins", {}).get("core", None) is not None:
        # An arugument setting a timeout overrides the config's timeout
        conf["plugins"]["core"]["timeout"] = timeout

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

    archend = conf["core"]["arch"]
    try:
        q_config = qemu_configs[archend]
        q_config["kconf_group"] = q_config.get("kconf_group", archend)
        q_config["arch"] = q_config.get("arch", archend)
    except KeyError:
        raise ValueError(f"Unknown architecture: {archend}")
    conf["core"]["kernel"] = get_kernel(conf, q_config)
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

            make_image(config_fs, config_image, qcow_dir, proj_dir, conf_yaml)
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
        CID = 4  # We can use a constant CID with vhost-user-vsock
        socket_path = path / "socket"
        uds_path = path / "vsocket"
        mem_path = path / "mem_path"

        vpn_args = {"socket_path": socket_path, "uds_path": uds_path, "CID": CID}

        vsock_args = [
            "-object",
            f'memory-backend-file,id=mem0,mem-path={mem_path},size={conf["core"]["mem"]},share=on',
            "-chardev",
            f"socket,id=char0,reconnect=0,path={socket_path}",
            "-device",
            "vhost-user-vsock-pci,chardev=char0",
        ]

        if "mips" not in q_config["arch"]:   # and "ppc" not in q_config["arch"]:
            vsock_args.extend(["-numa", "node,memdev=mem0",])

    append = f"root={ROOTFS} init=/igloo/boot/preinit console=ttyS0 rw panic=1"  # Required
    if "kernel_quiet" in conf["core"] and conf["core"]["kernel_quiet"]:
        append += " quiet"

    append += " rootfstype=ext2 norandmaps nokaslr"  # Nice to have
    append += (
        " clocksource=jiffies nohz_full nohz=off no_timer_check"  # Improve determinism?
    )
    append += " idle=poll acpi=off nosoftlockup "  # Improve determinism?
    if vpn_enabled:
        append += f" CID={vpn_args['CID']} "

    if archend in ["armel", "aarch64"]:
        append = append.replace("console=ttyS0", "console=ttyAMA0")
    elif archend in ["powerpc", "powerpc64", "powerpc64el"]:
        append = append.replace("console=ttyS0", "console=hvc0 console=ttyS0")

    telnet_port = find_free_port()
    if telnet_port is None:
        raise OSError("No available port found in the specified range")

    # If core config specifes immutable: False we'll run without snapshot
    no_snapshot_drive = f"file={config_image},id=hd0"
    snapshot_drive = no_snapshot_drive + ",cache=unsafe,snapshot=on"
    drive = snapshot_drive if conf["core"].get("immutable", True) else no_snapshot_drive
    if vpn_enabled and ("mips" in q_config["arch"]):  # and "ppc" not in q_config["arch"]):
        machine_args = q_config["qemu_machine"]+",memory-backend=mem0"
    else:
        machine_args = q_config["qemu_machine"]
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
        args += ["-bios", "/igloo_static/loongarch64/bios-loong64-8.1.bin"]

    args += ["-no-reboot"]

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

    if "shared_dir" in conf["core"]:
        shared_dir = conf["core"]["shared_dir"]
        if shared_dir[0] == "/":
            shared_dir = shared_dir[1:]  # Ensure it's relative path to proj_dir
        shared_dir = os.path.join(out_dir, shared_dir)
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

    # Fixed clock time.
    args = args + ["-rtc", "base=2023-01-01T00:00:00"]

    # Add vsock args
    args += vsock_args

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

    # Setup PANDA. Do not let it print
    parent_outdir = os.path.dirname(out_dir)
    stdout_path = os.path.join(parent_outdir, "qemu_stdout.txt")
    stderr_path = os.path.join(parent_outdir, "qemu_stderr.txt")

    with print_to_log(stdout_path, stderr_path):
        logger.debug(f"Preparing PANDA args: {args}")
        logger.debug(f"Architecture: {q_config['arch']} Mem: {conf['core']['mem']}")
        panda = Panda(q_config["arch"], mem=conf["core"]["mem"], extra_args=args)

        if "64" in archend:
            panda.set_os_name("linux-64-generic")
        else:
            panda.set_os_name("linux-32-generic")

        panda.load_plugin("osi", args={"disable-autoload": True})
        panda.load_plugin(
            "osi_linux",
            args={
                "kconf_file": os.path.join(os.path.dirname(conf["core"]["kernel"]), "osi.config"),
                "pagewalk": False,
                "kconf_group": q_config["kconf_group"],
                "hypercall": True,
            },
        )

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

    sys.path.append("/pyplugins")

    plugins.initialize(panda, args)
    plugins.load_plugins(conf_plugins)

    # XXX HACK: normally panda args are set at the constructor. But we want to load
    # our plugins first and these need a handle to panda. So after we've constructed
    # our panda object, we'll directly insert our args into panda.panda_args in
    # the string entry after the "-append" argument which is a string list of
    # the kernel append args. We put our values at the start of this list

    # Find the argument after '-append' in the list and re-render it based on updated env
    append_idx = panda.panda_args.index("-append") + 1

    config_args = [
        f"{k}" + (f"={v}" if v is not None else "") for k, v in conf["env"].items()
    ]

    # We had some args originally (e.g., rootfs), not from our config, so
    # we need to keep those.
    # XXX: This is a bit hacky. We want users to be able to clobber args by prioritizing config
    # args first, but we need to know the start of the string too. So let's say a user can't change
    # the root=/dev/vda argument and put that first. Then config args. Then the rest of the args
    root_str = f"root={ROOTFS}"
    panda.panda_args[append_idx] = (
        root_str
        + " "
        + " ".join(config_args)
        + panda.panda_args[append_idx].replace(root_str, "")
    )

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


def find_free_port():
    telnet_port = 23
    while telnet_port < 65535:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                sock.bind(("127.0.0.1", telnet_port))
                break
            except OSError:
                telnet_port += 1000

    if telnet_port > 65535:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("localhost", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            telnet_port = s.getsockname()[1]

    return telnet_port


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

    logger.debug("penguin_run start:")
    logger.debug(f"proj_dir={proj_dir}")
    logger.debug(f"config={config}")
    logger.debug(f"out_dir={out_dir}")
    logger.debug(f"init={init}")
    logger.debug(f"timeout={timeout}")
    logger.debug(f"show_output={show_output}")

    run_config(
        proj_dir, config, out_dir, logger, init, timeout, show_output, verbose=verbose
    )


if __name__ == "__main__":
    main()
