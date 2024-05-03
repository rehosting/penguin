#!/usr/bin/env python3
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import os
import sys
import shutil
import random
import logging
from time import sleep
from contextlib import contextmanager
from pandare import Panda
from .utils import load_config, hash_image_inputs
from .defaults import default_plugin_path
from .common import yaml

# Note armel is just panda-system-arm and mipseb is just panda-system-mips

ROOTFS="/dev/vda" # Common to all
qemu_configs = {
        "armel": { "qemu_machine": "virt",
                    "arch":         "arm",
                    "kconf_group":  "armel",
                    "mem_gb":          "2",
                },

        "mipsel": {"qemu_machine": "malta",
                    "arch":         "mipsel",
                    "kconf_group":  "mipsel",
                    "mem_gb":          "2",
                },

        "mipseb": {"qemu_machine": "malta",
                    "arch":         "mips",
                    "kconf_group":  "mipseb",
                    "mem_gb":          "2",
                },
        "mips64eb": {"qemu_machine": "malta",
                    "arch":         "mips64",
                    "kconf_group":  "mips64eb",
                    "mem_gb":          "2",
                },
}

def _sort_plugins_by_dependency(conf_plugins):
    """
    Sorts the plugins based on their dependencies.
    """
    def dfs(plugin_name, visited, stack):
        """
        Depth-First Search to sort plugins.
        """
        visited.add(plugin_name)
        details = conf_plugins.get(plugin_name, {})
        deps = details.get('depends_on', [])
        # Allow depends_on to be a single string or a list of strings
        if isinstance(deps, str):
            deps = [deps]
        for dep in deps:
            if dep not in visited:
                if dep not in conf_plugins:
                    raise ValueError(f"Plugin {plugin_name} depends on {dep}, which is missing.")
                dfs(dep, visited, stack)
        stack.append(plugin_name)

    sorted_plugins = []
    visited = set()

    for plugin_name in conf_plugins:
        if plugin_name not in visited:
            dfs(plugin_name, visited, sorted_plugins)

    return sorted_plugins

@contextmanager
def print_to_log(out, err):
    original_stdout = sys.stdout  # Save the original stdout
    original_stderr = sys.stderr  # Save the original stderr
    sys.stdout = open(out, 'w')  # Redirect stdout to devnull
    sys.stderr = open(err, 'w')  # Redirect stderr to devnull
    try:
        yield
    finally:
        sys.stdout.close() # close the file
        sys.stderr.close() # close the file
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
        os.dup2(original_stdout_fd, sys.stdout.fileno())
        os.dup2(original_stderr_fd, sys.stderr.fileno())

        # Close the file descriptors for the new stdout and stderr
        os.close(new_stdout)
        os.close(new_stderr)


def run_config(conf_yaml, proj_dir=None, out_dir=None, logger=None, init=None, timeout=None, show_output=False):
    '''
    conf_yaml a path to our config within proj_dir
    proj_dir contains config.yaml
    out_dir stores results and a copy of config.yaml
    '''

    # Ensure config_yaml is directly in proj_dir
    if os.path.dirname(conf_yaml) != proj_dir:
        raise ValueError(f"config_yaml must be in proj_dir: config directory {os.path.dirname(conf_yaml)} != {proj_dir}")

    qcow_dir = os.path.join(proj_dir, 'qcows')
    if not os.path.isdir(qcow_dir):
        os.makedirs(qcow_dir, exist_ok=True)

    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(conf_yaml), 'output')
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    if logger is None:
        logger = logging.getLogger('penguin_run')
        logger.setLevel(logging.INFO)

    # Image isn't in our config, but the path we use is a property
    # of configs fiiles section - we'll hash it to get a path
    # Read input config and validate
    conf = load_config(conf_yaml)

    if timeout is not None and conf.get('plugins', {}).get('core', None) is not None:
        # An arugument setting a timeout overrides the config's timeout
        conf['plugins']['core']['timeout'] = timeout


    if 'igloo_init' not in conf['env']:
        if init:
            conf['env']['igloo_init'] = init
        else:
            try:
                with open(os.path.join(*[os.path.dirname(conf_yaml), 'base', 'env.yaml']), 'r') as f:
                    # Read yaml file, get 'igloo_init' key
                    inits = yaml.safe_load(f)['igloo_init']
            except FileNotFoundError:
                inits = []
            raise RuntimeError(f"No init binary is specified in configuraiton, set one in config's env section as igloo_init. Static analysis identified the following: {inits}")


    archend = conf['core']['arch']
    kernel = conf['core']['kernel']
    config_fs = os.path.join(proj_dir, conf['core']['fs']) # Path to tar filesystem
    plugin_path = conf['core']['plugin_path'] if 'plugin_path' in conf['core'] else default_plugin_path
    static_files = conf['static_files'] if 'static_files' in conf else {} # FS shims
    conf_plugins = conf['plugins'] # {plugin_name: {enabled: False, other... opts}}

    if isinstance(conf_plugins, list):
        logger.info("Warning, execpted dict of plugins, got list")
        conf_plugins = {plugin: {} for plugin in conf_plugins}

    if not os.path.isfile(kernel):
        raise ValueError(f"Kernel file invalid: {kernel}")

    if not os.path.isfile(config_fs):
        raise ValueError(f"Missing filesystem archive in base directory: {config_fs}")

    h = hash_image_inputs(proj_dir, conf)
    image_filename = f"image_{h}.qcow2"
    config_image = os.path.join(qcow_dir, image_filename)

    # Make sure we have a clean out_dir everytime. XXX should we raise an error here instead?
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
        open(lock_file, 'a').close() # create lock file

        try:
            logger.info(f"Missing filesystem image {config_image}, generating from config")
            from .penguin_prep import prepare_run
            prepare_run(proj_dir, conf, qcow_dir, out_filename=image_filename)
        except Exception as e:
            logger.info(f"Failed to make image: for {config_fs} / {os.path.dirname(qcow_dir)}")
            if os.path.isfile(os.path.join(qcow_dir, image_filename)):
                os.remove(os.path.join(qcow_dir, image_filename))
            raise e
        finally:
            # Always remove lock file, even if we failed to make the image
            if os.path.isfile(lock_file):
                os.remove(lock_file)

        # We expect to have the image now
        if not os.path.isfile(config_image):
            raise ValueError(f"Image file invalid: {config_image}")
        
    CID=4 # We can use a constant CID with vhost-user-vsock
    # Create a temp dir for our vhost files:
    tmpdir = tempfile.TemporaryDirectory()
    path = Path(tmpdir.name)
    socket_path = path / "socket"
    uds_path =    path / "vsocket"
    mem_path =    path / "mem_path"

    # Launch a process that listens on the file socket and forwards to the uds
    # which QEMU connects to. TODO: move to vpn plugin?
    host_vsock_bridge = subprocess.Popen(["vhost-device-vsock", "--guest-cid", str(CID), "--socket", socket_path, "--uds-path" , uds_path])

    try:
        q_config = qemu_configs[archend]
    except KeyError:
        raise ValueError(f"Unknown architecture: {archend}")
    
    vsock_args = [
        '-object', f'memory-backend-file,id=mem0,mem-path={mem_path},size={q_config["mem_gb"]}G,share=on',
        '-numa', 'node,memdev=mem0',
        '-chardev', f'socket,id=char0,reconnect=0,path={socket_path}',
        '-device', 'vhost-user-vsock-pci,chardev=char0'
        ]

    append = f"root={ROOTFS} init=/igloo/init console=ttyS0  CID={CID} rw panic=1" # Required
    append += " rootfstype=ext2 norandmaps nokaslr" # Nice to have
    append += " clocksource=jiffies nohz_full nohz=off no_timer_check" # Improve determinism?
    append += " idle=poll acpi=off nosoftlockup " # Improve determinism?

    if archend == "armel":
        append = append.replace("console=ttyS0", "console=ttyAMA0")

    root_shell = []
    if conf['core'].get('root_shell', False):
        root_shell  = ['-serial', 'telnet:0.0.0.0:4321,server,nowait'] # ttyS1: root shell

    # If core config specifes immutable: False we'll run without snapshot
    no_snapshot_drive = f"file={config_image},if=virtio"
    snapshot_drive = no_snapshot_drive + ",cache=unsafe,snapshot=on"
    drive = snapshot_drive if conf['core'].get('immutable', True) else no_snapshot_drive

    args = [ '-M',     q_config['qemu_machine'],
            '-kernel', kernel,
            '-append', append,
            '-display', 'none',
            "-drive", drive]

    args += ['-no-reboot']

    if conf['core'].get('network', False):
        # Connect guest to network if specified
        if archend == "armel":
            logger.info("WARNING: UNTESTSED network flags for arm")
        args.extend(['-netdev', 'user,id=user.0', '-device', 'virtio-net,netdev=user.0'])

    if 'show_output' in conf['core'] and conf['core']['show_output']:
        console_out = ['-serial', 'mon:stdio']
    else:
        console_out = ['-serial', f'file:{out_dir}/console.log', '-monitor', 'null'] # ttyS0: guest console output

    if 'shared_dir' in conf['core']:
        shared_dir = conf['core']['shared_dir']
        if shared_dir[0] == '/':
            shared_dir = shared_dir[1:] # Ensure it's relative path to proj_dir
        shared_dir = os.path.join(proj_dir, shared_dir)
        os.makedirs(shared_dir,exist_ok=True)
        args += [
            '-virtfs',
            ','.join((
                'local',
                f'path={shared_dir}',
                'mount_tag=igloo_shared_dir',
                'security_model=mapped-xattr',
            )),
        ]

    # ARM maps ttyS1 to the first listed device while MIPS maps ttyS0 to the first devie
    if archend in ["mipsel", "mipseb", "mips64eb"]:
        args = args + console_out + root_shell
    else:
        args = args + root_shell + console_out

    if conf['core'].get('cpu', None):
        args += ['-cpu', conf['core']['cpu']]
    elif archend == 'mips64eb':
        args += ['-cpu', 'MIPS64R2-generic']

    ############# Reduce determinism #############

    # Fixed clock time.
    args = args + ['-rtc', 'base=2023-01-01T00:00:00']

    # Add vsock args
    args += vsock_args

    # Disable audio (allegedly speeds up emulation by avoiding running another thread)
    os.environ['QEMU_AUDIO_DRV'] = 'none'

    # Setup PANDA. Do not let it print
    parent_outdir = os.path.dirname(out_dir)
    stdout_path = os.path.join(parent_outdir, 'qemu_stdout.txt')
    stderr_path = os.path.join(parent_outdir, 'qemu_stderr.txt')

    with print_to_log(stdout_path, stderr_path):
        panda = Panda(q_config['arch'], mem=q_config['mem_gb']+"G", extra_args=args)

        if '64' in archend:
            panda.set_os_name("linux-64-generic")
        else:
            panda.set_os_name("linux-32-generic")

        panda.load_plugin("syscalls2", args = {"load-info": True})
        panda.load_plugin("osi", args = {"disable-autoload":True})
        panda.load_plugin("osi_linux", args = {"kconf_file":os.path.join(os.path.dirname(kernel), "osi.config"),
                                                "pagewalk": True,
                                                "kconf_group": q_config['kconf_group']})

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

    for plugin_name in _sort_plugins_by_dependency(conf_plugins):
        details = conf_plugins[plugin_name]
        if 'enabled' in details and not details['enabled']:
            continue # Special arg "enabled" - if false we skip
        logger.debug(f"Loading plugin: {plugin_name}")

        args ={
            'plugins': conf_plugins,
            'CID': CID,
            'vhost_socket': uds_path,
            'conf': conf,
            'fs': config_fs,
            'fw': config_image,
            'outdir': out_dir
        }
        # If we have any deatils, pass them along
        if details is not None:
            args.update(details)
        path = os.path.join(plugin_path, plugin_name+".py")
        if not os.path.isfile(path):
            raise ValueError(f"Plugin not found: {path} with name={plugin_name} and plugin_path={plugin_path}")
        try:
            if len(panda.pyplugins.load_all(path, args)) == 0:
                with open(os.path.join(out_dir, 'plugin_errors.txt'), 'a') as f:
                    f.write(f"Failed to load plugin: {plugin_name}")
                raise ValueError(f"Failed to load plugin: {plugin_name}")
        except SyntaxError as e:
            logger.error(f"Syntax error loading pyplugin: {e}")
            raise ValueError(f"Failed to load plugin: {plugin_name}")

    # XXX HACK: normally panda args are set at the constructor. But we want to load
    # our plugins first and these need a handle to panda. So after we've constructed
    # our panda object, we'll directly insert our args into panda.panda_args in
    # the string entry after the "-append" argument which is a string list of
    # the kernel append args. We put our values at the start of this list

    # Find the argument after '-append' in the list and re-render it based on updated env
    append_idx = panda.panda_args.index("-append") + 1

    config_args = [f"{k}" + (f"={v}" if v is not None else '') for k, v in conf['env'].items()]

    # We had some args originally (e.g., rootfs), not from our config, so
    # we need to keep those.
    # XXX: This is a bit hacky. We want users to be able to clobber args by prioritizing config
    # args first, but we need to know the start of the string too. So let's say a user can't change
    # the root=/dev/vda argument and put that first. Then config args. Then the rest of the args
    root_str = f"root={ROOTFS}"
    panda.panda_args[append_idx] = root_str + " " + " ".join(config_args) + panda.panda_args[append_idx].replace(root_str, "")

    @panda.cb_pre_shutdown
    def pre_shutdown():
        '''
        Ensure pyplugins nicely clean up. Working around some panda bug
        '''
        panda.pyplugins.unload_all()

    @panda.cb_guest_hypercall
    def before_hc(cpu):
        # This is a bit of a hack. We want this in core.py, but we were seeing
        # some panda segfaults at shutdown when the Core pyplugin was uninitialized
        # but the guest was still running and panda was trying to call into the
        # freed python cffi callback object. As a workaround we have it here.
        num = panda.arch.get_arg(cpu, 0)
        if target := getattr(panda.pyplugins.ppp, 'Core', None):
            return target.handle_hc(cpu, num) # True IFF that handles num
        return False

    logger.info("Launching rehosting")
    def _run():
        try:
            panda.run()
        except KeyboardInterrupt:
            logger.info("\nStopping for ctrl-c\n")
        finally:
            panda.panda_finish()
            host_vsock_bridge.kill()
            shutil.rmtree(tmpdir.name)

    if show_output:
        _run()
    else:
        with redirect_stdout_stderr(stdout_path, stderr_path):
            _run()

def main():
    logger = logging.getLogger('penguin_run')
    logger.setLevel(logging.INFO)
    logger.info("Penguin run running")
    if len(sys.argv) >= 2:
        # Given a config, run it. Specify qcow_dir to store qcow if not "dirname(config)""
        # and specify out_dir to store results if not "dirname(config)/output"
        config = sys.argv[1]
        out_dir = sys.argv[2] if len(sys.argv) > 2 else None

        proj_dir = os.path.dirname(config)

        # Two optional args: init and timeout
        init = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "None" else None
        timeout = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] != "None" else None
        show_output = sys.argv[6]=='show' if len(sys.argv) > 6 else False

        run_config(config, proj_dir, out_dir, logger, init, timeout, show_output)
    else:
        raise RuntimeError(f"USAGE {sys.argv[0]} [config.yaml] (out_dir: default is dirname(config.yaml)/output) (qcow_dir: dirname(config.yaml)/qcows)")

if __name__ == "__main__":
    main()
