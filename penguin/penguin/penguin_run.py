#!/usr/bin/env python3
import os
import sys
import shutil
import random
from time import sleep
from pandare import Panda
from .utils import load_config, hash_image_inputs
from .defaults import default_plugin_path

# Note armel is just panda-system-arm and mipseb is just panda-system-mips

ROOTFS="/dev/vda" # Common to all
qemu_configs = {
        "armel": { "qemu_machine": "virt",
                    "arch":         "arm",
                    "kconf_group":  "armel",
                    "mem_gb":          "4",
                },

        "mipsel": {"qemu_machine": "malta",
                    "arch":         "mipsel",
                    "kconf_group":  "mipsel",
                    "mem_gb":          "1",
                },

        "mipseb": {"qemu_machine": "malta",
                    "arch":         "mips",
                    "kconf_group":  "mipseb",
                    "mem_gb":          "1",
                },
        "mips64eb": {"qemu_machine": "malta",
                    "arch":         "mips64",
                    "kconf_group":  "mips64eb",
                    "mem_gb":          "1",
                },
}

def make_unique_cid():
    CID = None
    max_cid = 3 # Try to keep these small to save kernel arg space
    while CID==None:
        max_cid += (1 if max_cid < 32 else 0)
        CID=random.randint(3,(2**max_cid)-1) # +3 is to shift past the special CIDs
        for fname in os.listdir("/tmp"):
            #The host side of the VPN creates these files
            if fname.startswith(f"vpn_events_{CID}_"):
                print(f"Found existing qemu/panda with cid={CID}")
                #Also, consider buying a lotto ticket
                CID=None
                break
    return CID

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

def run_config(conf_yaml, out_dir=None, qcow_dir=None):
    '''
    conf_yaml a path to our config
    qcow_dir contains image.qcow + config.yaml
    out_dir stores results and a copy of config.yaml
    '''

    if qcow_dir is None:
        qcow_dir = os.path.join(os.path.dirname(conf_yaml), 'qcows')

    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(conf_yaml), 'output')

    # Image isn't in our config, but the path we use is a property
    # of configs fiiles section - we'll hash it to get a path
    # Read input config and validate
    conf = load_config(conf_yaml)
    archend = conf['core']['arch']
    kernel = conf['core']['kernel']
    config_fs = conf['core']['fs'] # Path to tar filesystem
    plugin_path = conf['core']['plugin_path'] if 'plugin_path' in conf['core'] else default_plugin_path
    static_files = conf['static_files'] if 'static_files' in conf else {} # FS shims
    conf_plugins = conf['plugins'] # {plugin_name: {enabled: False, other... opts}}

    if isinstance(conf_plugins, list):
        print("Warning, execpted dict of plugins, got list")
        conf_plugins = {plugin: {} for plugin in conf_plugins}

    if not os.path.isfile(kernel):
        raise ValueError(f"Kernel file invalid: {kernel}")

    if not os.path.isfile(config_fs):
        raise ValueError(f"Missing filesystem archive in base directory: {config_fs}")

    h = hash_image_inputs(conf)
    image_filename = f"image_{h}.qcow2"
    config_image = os.path.join(qcow_dir, image_filename)

    # Make sure we have a clean out_dir everytime. XXX should we raise an error here instead?
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    # Make sure we have a qcows dir
    if not os.path.isdir(qcow_dir):
        os.makedirs(qcow_dir)

    while os.path.isfile(image_filename+".lock"):
        # Stall while there's a lock
        print("stalling on lock")
        sleep(1)


    # If image isn't in our out_dir already, generate it
    if not os.path.isfile(config_image):
        open(image_filename+".lock", 'a').close() # create lock file

        print(f"Missing filesystem image {config_image}, generating from config")
        from .penguin_prep import prepare_run
        prepare_run(conf, qcow_dir, out_filename=image_filename)

        # Remove lock file
        os.remove(image_filename+".lock")

        # We expect to have the image now
        if not os.path.isfile(config_image):
            raise ValueError(f"Image file invalid: {config_image}")
        
    # Generate a unique CID
    CID = make_unique_cid()

    try:
        q_config = qemu_configs[archend]
    except KeyError:
        raise ValueError(f"Unknown architecture: {archend}")

    append = f"root={ROOTFS} init=/igloo/init console=ttyS0  CID={CID} rw panic=1" # Required
    append += " rootfstype=ext2 norandmaps nokaslr" # Nice to have
    append += " clocksource=jiffies nohz_full nohz=off no_timer_check" # Improve determinism?
    append += " idle=poll acpi=off nosoftlockup " # Improve determinism?

    have_vsock = os.path.exists("/dev/vhost-vsock") and 'vpn' in conf['plugins'] and ('enabled' not in conf['plugins']['vpn'] or conf['plugins']['vpn']['enabled'])

    if not have_vsock:
        append = append.replace(f" CID={CID}", "") # Remove CID if we don't have vhost-vsock

    if archend in ["armel"]:
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

    if have_vsock:
        # Only add vhost-vsock if we have it and the vpn plugin is enabled
        args.extend(['-device', f'vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={CID}'])

    if 'show_output' in conf['core'] and conf['core']['show_output']:
        console_out = ['-serial', 'mon:stdio']
    else:
        console_out = ['-serial', f'file:{out_dir}/console.log', '-monitor', 'stdio'] # ttyS0: guest console output

    # ARM maps ttyS1 to the first listed device while MIPS maps ttyS0 to the first devie
    if archend in ["mipsel", "mipseb", "mips64eb"]:
        args = args + console_out + root_shell
    else:
        args = args + root_shell + console_out

    if archend == 'mips64eb':
        args += ['-cpu', 'MIPS64R2-generic']

    ############# Reduce determinism #############

    # Fixed clock time.
    args = args + ['-rtc', 'base=2023-01-01T00:00:00']

    # Disable audio (allegedly speeds up emulation by avoiding running another thread)
    os.environ['QEMU_AUDIO_DRV'] = 'none'

    # Setup PANDA
    panda = Panda(q_config['arch'], mem=q_config['mem_gb']+"G", extra_args=args)

    if archend in ["mips64eb"]:
        panda.set_os_name("linux-64-generic")
    else:
        panda.set_os_name("linux-32-generic")

    panda.load_plugin("syscalls2", args = {"load-info": True})
    panda.load_plugin("osi", args = {"disable-autoload":True})
    panda.load_plugin("osi_linux", args = {"kconf_file":"/igloo_static/kernels/osi.config",
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

    print("Loading plugins")
    for plugin_name in _sort_plugins_by_dependency(conf_plugins):
        details = conf_plugins[plugin_name]
        if 'enabled' in details and not details['enabled']:
            continue # Special arg "enabled" - if false we skip

        args ={
            'plugins': conf_plugins,
            'CID': CID,
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
        if len(panda.pyplugins.load_all(path, args)) == 0:
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
    full_append = root_str + " " + " ".join(config_args) +  panda.panda_args[append_idx].replace(root_str, "")
    if len(full_append) > 255:
        print("WARNING append may be too long. The following will be passed through reliably:")
        print(full_append[:255])
        print("The rest may be dropped:")
        print(full_append[255:])

    panda.panda_args[append_idx] = full_append

    print("Run emulation")
    try:
        panda.run()
    except KeyboardInterrupt:
        print("\nStopping for ctrl-c\n")
    finally:
        panda.panda_finish()

def main():
    print("Penguin run running")
    if len(sys.argv) >= 2:
        # Given a config, run it. Specify qcow_dir to store qcow if not "dirname(config)""
        # and specify out_dir to store results if not "dirname(config)/output"
        config = sys.argv[1]
        out_dir = sys.argv[2] if len(sys.argv) > 2 else None
        qcow_dir = sys.argv[3] if len(sys.argv) > 3 else None
        run_config(config, out_dir, qcow_dir)
    else:
        raise RuntimeError(f"USAGE {sys.argv[0]} [config.yaml] (out_dir: default is dirname(config.yaml)/output) (qcow_dir: dirname(config.yaml)/qcows)")

if __name__ == "__main__":
    main()
