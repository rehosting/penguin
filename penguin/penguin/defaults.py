# This file contains default values for penguin configuration
# We specify a default init script, and a set of default plugins
# along with their descriptions and default settings.

default_version = "1.0.0"

# Where are plugins in the filesystem. These are our standard pyplugins
# that we use for env, pseudofiles, etc.
default_plugin_path = "/pandata"

default_init_script = """#!/igloo/utils/sh
/igloo/utils/busybox mkdir -p /sys /proc /dev/pts /run /tmp /dev
/igloo/utils/busybox mount -t sysfs sysfs /sys
/igloo/utils/busybox mount -t proc proc /proc
/igloo/utils/busybox mount -t tmpfs tmpfs /run
/igloo/utils/busybox mount -t tmpfs tmpfs /tmp
/igloo/utils/busybox mount -t devtmpfs devtmpfs /dev

/igloo/utils/busybox mkdir -p /dev/pts
/igloo/utils/busybox mount -t devpts devpts /dev/pts

if [ -e /igloo/utils/random_seed ]; then
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/random
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/urandom
fi

if [ ! -z "${ROOT_SHELL}" ]; then
  echo '[IGLOO INIT] Launching root shell';
  ENV=/igloo/utils/igloo_profile /igloo/utils/console &
  unset ROOT_SHELL
fi

if [ ! -z "${SHARED_DIR}" ]; then
  /igloo/utils/busybox mkdir /igloo/shared
  echo '[IGLOO INIT] Mounting shared directory';
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L
  unset SHARED_DIR
fi

if [ ! -z "${CID}" ]; then
  echo '[IGLOO INIT] Launching VPN';
  /igloo/utils/vpn guest -c ${CID} >/dev/null &
  unset CID
fi

if [ ! -z "${igloo_init}" ]; then
  echo '[IGLOO INIT] Running specified init binary';
  LD_PRELOAD=/igloo/utils/libnvram.so exec "${igloo_init}"
fi
echo "[IGLOO INIT] Fatal: no igloo_init specified in env. Abort"
exit 1
"""

default_plugins = {
    'core': {
        "description": "Utility: sanity tests and timeout",
        'version': "1.0.0",
    },

    "netbinds": {
      "description": "Analysis: Track network binds",
      "version": "1.0.0"
    },

    'vpn': {
        'description': "Utility: network bridging",
        'version': "1.0.0",
        'depends_on': "netbinds"
    },

    'shell': {
        "description": "Analysis: track shell script coverage and variable accesses",
        'version': "1.0.0",
    },

    'coverage': {
        "description": "Analysis: Track coverage of binaries",
        'version': "1.0.0",
    },

    'env': {
        "description": "Analysis: Track accesses to kernel and uboot environment",
        'version': "1.0.0",
    },

    'pseudofiles': {
        "description": "Analysis & Intervention: Track failed /dev and /proc files. Hide these failures using models specifed in config",
        'version': "1.0.0",
    },

    'health': {
        "description": "Analysis: Track health of the system",
        'version': "1.0.0",
    },

    'nmap': {
        "description": "Analysis: run nmap scans on guest network services",
        'depends_on': 'vpn',
        'enabled': False,
        'version': "1.0.0",
    },
    'zap': {
        "description": "Analysis: Run ZAP web crawler on guest web servers",
        'depends_on': 'vpn',
        'enabled': False,
        'version': "1.0.0",
    },
    'mount': {
        "description": "Analysis: Track when filesystems cannot be mounted",
        'enabled': True,
        'version': "1.0.0",
    },
}
