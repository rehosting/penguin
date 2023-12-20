# This file contains default values for penguin configuration
# We specify a default init script, and a set of default plugins
# along with their descriptions and default settings.

default_version = "1.0.0"

default_init_script = """#!/igloo/utils/sh
/igloo/utils/busybox mkdir -p /sys /proc /dev/pts /run /tmp
/igloo/utils/busybox mount -t sysfs sysfs /sys
/igloo/utils/busybox mount -t proc proc /proc
/igloo/utils/busybox mount -t tmpfs tmpfs /run
/igloo/utils/busybox mount -t tmpfs tmpfs /tmp
/igloo/utils/busybox mount -t devpts devpts /dev/pts

# symlink /dev/root to /dev/vda. Not sure about this.
#/igloo/utils/busybox ln -s /dev/vda /dev/root

if [ -e /igloo/utils/random_seed ]; then
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/random
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/urandom
fi

if [ ! -z "${ROOT_SHELL}" ]; then
  echo '[IGLOO INIT] Launching root shell';
  ENV=/igloo/utils/igloo_profile /igloo/utils/console &
  unset ROOT_SHELL
fi

if [ ! -z "${CID}" ]; then
  echo '[IGLOO INIT] Launching VPN';
  /igloo/utils/vpn guest -c ${CID} >/dev/null &
  unset CID
fi

if [ ! -z "${MTD_PLACEHOLDER}" ]; then
  echo "[IGLOO INIT] populating /dev/mtd* with placeholder"

  echo "DI/womlnbG9vX3Vib290X2Vudj1wbGFjZWhvbGRlcgAA" | \\
    /igloo/utils/busybox base64 -d > /igloo/utils/mtd_placeholder
  # Write 0x4000 zeros into mtd2
  /igloo/utils/busybox dd if=/dev/zero of=/dev/mtd1 bs=16384 count=1

  /igloo/utils/busybox dd if=/igloo/utils/mtd_placeholder \\
    of=/dev/mtd1 bs=1634 count=1 conv=notrunc

  # Let's make our shim look like MTDs 2 through 10
  for i in {2..10}; do
    /igloo/utils/busybox cp /dev/mtd1 /dev/mtd${i}
  done

  unset MTD_PLACEHOLDER
fi

if [ ! -z "${igloo_init}" ]; then
  echo '[IGLOO INIT] Running specified init binary';
  exec "${igloo_init}"
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
}
