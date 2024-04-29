# This file contains default values for penguin configuration
# We specify a default init script, and a set of default plugins
# along with their descriptions and default settings.
from copy import deepcopy
from os.path import dirname

default_version = "1.0.0"

# Where are plugins in the filesystem. These are our standard pyplugins
# that we use for env, pseudofiles, etc.
default_plugin_path = "/pandata"

default_netdevs = [f"eth{x}" for x in range(6)] + [f"wlan{x}" for x in range(6)] + \
                  [f"eno{x}" for x in range(3)] + [f"ens{x}" for x in [33, 192]] + \
                  ["enx0", "enp0s25", "wlp2s0"]

# Resolve current path then go to ../resources/init.sh
default_init_script = open(f"{dirname(dirname(__file__))}/resources/init.sh").read()

default_plugins = {
    "core": {
        "description": "Utility: sanity tests and timeout",
        "version": "1.0.0",
    },

    "netbinds": {
      "description": "Analysis: Track network binds",
      "version": "1.0.0",
      "depends_on": "core"
    },

    "vpn": {
        "description": "Utility: network bridging",
        "version": "1.0.0",
        "depends_on": "netbinds"
    },

    "shell": {
        "description": "Analysis: track shell script coverage and variable accesses",
        "version": "1.0.0",
    },

    "coverage": {
        "description": "Analysis: Track coverage of binaries",
        "version": "1.0.0",
    },

    "env": {
        "description": "Analysis: Track accesses to kernel and uboot environment",
        "version": "1.0.0",
        "depends_on": "core"
    },

    "pseudofiles": {
        "description": "Analysis & Intervention: Track failed /dev and /proc files. Hide these failures using models specifed in config",
        "version": "1.0.0",
        "depends_on": "core"
    },

    "health": {
        "description": "Analysis: Track health of the system",
        "version": "1.0.0",
        "depends_on": "core"
    },

    "nmap": {
        "description": "Analysis: run nmap scans on guest network services",
        "depends_on": "vpn",
        "enabled": False,
        "version": "1.0.0",
    },
    "zap": {
        "description": "Analysis: Run ZAP web crawler on guest web servers",
        "depends_on": "vpn",
        "enabled": False,
        "version": "1.0.0",
    },
    "mount": {
        "description": "Analysis: Track when filesystems cannot be mounted",
        "enabled": True,
        "version": "1.0.0",
    },
    "nvram2": {
        "description": "Analysis: Track nvram accesses",
        "enabled": True,
        "version": "1.0.0",
        "depends_on": "core"
    },
    "lifeguard": {
        "description": "Intervention: Block violent signals",
        "enabled": True,
        "version": "1.0.0",
    },
    'interfaces': {
        "description": "Analysis & Intervention: Track network interfaces accessed and add missing ones",
        "enabled": True,
        "version": "1.0.0",
        "depends_on": "health"
    },
    'send_hypercall': {
        'description': "Analysis: Consume hypercall output from the guest (for nvram accesses)",
        'version': "1.0.0",
        'depends_on': "core"
    }
}

# We add ioctl wildcard -> 0 in single-iteration mode
# In multi-iteration mode we dynamically build ioctl models

# Hardcoded device list and acos ioctls are from Firmadyne/FirmAE
# https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/blob/master/drivers/firmadyne/devfs_stubs.c#L37-L52
default_pseudo_model = {
    'read': {
        'model': 'zero',
    },
    'write': {
        'model': 'discard',
    }
}
acos_pseudo_model = deepcopy(default_pseudo_model)
acos_pseudo_model['ioctl'] = {
    0x40046431: {
        'model': 'return_const',
        'val': 1
    },
    0x80046431: {
        'model': 'return_const',
        'val': 1
    },
    0x40046432: {
        'model': 'return_const',
        'val': 1
    },
    0x80046432: {
        'model': 'return_const',
        'val': 1
    },
}

default_pseudofiles = {
  '/dev/acos_nat_cli': acos_pseudo_model,
  '/dev/brcmboard': default_pseudo_model,
  '/dev/dsl_cpe_api': default_pseudo_model,
  '/dev/gpio': default_pseudo_model,
  '/dev/nvram': default_pseudo_model,
  '/dev/pib': default_pseudo_model,
  '/dev/sc_led': default_pseudo_model,
  '/dev/tca0': default_pseudo_model,
  '/dev/ticfg': default_pseudo_model,
  '/dev/watchdog': default_pseudo_model,
  '/dev/wdt': default_pseudo_model,
  '/dev/zybtnio': default_pseudo_model,
  '/proc/blankstatus': default_pseudo_model,
  '/proc/btnCnt': default_pseudo_model,
  '/proc/br_igmpProxy': default_pseudo_model,
  '/proc/BtnMode': default_pseudo_model,
  '/proc/gpio': default_pseudo_model,
  '/proc/led': default_pseudo_model,
  '/proc/push_button': default_pseudo_model,
  '/proc/rtk_promiscuous': default_pseudo_model,
  '/proc/rtk_vlan_support': default_pseudo_model,
  '/proc/RstBtnCnt': default_pseudo_model,
  '/proc/sw_nat': default_pseudo_model,
  '/proc/simple_config/reset_button_s': default_pseudo_model,
  '/proc/quantum/drv_ctl': default_pseudo_model,
  '/proc/rt3052/mii/ctrl': default_pseudo_model,
  '/proc/rt3052/mii/data': default_pseudo_model
}

default_lib_aliases = {
            "nvram_load": "nvram_init",
            "nvram_loaddefault": "true",
            "_nvram_get": "nvram_get",
            "nvram_get_state": "nvram_get_int",
            "nvram_set_state": "nvram_set_int",
            "nvram_restore_default": "nvram_reset",
            "nvram_upgrade": "nvram_commit",
            "get_default_mac": "true",
            "VCTGetPortAutoNegSetting": "false1",
            "agApi_fwGetFirstTriggerConf": "true1",
            "agApi_fwGetNextTriggerConf": "true1",
            "artblock_get": "nvram_get",
            "artblock_fast_get": "nvram_safe_get",
            "artblock_safe_get": "nvram_safe_get",
            "artblock_set": "nvram_set",
            "nvram_flag_set": "true",
            "nvram_flag_reset": "true",
            "nvram_master_init": "false",
            "nvram_slave_init": "false",
            "apmib_init": "true",
            "apmib_reinit": "true",
            "apmib_update": "true",
            "WAN_ith_CONFIG_SET_AS_STR": "nvram_nset",
            "WAN_ith_CONFIG_SET_AS_INT": "nvram_nset_int",
            "acos_nvram_init": "nvram_init",
            "acos_nvram_get": "nvram_get",
            "acos_nvram_read": "nvram_get_buf",
            "acos_nvram_set": "nvram_set",
            "acos_nvram_loaddefault": "true",
            "acos_nvram_unset": "nvram_unset",
            "acos_nvram_commit": "nvram_commit",
            "acosNvramConfig_init": "nvram_init",
            "acosNvramConfig_get": "nvram_get",
            "acosNvramConfig_read": "nvram_get_buf",
            "acosNvramConfig_set": "nvram_set",
            "acosNvramConfig_write": "nvram_set",
            "acosNvramConfig_unset": "nvram_unset",
            "acosNvramConfig_match": "nvram_match",
            "acosNvramConfig_invmatch": "nvram_invmatch",
            "acosNvramConfig_save": "nvram_commit",
            "acosNvramConfig_save_config": "nvram_commit",
            "acosNvramConfig_loadFactoryDefault": "nvram_loaddefault",
            "nvram_commit_adv": "nvram_commit",
            "nvram_unlock_adv": "true",
            "nvram_lock_adv": "true",
            "nvram_check": "true",
            "envram_get_func": "envram_get",
            "nvram_getf": "envram_getf",
            "envram_set_func": "envram_set",
            "nvram_setf": "envram_setf",
            "envram_unset_func": "envram_unset",
        }