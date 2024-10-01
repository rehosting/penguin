# This file contains default values for penguin configuration
# We specify a default init script, and a set of default plugins
# along with their descriptions and default settings.
from copy import deepcopy
from os.path import dirname

default_version = "1.0.0"
static_dir = "/igloo_static/"
DEFAULT_KERNEL = "4.10"

# Where are plugins in the filesystem. These are our standard pyplugins
# that we use for env, pseudofiles, etc.
default_plugin_path = "/pandata"

default_netdevs = (
    [f"eth{x}" for x in range(6)]
    + [f"wlan{x}" for x in range(6)]
    + [f"eno{x}" for x in range(3)]
    + [f"ens{x}" for x in [33, 192]]
    + ["enx0", "enp0s25", "wlp2s0"]
)

# Resolve current path then go to ../resources/init.sh
default_init_script = open(f"{dirname(dirname(__file__))}/resources/init.sh").read()

default_plugins = {
    "core": {},
    "netbinds": {
        "depends_on": "core",
    },
    "vpn": {
        "depends_on": "netbinds",
    },
    "shell": {},
    "coverage": {
        "enabled": False,
    },
    "env": {
        "depends_on": "core",
    },
    "pseudofiles": {
        "depends_on": "core",
    },
    "health": {
        "depends_on": "core",
    },
    "nmap": {
        "depends_on": "vpn",
        "enabled": False,
    },
    "zap": {
        "depends_on": "vpn",
        "enabled": False,
    },
    "mount": {},
    "nvram2": {
        "depends_on": "core",
    },
    "lifeguard": {
    },
    "interfaces": {
        "depends_on": "health",
    },
    "send_hypercall": {
        "depends_on": "core",
    },
}

# We add ioctl wildcard -> 0 in single-iteration mode
# In multi-iteration mode we dynamically build ioctl models

# Hardcoded device list and acos ioctls are from Firmadyne/FirmAE
# https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/blob/master/drivers/firmadyne/devfs_stubs.c#L37-L52
_default_pseudo_model = {
    "read": {
        "model": "zero",
    },
    "write": {
        "model": "discard",
    }
}

_default_dev_model = deepcopy(_default_pseudo_model)
_default_dev_model["ioctl"] = {
    "*": {
        "model": "return_const",
        "val": 0,
    }
}

# Hardcoded ioctl models for some devices from FirmAE
_dev_acos_pseudo_model = deepcopy(_default_dev_model)
_dev_acos_pseudo_model["ioctl"].update({
        0x40046431: {"model": "return_const", "val": 1},
        0x80046431: {"model": "return_const", "val": 1},
        0x40046432: {"model": "return_const", "val": 1},
        0x80046432: {"model": "return_const", "val": 1},
    })

default_pseudofiles = {

	# Reasonable generic /dev entries
    "/dev/gpio": _default_dev_model,
    "/dev/nvram": _default_dev_model,
    "/dev/watchdog": _default_dev_model,

	# Reasonable generic /proc entries
    "/proc/gpio": _default_pseudo_model,
    "/proc/led": _default_pseudo_model,

	# Netgear specific unique device + behavior
    "/dev/acos_nat_cli": _dev_acos_pseudo_model,

	# Hardcoded /dev list from FirmAE
    "/dev/brcmboard": _default_dev_model,
    "/dev/dsl_cpe_api": _default_dev_model,
    "/dev/pib": _default_dev_model,
    "/dev/sc_led": _default_dev_model,
    "/dev/tca0": _default_dev_model,
    "/dev/ticfg": _default_dev_model,
    "/dev/wdt": _default_dev_model,
    "/dev/zybtnio": _default_dev_model,

	# Hardcoded /proc entries from FirmAE
    "/proc/blankstatus": _default_pseudo_model,
    "/proc/btnCnt": _default_pseudo_model,
    "/proc/br_igmpProxy": _default_pseudo_model,
    "/proc/BtnMode": _default_pseudo_model,
    "/proc/push_button": _default_pseudo_model,
    "/proc/rtk_promiscuous": _default_pseudo_model,
    "/proc/rtk_vlan_support": _default_pseudo_model,
    "/proc/RstBtnCnt": _default_pseudo_model,
    "/proc/sw_nat": _default_pseudo_model,
    "/proc/simple_config/reset_button_s": _default_pseudo_model,
    "/proc/quantum/drv_ctl": _default_pseudo_model,
    "/proc/rt3052/mii/ctrl": _default_pseudo_model,
    "/proc/rt3052/mii/data": _default_pseudo_model,
}

default_lib_aliases = {
    # Device specific FirmAE hacks - unknown which devices these target
    # Some seem sort of reasonable/generic (load -> init?)
        "_nvram_get": "nvram_get",
        "nvram_load": "nvram_init",
        "nvram_get_state": "nvram_get_int",
        "nvram_set_state": "nvram_set_int",
        "nvram_restore_default": "nvram_reset",
        "nvram_upgrade": "nvram_commit",
        "nvram_check": "true",
        "nvram_flag_reset": "true",
        "nvram_flag_set": "true",
        "nvram_loaddefault": "true",
        "VCTGetPortAutoNegSetting": "false1",
        "get_default_mac": "true",

        # getf/setf -> envram implementation
        "nvram_getf": "envram_getf",
        "nvram_setf": "envram_setf",

        # Master/slave -> false
        "nvram_master_init": "false",
        "nvram_slave_init": "false",

        # "_adv" shim
        "nvram_lock_adv": "true",
        "nvram_unlock_adv": "true",
        "nvram_commit_adv": "nvram_commit",
	
        # "WAN_" shims
        "WAN_ith_CONFIG_SET_AS_INT": "nvram_nset_int",
        "WAN_ith_CONFIG_SET_AS_STR": "nvram_nset",


    # Netgear (acos) specific FirmAE hack
    "acosNvramConfig_get": "nvram_get",
    "acosNvramConfig_init": "nvram_init",
    "acosNvramConfig_invmatch": "nvram_invmatch",
    "acosNvramConfig_loadFactoryDefault": "nvram_loaddefault",
    "acosNvramConfig_match": "nvram_match",
    "acosNvramConfig_read": "nvram_get_buf",
    "acosNvramConfig_save": "nvram_commit",
    "acosNvramConfig_save_config": "nvram_commit",
    "acosNvramConfig_set": "nvram_set",
    "acosNvramConfig_unset": "nvram_unset",
    "acosNvramConfig_write": "nvram_set",
    "acos_nvram_commit": "nvram_commit",
    "acos_nvram_get": "nvram_get",
    "acos_nvram_init": "nvram_init",
    "acos_nvram_loaddefault": "true",
    "acos_nvram_read": "nvram_get_buf",
    "acos_nvram_set": "nvram_set",
    "acos_nvram_unset": "nvram_unset",

	# Netgear (6250/6400) specific FirmAE hack
    "agApi_fwGetFirstTriggerConf": "true1",
    "agApi_fwGetNextTriggerConf": "true1",

    # Realtek specific FirmAE hacks
    "apmib_init": "true",
    "apmib_reinit": "true",
    "apmib_update": "true",

	# D-Link specific FirmAE hacks
    "artblock_fast_get": "nvram_safe_get",
    "artblock_get": "nvram_get",
    "artblock_safe_get": "nvram_safe_get",
    "artblock_set": "nvram_set",

	# ASUS specific FirmAE hacks
    "envram_get_func": "envram_get",
    "envram_set_func": "envram_set",
    "envram_unset_func": "envram_unset",
}
