# This file contains default values for penguin configuration
# We specify a default init script, and a set of default plugins
# along with their descriptions and default settings.
from copy import deepcopy
from os.path import dirname

vnc_password = "IGLOOPassw0rd!"

default_version = 2
static_dir = "/igloo_static/"
# XXX in config_patchers we append .0 to this - may need to update
DEFAULT_KERNEL = "6.13"

# Where are plugins in the filesystem. These are our standard pyplugins
# that we use for env, pseudofiles, etc.
default_plugin_path = "/pyplugins"

default_netdevs = (
    [f"eth{x}" for x in range(6)]
    + [f"wlan{x}" for x in range(6)]
    + [f"eno{x}" for x in range(3)]
    + [f"ens{x}" for x in [33, 192]]
    + ["enx0", "enp0s25", "wlp2s0"]
)

# Resolve current path then go to ../resources/init.sh
default_init_script = open(
    f"{dirname(dirname(__file__))}/resources/init.sh").read()

# Resolve current path then go to ../resources/preinit.sh
default_preinit_script = open(
    f"{dirname(dirname(__file__))}/resources/preinit.sh").read()

default_plugins = {
    "core": {},
    "netbinds": {
    },
    "vpn": {
    },
    "shell": {},
    "pseudofiles": {
    },
    "health": {
    },
    "mount": {},
    "nvram2": {
    },
    "lifeguard": {
    },
    "interfaces": {
    },
    "send_hypercall": {
    },
    "indiv_debug": {},
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

expert_knowledge_pseudofiles = {
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

# LIB INJECT MAPPINGS
default_libinject_string_introspection = {
    "strcmp": "libinject_strcmp",
    "strncmp": "libinject_strncmp",
    "getenv": "libinject_getenv",
    "strstr": "libinject_strstr"
}

atheros_broadcom = {
    "nvram_get_nvramspace": "libinject_nvram_get_nvramspace",
    "nvram_nget": "libinject_nvram_nget",
    "nvram_nset": "libinject_nvram_nset",
    "nvram_nset_int": "libinject_nvram_nset_int",
    "nvram_nmatch": "libinject_nvram_nmatch"
}

realtek = {
    "apmib_get": "libinject_apmib_get",
    "apmib_set": "libinject_apmib_set"
}

netgear_acos = {
    "WAN_ith_CONFIG_GET": "libinject_WAN_ith_CONFIG_GET"
}

zyxel_or_edimax = {
    "nvram_getall_adv": "libinject_nvram_getall_adv",
    "nvram_get_adv": "libinject_nvram_get_adv",
    "nvram_set_adv": "libinject_nvram_set_adv",
    "nvram_state": "libinject_nvram_state",
    "envram_commit": "libinject_envram_commit",
    "envram_default": "libinject_envram_default",
    "envram_load": "libinject_envram_load",
    "envram_safe_load": "libinject_envram_safe_load",
    "envram_match": "libinject_envram_match",
    "envram_get": "libinject_envram_get",
    "envram_getf": "libinject_envram_getf",
    "envram_set": "libinject_envram_set",
    "envram_setf": "libinject_envram_setf",
    "envram_unset": "libinject_envram_unset"
}

ralink = {
    "nvram_bufget": "libinject_nvram_bufget",
    "nvram_bufset": "libinject_nvram_bufset"
}

# One to one mappings of orig fn to shim
base_names = {
    "nvram_init": "libinject_nvram_init",
    "nvram_reset": "libinject_nvram_reset",
    "nvram_clear": "libinject_nvram_clear",
    "nvram_close": "libinject_nvram_close",
    "nvram_commit": "libinject_nvram_commit",
    "nvram_get": "libinject_nvram_get",
    "nvram_safe_get": "libinject_nvram_safe_get",
    "nvram_default_get": "libinject_nvram_default_get",
    "nvram_get_buf": "libinject_nvram_get_buf",
    "nvram_get_int": "libinject_nvram_get_int",
    "nvram_getall": "libinject_nvram_getall",
    "nvram_set": "libinject_nvram_set",
    "nvram_set_int": "libinject_nvram_set_int",
    "nvram_unset": "libinject_nvram_unset",
    "nvram_safe_unset": "libinject_nvram_safe_unset",
    "nvram_list_add": "libinject_nvram_list_add",
    "nvram_list_exist": "libinject_nvram_list_exist",
    "nvram_list_del": "libinject_nvram_list_del",
    "nvram_match": "libinject_nvram_match",
    "nvram_invmatch": "libinject_nvram_invmatch",
    "nvram_parse_nvram_from_file": "libinject_parse_nvram_from_file",
}

# Alternative names for the same function
base_aliases = {
    # Some seem sort of reasonable/generic (load -> init?)
    "nvram_load": "libinject_nvram_init",
    "nvram_loaddefault": "libinject_ret_1",
    "_nvram_get": "libinject_nvram_get",
    "nvram_get_state": "libinject_nvram_get_int",
    "nvram_set_state": "libinject_nvram_set_int",
    "nvram_restore_default": "libinject_nvram_reset",
    "nvram_upgrade": "libinject_nvram_commit",
    "VCTGetPortAutoNegSetting": "libinject_ret_0_arg",
    "nvram_commit_adv": "libinject_nvram_commit",
    "nvram_check": "libinject_ret_1",
    "nvram_flag_set": "libinject_ret_1",
    "nvram_flag_reset": "libinject_ret_1",
    "get_default_mac": "libinject_ret_1",

    # getf/setf -> envram implementation
    "nvram_getf": "libinject_envram_getf",
    "nvram_setf": "libinject_envram_setf",

    # Master/slave -> ret 0
    "nvram_master_init": "libinject_ret_0",
    "nvram_slave_init": "libinject_ret_0",

    # _adv -> ret 1
    "nvram_unlock_adv": "libinject_ret_1",
    "nvram_lock_adv": "libinject_ret_1",

    # "WAN_" shims
    "WAN_ith_CONFIG_SET_AS_STR": "libinject_nvram_nset",
    "WAN_ith_CONFIG_SET_AS_INT": "libinject_nvram_nset_int",

    # Netgear (6250/6400) specific FirmAE hack
    "agApi_fwGetFirstTriggerConf": "libinject_ret_1_arg",
    "agApi_fwGetNextTriggerConf": "libinject_ret_1_arg",

    # Realtek specific FirmAE hacks
    "apmib_init": "libinject_ret_1",
    "apmib_reinit": "libinject_ret_1",
    "apmib_update": "libinject_ret_1",

    # Netgear (acos) specific FirmAE hack
    "acos_nvram_init": "libinject_nvram_init",
    "acos_nvram_get": "libinject_nvram_get",
    "acos_nvram_read": "libinject_nvram_get_buf",
    "acos_nvram_set": "libinject_nvram_set",
    "acos_nvram_loaddefault": "libinject_ret_1",
    "acos_nvram_unset": "libinject_nvram_unset",
    "acos_nvram_commit": "libinject_nvram_commit",
    "acosNvramConfig_init": "libinject_nvram_init",
    "acosNvramConfig_get": "libinject_nvram_get",
    "acosNvramConfig_read": "libinject_nvram_get_buf",
    "acosNvramConfig_set": "libinject_nvram_set",
    "acosNvramConfig_write": "libinject_nvram_set",
    "acosNvramConfig_unset": "libinject_nvram_unset",
    "acosNvramConfig_match": "libinject_nvram_match",
    "acosNvramConfig_invmatch": "libinject_nvram_invmatch",
    "acosNvramConfig_save": "libinject_nvram_commit",
    "acosNvramConfig_save_config": "libinject_nvram_commit",
    "acosNvramConfig_loadFactoryDefault": "libinject_ret_1",

    # D-Link specific FirmAE hacks
    "artblock_get": "libinject_nvram_get",
    "artblock_fast_get": "libinject_nvram_safe_get",
    "artblock_safe_get": "libinject_nvram_safe_get",
    "artblock_set": "libinject_nvram_set",

    # ASUS specific FirmAE hacks
    "envram_get_func": "libinject_envram_get",
    "envram_set_func": "libinject_envram_set",
    "envram_unset_func": "libinject_envram_unset",
}

# All variables together
default_lib_aliases = {k: v for x in [
    atheros_broadcom,
    realtek,
    netgear_acos,
    zyxel_or_edimax,
    ralink,
    base_names,
    base_aliases
] for k, v in x.items()}
