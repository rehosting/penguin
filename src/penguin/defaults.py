# This file contains default values for penguin configuration
# We specify a default init script, and a set of default plugins
# along with their descriptions and default settings.
from copy import deepcopy
from os.path import dirname

default_version = 2
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
default_pseudo_model = {
    "read": {
        "model": "zero",
    },
    "write": {
        "model": "discard",
    },
}
acos_pseudo_model = deepcopy(default_pseudo_model)
acos_pseudo_model["ioctl"] = {
    0x40046431: {"model": "return_const", "val": 1},
    0x80046431: {"model": "return_const", "val": 1},
    0x40046432: {"model": "return_const", "val": 1},
    0x80046432: {"model": "return_const", "val": 1},
}

default_pseudofiles = {
    "/dev/acos_nat_cli": acos_pseudo_model,
    "/dev/brcmboard": default_pseudo_model,
    "/dev/dsl_cpe_api": default_pseudo_model,
    "/dev/gpio": default_pseudo_model,
    "/dev/nvram": default_pseudo_model,
    "/dev/pib": default_pseudo_model,
    "/dev/sc_led": default_pseudo_model,
    "/dev/tca0": default_pseudo_model,
    "/dev/ticfg": default_pseudo_model,
    "/dev/watchdog": default_pseudo_model,
    "/dev/wdt": default_pseudo_model,
    "/dev/zybtnio": default_pseudo_model,
    "/proc/blankstatus": default_pseudo_model,
    "/proc/btnCnt": default_pseudo_model,
    "/proc/br_igmpProxy": default_pseudo_model,
    "/proc/BtnMode": default_pseudo_model,
    "/proc/gpio": default_pseudo_model,
    "/proc/led": default_pseudo_model,
    "/proc/push_button": default_pseudo_model,
    "/proc/rtk_promiscuous": default_pseudo_model,
    "/proc/rtk_vlan_support": default_pseudo_model,
    "/proc/RstBtnCnt": default_pseudo_model,
    "/proc/sw_nat": default_pseudo_model,
    "/proc/simple_config/reset_button_s": default_pseudo_model,
    "/proc/quantum/drv_ctl": default_pseudo_model,
    "/proc/rt3052/mii/ctrl": default_pseudo_model,
    "/proc/rt3052/mii/data": default_pseudo_model,
}

default_lib_aliases = {
    # string_introspection
    "strcmp": "libinject_strcmp",
    "strncmp": "libinject_strncmp",
    "getenv": "libinject_getenv",
    "strstr": "libinject_strstr",

    # atheros_broadcom
    "nvram_get_nvramspace": "libinject_nvram_get_nvramspace",
    "nvram_nget": "libinject_nvram_nget",
    "nvram_nset": "libinject_nvram_nset",
    "nvram_nset_int": "libinject_nvram_nset_int",
    "nvram_nmatch": "libinject_nvram_nmatch",

    # realtek
    "apmib_get": "libinject_apmib_get",
    "apmib_set": "libinject_apmib_set",

    # netgear_acos
    "WAN_ith_CONFIG_GET": "libinject_WAN_ith_CONFIG_GET",

    # zyxel_or_edimax
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
    "envram_unset": "libinject_envram_unset",

    # ralink
    "nvram_bufget": "libinject_nvram_bufget",
    "nvram_bufset": "libinject_nvram_bufset",

    # One to one mappings of orig fn to shim
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

    # Alternative names for the same function
    "nvram_load": "libinject_nvram_init",
    "nvram_loaddefault": "libinject_ret_1",
    "_nvram_get": "libinject_nvram_get",
    "nvram_get_state": "libinject_nvram_get_int",
    "nvram_set_state": "libinject_nvram_set_int",
    "nvram_restore_default": "libinject_nvram_reset",
    "nvram_upgrade": "libinject_nvram_commit",
    "get_default_mac": "libinject_ret_1",
    "VCTGetPortAutoNegSetting": "libinject_ret_0_arg",
    "agApi_fwGetFirstTriggerConf": "libinject_ret_1_arg",
    "agApi_fwGetNextTriggerConf": "libinject_ret_1_arg",
    "artblock_get": "libinject_nvram_get",
    "artblock_fast_get": "libinject_nvram_safe_get",
    "artblock_safe_get": "libinject_nvram_safe_get",
    "artblock_set": "libinject_nvram_set",
    "nvram_flag_set": "libinject_ret_1",
    "nvram_flag_reset": "libinject_ret_1",
    "nvram_master_init": "libinject_ret_0",
    "nvram_slave_init": "libinject_ret_0",
    "apmib_init": "libinject_ret_1",
    "apmib_reinit": "libinject_ret_1",
    "apmib_update": "libinject_ret_1",
    "WAN_ith_CONFIG_SET_AS_STR": "libinject_nvram_nset",
    "WAN_ith_CONFIG_SET_AS_INT": "libinject_nvram_nset_int",
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
    "nvram_commit_adv": "libinject_nvram_commit",
    "nvram_unlock_adv": "libinject_ret_1",
    "nvram_lock_adv": "libinject_ret_1",
    "nvram_check": "libinject_ret_1",
    "envram_get_func": "libinject_envram_get",
    "nvram_getf": "libinject_envram_getf",
    "envram_set_func": "libinject_envram_set",
    "nvram_setf": "libinject_envram_setf",
    "envram_unset_func": "libinject_envram_unset",
}
