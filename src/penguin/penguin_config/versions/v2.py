class V2:
    num = 2

    change_description = """
    All libnvram functions now have a `libinject_` prefix.
    This prevents overriding more library functions than intended.
    """

    new_aliases = {
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
    }

    fix_guide = """
    In `lib_inject.aliases`,

    1. Change `'true'` to `libinject_ret_1`,
    `'false'` to `libinject_ret_0`,
    `'true1'` to `libinject_ret_1_arg`,
    and `'false1'` to `libinject_ret_0_arg`.

    2. Replace `nvram_loaddefault` in the right side with `libinject_ret_1`.

    3. Add the `libinject_` prefix to names of libnvram functions.

    4. Add aliases of the form `X: libinject_X` for all the prefixed functions.
    https://github.com/rehosting/libnvram/commit/5cdd5156c777f497361d86c1c7f166ed9005a6f3
    """

    example_old_config = dict(
        lib_inject=dict(
            aliases=dict(
                nvram_load="nvram_init",
                nvram_loaddefault="true",
                nvram_get_state="nvram_get_int",
                nvram_set_state="nvram_set_int",
                nvram_restore_default="nvram_reset",
            )
        )
    )

    def auto_fix(config):
        aliases = config["lib_inject"]["aliases"]
        for k, v in aliases.items():
            match v:
                case "true":
                    aliases[k] = "libinject_ret_1"
                case "false":
                    aliases[k] = "libinject_ret_0"
                case "true1":
                    aliases[k] = "libinject_ret_1_arg"
                case "false1":
                    aliases[k] = "libinject_ret_0_arg"
                case "nvram_loaddefault":
                    aliases[k] = "libinject_ret_1"
                case _:
                    aliases[k] = f"libinject_{v}"

        config["lib_inject"]["aliases"] = aliases | V2.new_aliases
