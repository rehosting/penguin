class V3:
    num = 3

    change_description = """
    We expose the config via hypercalls and no longer configure the guest with env plugin.
    igloo_init is now set in core instead of being set in env
    """

    fix_guide = """
    igloo_init is used by init.sh to launch the correct init program and is generated in static_patches/base.yaml
    In a project generated with `penguin init` config v2 init.sh will check the environment for igloo_init

    To migrate:
    1. set `core.igloo_init`

    2. update init.sh in static_patches/base.yaml to use get_config to obtain igloo_init:
    ```
    #ADD BEFORE `if` check for igloo_init
    igloo_init = $(/igloo/utils/get_config core.igloo_init)
    if [ ! -z "${igloo_init}" ]; then
    ```

    The auto-fix (if you say Y in the next step) will just set `core.igloo_init`=`env.igloo_init`
    `env.igloo_init` will be retained for backwards compability
    """

    example_old_config = dict(
        env=dict(
            igloo_init="/sbin/init"
        ),
        core=dict()
    )

    def auto_fix(config):
        config["core"]["igloo_init"] = config["env"]["igloo_init"]
