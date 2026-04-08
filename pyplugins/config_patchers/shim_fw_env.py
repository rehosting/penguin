from penguin.static_plugin import ConfigPatcherPlugin

class ShimFwEnv(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("Untested shim type")
        super().__init__(*args, **kwargs)
        self.patch_name = "static.shims.fw_env"

    def generate(self, patches: dict) -> dict:
        from .tar_helper import TarHelper
        from .shim_binaries import ShimBinaries
        files = TarHelper.get_all_members(self.fs_archive)
        return ShimBinaries(files).make_shims({
            "fw_printenv": "fw_printenv",
            "fw_getenv": "fw_printenv",
            "fw_setenv": "fw_printenv",
        })
