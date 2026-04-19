from penguin.static_plugin import ConfigPatcherPlugin

class ShimBusybox(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.shims.busybox"
        self.enabled = False

    def generate(self, patches: dict) -> dict:
        from .tar_helper import TarHelper
        from .shim_binaries import ShimBinaries
        files = TarHelper.get_all_members(self.fs_archive)
        return ShimBinaries(files).make_shims({
            "ash": "busybox",
            "sh": "busybox",
            "bash": "bash",
        })
