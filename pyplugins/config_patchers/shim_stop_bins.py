from penguin.static_plugin import ConfigPatcherPlugin

class ShimStopBins(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.shims.stop_bins"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        from .tar_helper import TarHelper
        from .shim_binaries import ShimBinaries
        files = TarHelper.get_all_members(self.fs_archive)
        return ShimBinaries(files).make_shims({
            "reboot": "exit0.sh",
            "halt": "exit0.sh",
        })
