"""
Shim guest binaries (reboot/halt/insmod/shells/crypto tools) with igloo
utilities.
"""

import os

from penguin.config_patchers import RESOURCES, make_shims
from penguin.init_plugin import InitContext, InitPlugin


class ShimStopBins(InitPlugin):
    patch_name = "static.shims.stop_bins"
    order = 220

    def patch(self, ctx: InitContext) -> dict:
        return make_shims(ctx.archive_files, {
            "reboot": "exit0.sh",
            "halt": "exit0.sh",
        })


class ShimNoModules(InitPlugin):
    patch_name = "static.shims.no_modules"
    order = 230

    def patch(self, ctx: InitContext) -> dict:
        return make_shims(ctx.archive_files, {
            "insmod": "exit0.sh"
        })


class ShimBusybox(InitPlugin):
    patch_name = "static.shims.busybox"
    order = 240
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
        return make_shims(ctx.archive_files, {
            "ash": "busybox",
            "sh": "busybox",
            "bash": "bash",
        })


class ShimCrypto(InitPlugin):
    patch_name = "static.shims.crypto"
    order = 250
    enabled = False

    def patch(self, ctx: InitContext) -> dict | None:
        result = make_shims(ctx.archive_files, {
            "openssl": "openssl",
            "ssh-keygen": "ssh-keygen"
        })

        if not len(result.get("static_files", [])):
            # Nothing to shim, don't add the key copy
            return

        result["static_files"]["/igloo/keys/*"] = {
            "type": "host_file",
            "mode": 0o444,
            "host_path": os.path.join(*[RESOURCES, "static_keys", "*"])
        }

        return result
