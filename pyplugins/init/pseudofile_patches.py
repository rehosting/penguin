"""
Pseudofile model patches: FirmAE expert knowledge, models tailored from
filesystem references, and the FirmAE Linksys GPIO hack.
"""

import os

from collections import defaultdict

from penguin.defaults import expert_knowledge_pseudofiles
from penguin.init_plugin import InitContext, InitPlugin


class PseudofilesExpert(InitPlugin):
    '''
    Fixed set of pseudofile models from FirmAE.
    '''
    patch_name = "pseudofiles.expert_knowledge"
    order = 80

    def patch(self, ctx: InitContext) -> dict:
        return {'pseudofiles': expert_knowledge_pseudofiles}


class PseudofilesTailored(InitPlugin):
    '''
    For all missing pseudofiles we saw referenced during static analysis,
    try adding them with a default model
    '''
    patch_name = "pseudofiles.dynamic"
    order = 90

    def patch(self, ctx: InitContext) -> dict | None:
        pseudofiles = self.plugins.PseudofileFinder.pseudofiles
        results = {}
        mtd_count = 0

        for section, file_names in pseudofiles.items():
            for file_name in file_names:
                if section == 'dev' and file_name.startswith("/dev/mtd"):
                    # TODO: do we want to make placeholders for MTD or not?
                    continue

                if file_name.endswith("/"):
                    # We don't want to treat a directory as a pseudofile, instead we'll
                    # add a placehodler into the directory. This ensures the directory is created
                    # XXX: hyperfs doesn't allow userspace to create files in these directories yet
                    # https://github.com/rehosting/hyperfs/issues/20
                    file_name += ".placeholder"
                results[file_name] = {
                    'read': {
                        "model": "zero",
                    },
                    'write': {
                        "model": "discard",
                    }
                }

                if section == "dev":
                    # /dev files get a default IOCTL model
                    results[file_name]['ioctl'] = {
                        '*': {"model": "return_const", "val": 0}
                    }

                    if file_name.startswith("/dev/mtd"):
                        # MTD devices get a name (shows up in /proc/mtd)
                        # Note 'uboot' probably isn't right, but we need something
                        results[file_name]['name'] = f"uboot.{mtd_count}"
                        mtd_count += 1

        if len(results):
            return {'pseudofiles': results}


class LinksysHack(InitPlugin):
    '''
    Linksys specific hack from FirmAE with pseudofile model.
    '''
    patch_name = "pseudofiles.linksys"
    order = 200

    def patch(self, ctx: InitContext) -> dict:
        self.extract_dir = str(ctx.extracted_fs)
        result = defaultdict(dict)
        # TODO: The following changes from FirmAE should likely be disabled by default
        # as we can't consider this information as part of our search if it's in the initial config
        # Linksys specific hack from firmae
        if all(
            os.path.isfile(os.path.join(self.extract_dir, x[1:]))
            for x in ["/bin/gpio", "/usr/lib/libcm.so", "/usr/lib/libshared.so"]
        ):
            result["pseudofiles"]["/dev/gpio/in"] = {
                "read": {
                    "model": "return_const",
                    "val": 0xFFFFFFFF,
                }
            }

        return result
