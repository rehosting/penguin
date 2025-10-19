from . import PatchGenerator

class PseudofilesTailored(PatchGenerator):
    '''
    For all missing pseudofiles we saw referenced during static analysis,
    try adding them with a default model
    '''
    def __init__(self, pseudofiles: dict) -> None:
        self.patch_name = "pseudofiles.dynamic"
        self.pseudofiles = pseudofiles
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        results = {}
        mtd_count = 0

        for section, file_names in self.pseudofiles.items():
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
