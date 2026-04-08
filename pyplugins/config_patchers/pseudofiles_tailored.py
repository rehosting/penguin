from penguin.static_plugin import ConfigPatcherPlugin

class PseudofilesTailored(ConfigPatcherPlugin):
    depends_on = ['PseudofileFinder']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "pseudofiles.dynamic"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        pseudofiles = self.prior_results.get('PseudofileFinder', {})
        results = {}
        mtd_count = 0

        for section, file_names in pseudofiles.items():
            for file_name in file_names:
                if section == 'dev' and file_name.startswith("/dev/mtd"):
                    continue

                if file_name.endswith("/"):
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
                    results[file_name]['ioctl'] = {
                        '*': {"model": "return_const", "val": 0}
                    }

                    if file_name.startswith("/dev/mtd"):
                        results[file_name]['name'] = f"uboot.{mtd_count}"
                        mtd_count += 1

        if len(results):
            return {'pseudofiles': results}
