import os
import re
from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class KernelModules(ConfigPatcherPlugin):
    depends_on = ['KernelVersionFinder']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.kernel_modules"
        self.enabled = True

    @staticmethod
    def is_kernel_version(name: str) -> bool:
        return re.match(r"^\d+\.\d+\.\d+(-[\w\.]+)?$", name) is not None

    @staticmethod
    def pad_kernel_version(ver: str) -> str:
        base = ver.split("-", 1)[0]
        tokens = base.split(".")
        while len(tokens) < 3:
            tokens.append("0")
        return ".".join(tokens)

    def generate(self, patches: dict) -> dict:
        self.kernel_version = self.prior_results.get('KernelVersionFinder', {})
        if not self.kernel_version or "selected_kernel" not in self.kernel_version:
            return {}

        result = defaultdict(dict)
        kernel_version = None
        potential_kernels = set()

        modules_path = os.path.join(self.extracted_fs, "lib/modules")
        if os.path.exists(modules_path):
            for d in os.listdir(modules_path):
                d_path = os.path.join(modules_path, d)
                if os.path.isdir(d_path):
                    potential_kernels.add(d)

        potential_kernels = {d for d in potential_kernels if self.is_kernel_version(d)}

        if len(potential_kernels) == 1:
            kernel_version = potential_kernels.pop()
        elif len(potential_kernels) > 1:
            for potential_name in potential_kernels:
                if "." in potential_name and "-" in potential_name:
                    kernel_version = potential_name
                    break
            if not kernel_version:
                for potential_name in potential_kernels:
                    if "." in potential_name:
                        kernel_version = potential_name
                        break
            if not kernel_version:
                logger.warning(
                    "Multiple kernel versions look valid (TODO improve selection logic, grabbing first)"
                )
                logger.warning(potential_kernels)
                kernel_version = potential_kernels.pop()

        if kernel_version:
            padded_selected = self.pad_kernel_version(self.kernel_version["selected_kernel"])
            padded_target = self.pad_kernel_version(kernel_version)
            result["static_files"][f"/lib/modules/{padded_selected}"] = {
                "type": "symlink",
                "target": f"/lib/modules/{padded_target}",
            }

        return result
