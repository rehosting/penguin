from . import PatchGenerator
from collections import defaultdict
import os
import re

from penguin import getColoredLogger
logger = getColoredLogger("penguin.config_patchers")

class KernelModules(PatchGenerator):
    """
    Create a symlink from the guest kernel module path to our kernel's module path.
    (ie.., /lib/modules/1.2.0-custom -> /lib/modules/4.10.0)
    """
    def __init__(self, extract_dir: str, kernel_version: dict) -> None:
        self.patch_name = "static.kernel_modules"
        self.enabled = True
        self.extract_dir = extract_dir
        self.kernel_version = kernel_version

    @staticmethod
    def is_kernel_version(name: str) -> bool:
        # Regex to match typical kernel version patterns
        return re.match(r"^\d+\.\d+\.\d+(-[\w\.]+)?$", name) is not None

    # Always use a.b.c format for the symlink target
    @staticmethod
    def pad_kernel_version(ver: str) -> str:
        base = ver.split("-", 1)[0]
        tokens = base.split(".")
        while len(tokens) < 3:
            tokens.append("0")
        return ".".join(tokens)

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)

        # Identify original kernel version and create a symlink to /lib/modules
        kernel_version = None
        potential_kernels = set()

        # Only look at the top-level directories in self.extract_dir / lib / modules
        modules_path = os.path.join(self.extract_dir, "lib/modules")
        if os.path.exists(modules_path):
            for d in os.listdir(modules_path):
                d_path = os.path.join(modules_path, d)
                if os.path.isdir(d_path):
                    potential_kernels.add(d)

        # Filter potential kernels to match the expected version pattern
        potential_kernels = {d for d in potential_kernels if self.is_kernel_version(d)}

        # Determine the kernel version to use
        if len(potential_kernels) == 1:
            kernel_version = potential_kernels.pop()
        elif len(potential_kernels) > 1:
            # Prioritize the version names that match more complex patterns with dashes
            for potential_name in potential_kernels:
                if "." in potential_name and "-" in potential_name:
                    kernel_version = potential_name
                    break
            if not kernel_version:
                # Fallback to a simpler version matching pattern
                for potential_name in potential_kernels:
                    if "." in potential_name:
                        kernel_version = potential_name
                        break

            # Fallback to picking the first one (could improve this further)
            if not kernel_version:
                logger.warning(
                    "Multiple kernel versions look valid (TODO improve selection logic, grabbing first)"
                )
                logger.warning(potential_kernels)
                kernel_version = potential_kernels.pop()

        if kernel_version:
            # We have a kernel version, add it to our config
            padded_selected = self.pad_kernel_version(self.kernel_version["selected_kernel"])
            padded_target = self.pad_kernel_version(kernel_version)
            result["static_files"][f"/lib/modules/{padded_selected}"] = {
                "type": "symlink",
                "target": f"/lib/modules/{padded_target}",
            }

        return result
