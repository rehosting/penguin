import os
from penguin.static_plugin import ConfigPatcherPlugin
from penguin import getColoredLogger
from penguin.arch import arch_end
from penguin.defaults import default_init_script, default_plugins, static_dir as STATIC_DIR
from penguin.utils import get_arch_subdir

logger = getColoredLogger("penguin.config_patchers")

import penguin
RESOURCES = os.path.join(os.path.dirname(penguin.__file__), "resources")

class BasePatch(ConfigPatcherPlugin):
    """
    Generate base config for static_files and default plugins
    """
    depends_on = ['ArchId', 'InitFinder', 'KernelVersionFinder']
    UNKNOWN_INIT: str = "UNKNOWN_FIX_ME"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = "base"

    def generate(self, patches: dict) -> dict:
        arch_info = self.prior_results.get('ArchId')
        inits = self.prior_results.get('InitFinder', [])
        self.kernel_versions = self.prior_results.get('KernelVersionFinder', {"selected_kernel": ""})

        self.set_arch_info(arch_info)

        if len(inits):
            self.igloo_init = inits[0]
        else:
            self.igloo_init = self.UNKNOWN_INIT
            logger.warning("Failed to find any init programs - config will need manual refinement")

        if 'mips' in self.arch_name or self.arch_name == "intel64":
            igloo_serial_major = 4
            igloo_serial_minor = 65
        elif self.arch_name in ['armel', 'aarch64']:
            igloo_serial_major = 204
            igloo_serial_minor = 65
        elif "powerpc" in self.arch_name:
            igloo_serial_major = 229
            igloo_serial_minor = 1
        elif self.arch_name == "loongarch64":
            igloo_serial_major = 4
            igloo_serial_minor = 65
        else:
            igloo_serial_major = 204
            igloo_serial_minor = 65

        result = {
            "core": {
                "arch": self.arch_name,
                "kernel": self.kernel_versions["selected_kernel"],
            },
            "env": {
                "igloo_init": self.igloo_init,
            },
            "pseudofiles": {
                "/dev/ttyS1": {
                    "read": {
                        "model": "zero",
                    },
                    "write": {
                        "model": "discard",
                    },
                    "ioctl": {
                        "*": {
                            "model": "return_const",
                            "val": 0,
                        }
                    }
                },
                "/dev/ttyAMA1": {
                    "read": {
                        "model": "zero",
                    },
                    "write": {
                        "model": "discard",
                    },
                    "ioctl": {
                        "*": {
                            "model": "return_const",
                            "val": 0,
                        }
                    }
                }
            },
            "static_files": {
                "/igloo/init": {
                    "type": "inline_file",
                    "contents": default_init_script,
                    "mode": 0o111,
                },
                "/igloo/utils/sh": {
                    "type": "symlink",
                    "target": "/igloo/utils/busybox",
                },
                "/igloo/utils/sleep": {
                    "type": "symlink",
                    "target": "/igloo/utils/busybox",
                },
                "/igloo/ltrace/*": {
                    "type": "host_file",
                    "mode": 0o444,
                    "host_path": os.path.join(*[STATIC_DIR, "ltrace", "*"]),
                },
                "/igloo/dylibs/*": {
                    "type": "host_file",
                    "mode": 0o755,
                    "host_path": os.path.join(STATIC_DIR, "dylibs", self.dylib_dir or self.arch_dir, "*"),
                },
                "/igloo/source.d/*": {
                    "type": "host_file",
                    "mode": 0o755,
                    "host_path": os.path.join(*[RESOURCES, "source.d", "*"]),
                },
                "/igloo/serial": {
                    "type": "dev",
                    "devtype": "char",
                    "major": igloo_serial_major,
                    "minor": igloo_serial_minor,
                    "mode": 0o666,
                }
            },
            "plugins": default_plugins,
        }

        guest_scripts_dir = os.path.join(STATIC_DIR, "guest-utils", "scripts")
        for f in os.listdir(guest_scripts_dir):
            result["static_files"][f"/igloo/utils/{f}"] = {
                "type": "host_file",
                "host_path": f"{guest_scripts_dir}/{f}",
                "mode": 0o755,
            }
        result["static_files"]["/igloo/utils/*"] = {
            "type": "host_file",
            "host_path": f"{STATIC_DIR}/{self.arch_dir}/*",
            "mode": 0o755,
        }

        return result

    def set_arch_info(self, arch_identified: str) -> None:
        arch, endian = arch_end(arch_identified)
        if arch is None:
            raise NotImplementedError(f"Architecture {arch_identified} not supported ({arch}, {endian})")

        if arch == "aarch64":
            self.arch_name = "aarch64"
        elif arch == "intel64":
            self.arch_name = "intel64"
        elif arch == "loongarch64":
            self.arch_name = "loongarch64"
        elif arch == "riscv64":
            self.arch_name = "riscv64"
        elif arch == "powerpc":
            self.arch_name = "powerpc"
        elif arch == "powerpc64":
            if endian == "el":
                self.arch_name = "powerpc64le"
            else:
                self.arch_name = "powerpc64"
        else:
            self.arch_name = arch + endian

        mock_config = {"core": {"arch": self.arch_name}}
        self.arch_dir = get_arch_subdir(mock_config)

        if arch_identified == "aarch64":
            self.dylib_dir = "arm64"
        elif arch_identified == "intel64":
            self.dylib_dir = "x86_64"
        elif arch_identified == "loongarch64":
            self.dylib_dir = "loongarch"
        elif "powerpc" in self.arch_name:
            self.dylib_dir = self.arch_name.replace("powerpc", "ppc")
        else:
            self.dylib_dir = self.arch_dir
