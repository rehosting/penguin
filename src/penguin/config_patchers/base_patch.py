import os
from penguin.defaults import default_plugins, default_init_script, static_dir as STATIC_DIR, RESOURCES
from penguin.utils import get_arch_subdir
from penguin.arch import arch_end
from . import PatchGenerator
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers.base_patch")

class BasePatch(PatchGenerator):
    '''
    Generate base config for static_files and default plugins
    '''
    UNKNOWN_INIT: str = "UNKNOWN_FIX_ME"

    def __init__(self, arch_info: str, inits: list, kernel_versions: dict) -> None:
        self.patch_name = "base"
        self.enabled = True

        self.set_arch_info(arch_info)
        self.kernel_versions = kernel_versions

        if len(inits):
            self.igloo_init = inits[0]
        else:
            self.igloo_init = self.UNKNOWN_INIT
            logger.warning("Failed to find any init programs - config will need manual refinement")

    def set_arch_info(self, arch_identified: str) -> None:
        '''
        Set architecture info for config patch.

        :param arch_identified: Identified architecture string.
        :type arch_identified: str
        '''
        # TODO: should we allow a config to be generated for an unsupported architecture?
        # For example, what if we're wrong and a user wants to customize this.
        arch, endian = arch_end(arch_identified)
        if arch is None:
            raise NotImplementedError(f"Architecture {arch_identified} not supported ({arch}, {endian})")

        # Map architecture names to config schema valid names
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
                self.arch_name = "powerpc64le"  # powerpc64el -> powerpc64le for config schema
            else:
                self.arch_name = "powerpc64"  # powerpc64eb -> powerpc64
        else:
            # For architectures like mips with endianness, construct the name
            self.arch_name = arch + endian

        mock_config = {"core": {"arch": self.arch_name}}
        self.arch_dir = get_arch_subdir(mock_config)

        if arch_identified == "aarch64":
            self.dylib_dir = "arm64"
        elif arch_identified == "intel64":
            self.dylib_dir = "x86_64"
        elif arch_identified == "loongarch64":
            self.dylib_dir = "loongarch"
        elif arch_identified in ["powerpc64", "powerpc64el"]:
            self.dylib_dir = "ppc64"
        else:
            self.dylib_dir = self.arch_dir

    def generate(self, patches: dict) -> dict:
        # Add serial device in pseudofiles
        # This is because arm uses ttyAMA (major 204) and mips uses ttyS (major 4).
        # XXX: For mips we use major 4, minor 65. For arm we use major 204, minor 65.
        # For powerpc: major 229, minor 1 (hvc1)
        if 'mips' in self.arch_name or self.arch_name == "x86_64":
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
                # Ensure guest can't interfere with our 2nd serial console - make it a null device
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
                # Add ltrace prototype files. They go in /igloo/ltrace because /igloo is treated as ltrace's /usr/share, and the files are normally in /usr/share/ltrace.
                "/igloo/ltrace/*": {
                    "type": "host_file",
                    "mode": 0o444,
                    "host_path": os.path.join(*[STATIC_DIR, "ltrace", "*"]),
                },

                # Dynamic libraries
                "/igloo/dylibs/*": {
                    "type": "host_file",
                    "mode": 0o755,
                    "host_path": os.path.join(STATIC_DIR, "dylibs", self.dylib_dir or self.arch_dir, "*"),
                },

                # Startup scripts
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

        # Always add our utilities into static files
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
