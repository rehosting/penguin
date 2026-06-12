"""
Generate the base config: arch, kernel, init, serial devices, guest utilities,
and default plugins.
"""

import os

from penguin import getColoredLogger
from penguin import arch_registry
from penguin.arch import arch_end, get_dylib_subdir
from penguin.config_patchers import RESOURCES
from penguin.defaults import (
    default_init_script,
    default_plugins,
    static_dir as STATIC_DIR,
)
from penguin.init_plugin import InitContext, InitPlugin
from penguin.utils import get_arch_subdir

logger = getColoredLogger("penguin.init.base_patch")


class BasePatch(InitPlugin):
    '''
    Generate base config for static_files and default plugins
    '''
    UNKNOWN_INIT: str = "UNKNOWN_FIX_ME"

    patch_name = "base"
    order = 10
    # On unsupported/undetermined architecture this patch fails and is
    # skipped; init still completes and the resulting config needs core.arch
    # and core.kernel filled in manually before it can run.

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

        # Normalize the identified arch to its canonical config name so generated
        # configs use one spelling (e.g. x86_64, not intel64).
        self.arch_name = arch_registry.normalize_arch(self.arch_name)

        mock_config = {"core": {"arch": self.arch_name}}
        self.arch_dir = get_arch_subdir(mock_config)
        self.dylib_dir = get_dylib_subdir(self.arch_name)

    def patch(self, ctx: InitContext) -> dict:
        self.set_arch_info(self.plugins.ArchId.arch)
        self.kernel_versions = self.plugins.KernelVersionFinder.versions

        inits = self.plugins.InitFinder.inits
        if len(inits):
            self.igloo_init = inits[0]
        else:
            self.igloo_init = self.UNKNOWN_INIT
            logger.warning("Failed to find any init programs - config will need manual refinement")

        # Serial device major/minor varies by arch (arm uses ttyAMA major 204,
        # mips uses ttyS major 4, powerpc uses hvc1 major 229) — see arch_registry.
        igloo_serial_major, igloo_serial_minor = arch_registry.spec(self.arch_name).serial

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

                # Dynamic libraries. The arch subdir is left as a Jinja
                # template ({{ dylib_dir }}) and resolved at config-load time.
                "/igloo/dylibs/*": {
                    "type": "host_file",
                    "mode": 0o755,
                    "host_path": os.path.join(STATIC_DIR, "dylibs", "{{ dylib_dir }}", "*"),
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
                },
                "/dev/pts": {
                    "type": "dir",
                    "mode": 0o755,
                },
                "/dev/shm": {
                    "type": "dir",
                    "mode": 0o1777,
                },
                "/dev/fd": {
                    "type": "symlink",
                    "target": "/proc/self/fd",
                },
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
        # {{ arch_dir }} is resolved at config-load time from core.arch.
        result["static_files"]["/igloo/utils/*"] = {
            "type": "host_file",
            "host_path": f"{STATIC_DIR}/{{{{ arch_dir }}}}/*",
            "mode": 0o755,
        }

        return result
