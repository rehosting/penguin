"""
# Kernel Module Tracker

This plugin tracks and controls kernel module loading attempts in the guest system.
By default, it blocks all kernel module loading except for igloo.ko (the internal
framework module). Optionally, an allowlist can be configured to allow specific
kernel modules to load, or a denylist to explicitly block specific modules.

## Features

- Intercepts `init_module` and `finit_module` syscalls
- Tracks all kernel module loading attempts to `modules.log`
- Blocks module loading (except igloo.ko) by default
- Supports allowlist for specific modules to allow them to load
- Supports denylist for explicit blocking of specific modules

## Configuration

To enable the plugin with default behavior (block all except igloo.ko):

```yaml
plugins:
  kmods: {}
```

To allow specific modules to load, provide an allowlist:

```yaml
plugins:
  kmods:
    allowlist:
      - wireguard
      - nf_conntrack
      - xt_TCPMSS
```

To explicitly block specific modules, provide a denylist:

```yaml
plugins:
  kmods:
    denylist:
      - suspicious_module
      - untrusted_driver
```

To reduce logging verbosity, enable quiet mode:

```yaml
plugins:
  kmods:
    quiet: true
```

Both lists can be used together. Denylist takes precedence over allowlist.
Module names should not include the `.ko` extension or path.
When `quiet` is set to `true`, only errors are logged; otherwise, info-level logs are shown (default).

## Outputs

- `modules.log`: List of all kernel modules that were attempted to be loaded
"""

import logging
from typing import Optional
from penguin import plugins, Plugin


class KmodTracker(Plugin):
    """
    Tracks and controls kernel module loading in the guest system.

    This plugin intercepts kernel module loading syscalls and can either block
    them (default behavior), allow specific modules via allowlist, or explicitly
    block specific modules via denylist.

    Attributes:
        allowlist (list): List of kernel module names allowed to load
        denylist (list): List of kernel module names to explicitly block
        quiet (bool): If True, set log level to error; if False, use info level
    """

    def __init__(self):
        """Initialize the KmodTracker plugin and load configuration."""
        # Get allowlist of kernel modules that are allowed to be loaded
        self.allowlist = self.get_arg("allowlist") or []
        # Get denylist of kernel modules that are explicitly blocked
        self.denylist = self.get_arg("denylist") or []
        # Get quiet mode setting (defaults to False)
        self.quiet = self.get_arg("quiet") or False

        # Set log level based on quiet mode
        if self.quiet:
            self.logger.setLevel(logging.ERROR)
        else:
            self.logger.setLevel(logging.INFO)

    def _extract_module_name(self, kmod_path: str) -> Optional[str]:
        """
        Extract the module name from the full path.

        Args:
            kmod_path (str): Full path to the kernel module

        Returns:
            Optional[str]: Module name without path or .ko extension,
            or None if kmod_path is empty
        """
        if not kmod_path:
            return None

        module_name = kmod_path.split('/')[-1]
        if module_name.endswith('.ko'):
            module_name = module_name[:-3]

        return module_name

    def is_allowed(self, kmod_path: str) -> bool:
        """
        Check if a kernel module is in the allowlist.
        Extracts the module name from the path and checks against allowlist.

        Args:
            kmod_path: Path to the kernel module (e.g., "/lib/modules/foo.ko")

        Returns:
            True if the module is in the allowlist, False otherwise
        """
        if not kmod_path:
            return False

        # Extract module name from path (remove directory and .ko extension)
        module_name = self._extract_module_name(kmod_path)

        return module_name in self.allowlist

    def is_denied(self, kmod_path: str) -> bool:
        """
        Check if a kernel module is in the denylist.
        Extracts the module name from the path and checks against denylist.

        Args:
            kmod_path: Path to the kernel module (e.g., "/lib/modules/foo.ko")

        Returns:
            True if the module is in the denylist, False otherwise
        """
        if not kmod_path:
            return False

        # Extract module name from path (remove directory and .ko extension)
        module_name = self._extract_module_name(kmod_path)

        return module_name in self.denylist

    def track_kmod(self, kmod_path: str):
        """
        Track a kernel module loading attempt by recording it to modules.log.

        Args:
            kmod_path (str): Path to the kernel module being loaded
        """
        self.logger.info(f"Tracking kernel module: {kmod_path}")
        with open(self.get_arg("outdir") + "/modules.log", "a") as f:
            f.write(f"{kmod_path}\n")

    @plugins.syscalls.syscall("on_sys_init_module_enter")
    def init_module(self, regs, proto, syscall, module_image, size, param_values):
        """
        Handle the init_module syscall to track and optionally block module loading.

        This method intercepts attempts to load kernel modules via the init_module
        syscall. It always allows igloo.ko to load, tracks all other module loading
        attempts, and blocks modules unless they are allow-listed.

        Args:
            regs: CPU register state
            proto: Syscall prototype
            syscall: Syscall object with retval and skip_syscall attributes
            module_image: Pointer to module image in memory
            size: Size of the module image
            param_values: Module parameters

        Yields:
            Results from plugins.osi calls for process and file descriptor information
        """
        # Determine if this is our module!
        args = yield from plugins.osi.get_args()
        igloo_mod_args = ['/igloo/utils/busybox', 'insmod', '/igloo/boot/igloo.ko']
        if args == igloo_mod_args:
            return

        # Determine the module path
        kmod_path = None

        # Check args for .ko file
        matching_ko = [arg for arg in args if arg.endswith('.ko')]
        if any(matching_ko):
            kmod_path = matching_ko[-1]
        elif any(arg for arg in args if arg.endswith('modprobe')):
            self.logger.info(f"modprobe detected, cannot determine module path from args: {args}")
            return
        else:
            # Check open fds for .ko file
            fds = yield from plugins.osi.get_fds()
            for i in range(len(fds)):
                fdname = fds[i].name
                if fdname.endswith('.ko'):
                    kmod_path = fdname
                    break

        if not kmod_path:
            self.logger.info(f"Could not determine kernel module path from args: {args}")

        # Track the module
        if kmod_path:
            self.track_kmod(kmod_path)

        # Check if module is explicitly denied (denylist takes precedence)
        if kmod_path and self.is_denied(kmod_path):
            self.logger.info(f"Blocking denied module: {kmod_path}")
            syscall.retval = 0
            syscall.skip_syscall = True
            return

        # Check if module is in allowlist
        if kmod_path and self.is_allowed(kmod_path):
            self.logger.info(f"Allowing module from allowlist to load: {kmod_path}")
            return

        # Block module loading by default (fake success)
        syscall.retval = 0
        syscall.skip_syscall = True

    @plugins.syscalls.syscall("on_sys_finit_module_enter")
    def finit_module(self, regs, proto, syscall, fd, param_values, flags):
        """
        Handle the finit_module syscall to track and optionally block module loading.

        This method intercepts attempts to load kernel modules via the finit_module
        syscall (which loads modules from a file descriptor). It tracks all module
        loading attempts and blocks modules unless they are allow-listed.

        Args:
            regs: CPU register state
            proto: Syscall prototype
            syscall: Syscall object with retval and skip_syscall attributes
            fd: File descriptor of the kernel module file
            param_values: Module parameters
            flags: Module loading flags

        Yields:
            Results from plugins.osi.get_fd_name to retrieve the module path
        """
        # Analyze information to determine the module path
        fdname = yield from plugins.osi.get_fd_name(fd)
        if not fdname:
            self.logger.error(f"Could not determine kernel module path from fd: {fd}")
            return
        self.track_kmod(fdname)

        # Check if module is explicitly denied (denylist takes precedence)
        if self.is_denied(fdname):
            self.logger.info(f"Blocking denied module: {fdname}")
            syscall.skip_syscall = True
            syscall.retval = 0
            return

        # Check if module is in allowlist
        if self.is_allowed(fdname):
            self.logger.info(f"Allowing module from allowlist to load: {fdname}")
            return

        # Block module loading by default (fake success)
        syscall.skip_syscall = True
        syscall.retval = 0
