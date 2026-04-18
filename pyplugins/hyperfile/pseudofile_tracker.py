"""
Pseudofile Tracker Plugin
=========================

This plugin tracks guest attempts to access missing pseudofiles and monitors
the configured pseudofile models.

Purpose
-------

- Monitors syscalls for -ENOENT and -ENOTTY to track missing pseudofile accesses.
- Logs access attempts to missing files in `pseudofiles_failures.yaml`.
- Exports the currently configured pseudofile models to `pseudofiles_modeled.yaml`.

Usage
-----

Simply add this plugin to your configuration:
```yaml
core:
  plugins:
    - pseudofile_tracker
"""

import logging
import posixpath
import re
from os.path import join as pjoin

from penguin import Plugin, plugins, yaml
from apis.syscalls import ValueFilter

outfile_missing = "pseudofiles_failures.yaml"
outfile_models = "pseudofiles_modeled.yaml"

AT_FDCWD = -100

mem = plugins.mem
syscalls = plugins.syscalls
osi = plugins.osi

def path_interesting(path: str) -> bool:
    """Determines if a path is likely to be a good candidate for pseudofiles."""
    if "/pipe:[" in path:
        return False
    if "\\" in path:
        return False
    if path.startswith("/dev/") or path.startswith("/proc/") or path.startswith("/sys/"):
        return True
    return False

def ignore_cmd(ioctl: int) -> bool:
    """Ignore TTY ioctls, see ioctls.h for T*, TC*, and TIO* ioctls."""
    return 0x5400 <= ioctl <= 0x54FF

def ignore_ioctl_path(path: str) -> bool:
    """Filter out ioctl paths that are irrelevant to rehosting."""
    if path.startswith("/firmadyne/libnvram"):
        return True
    if path.startswith("/proc/"):
        return True
    if path.startswith("socket:"):
        return True
    if "/pipe:[" in path:
        return True
    return False

def get_total_counts(d) -> int:
    """Get the sum of all "count" values in a nested dictionary."""
    return (
        (d["count"] if "count" in d else sum(map(get_total_counts, d.values())))
        if isinstance(d, dict) else 0
    )

def sort_file_failures(d):
    """Recursively sorts the file failures dictionary by total event count."""
    return (
        dict(
            sorted(
                ((k, sort_file_failures(v)) for k, v in d.items()),
                key=lambda pair: get_total_counts(pair[1]),
                reverse=True,
            )
        )
        if isinstance(d, dict) else d
    )

class PseudofileTracker(Plugin):
    """
    Passively tracks missing file access and outputs telemetry logs.
    """
    
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.config = self.get_arg("conf")
        
        if self.get_arg_bool("verbose"):
            self.logger.setLevel(logging.DEBUG)
    
        self.logging_enabled = self.get_arg("logging")
        if self.logging_enabled is None:
            self.logging_enabled = "all"
    
        self.log_missing = "all" in self.logging_enabled or "missing" in self.logging_enabled
        self.log_modeled = "all" in self.logging_enabled or "modeled" in self.logging_enabled
    
        self.ENOENT = 2
        self.file_failures = {}
    
        # 1. Output the Models File
        if self.log_modeled and self.config and "pseudofiles" in self.config:
            with open(pjoin(self.outdir, outfile_models), "w") as f:
                yaml.dump(self.config["pseudofiles"], f, sort_keys=False)
                self.logger.debug(f"Dumped pseudofile config models to {outfile_models}")
    
        # 2. Subscribe to Failure Events
        if self.log_missing:
            self.dump_results()  # Clear/initialize the failures log
            self._register_syscall_handlers()

    def _resolve_absolute_path(self, dfd, filename):
        """Resolves relative filenames to absolute paths using OSI."""
        if filename.startswith("/"):
            return filename

        try:
            if not hasattr(plugins, "osi"):
                return filename
                
            base_dir = yield from osi.get_fd_name(dfd)
            if base_dir:
                return posixpath.normpath(posixpath.join(base_dir, filename))
                
        except Exception as e:
            self.logger.debug(f"Failed to resolve relative path '{filename}' with dfd {dfd}: {e}")
            
        return filename

    def _register_syscall_handlers(self):
        # By not defining string_filters here, we capture ALL -ENOENTs,
        # allowing our Python handlers to cleanly resolve relative paths
        # before running them against path_interesting().

        # ---------------------------------------------------------
        # 1. Path at Arg 0 (e.g. sys_open, sys_stat)
        # ---------------------------------------------------------
        arg0_syscalls = [
            "sys_open", "sys_stat", "sys_lstat", "sys_access",
            "sys_stat64", "sys_lstat64", "sys_newstat", "sys_newlstat",
            "sys_readlink", "sys_old_stat", "sys_old_lstat", "sys_creat"
        ]
        for sc in arg0_syscalls:
            syscalls.syscall(
                sc, on_return=True,
                retval_filter=ValueFilter.exact(-self.ENOENT)
            )(self._handle_enoent_arg0)

        # ---------------------------------------------------------
        # 2. Path at Arg 1 (e.g. sys_openat, sys_statx)
        # ---------------------------------------------------------
        arg1_syscalls = [
            "sys_openat", "sys_openat2", "sys_newfstatat", 
            "sys_faccessat", "sys_faccessat2", "sys_statx", "sys_readlinkat",
            "sys_fstatat64", "sys_fstatat"
        ]
        for sc in arg1_syscalls:
            syscalls.syscall(
                sc, on_return=True,
                retval_filter=ValueFilter.exact(-self.ENOENT)
            )(self._handle_enoent_arg1)

        # ---------------------------------------------------------
        # 3. sys_ioctl
        # ---------------------------------------------------------
        # Only "sys_ioctl" is needed because the C proxy's normalize_syscall_name 
        # transparently folds "compat_sys_ioctl" into the same hash bucket!
        syscalls.syscall(
            "sys_ioctl", on_return=True,
            retval_filter=ValueFilter.exact(-25)  # -ENOTTY
        )(self._handle_ioctl_enotty)


    # --- Handlers ---

    def _handle_enoent_arg0(self, regs, proto, syscall, filename_ptr, *args):
        """Triggered when arg0 syscalls fail with -ENOENT."""
        fd = self.panda.from_unsigned_guest(syscall.retval)
        if fd == -self.ENOENT:
            filename = yield from mem.read_str(filename_ptr)
            if filename:
                path = yield from self._resolve_absolute_path(AT_FDCWD, filename)
                self.centralized_log(path, "open")

    def _handle_enoent_arg1(self, regs, proto, syscall, dfd_raw, filename_ptr, *args):
        """Triggered when arg1 syscalls fail with -ENOENT."""
        fd = self.panda.from_unsigned_guest(syscall.retval)
        if fd == -self.ENOENT:
            # Cast dfd safely to a signed integer for AT_FDCWD
            dfd = self.panda.from_unsigned_guest(dfd_raw)
            filename = yield from mem.read_str(filename_ptr)
            if filename:
                path = yield from self._resolve_absolute_path(dfd, filename)
                self.centralized_log(path, "open")

    def _handle_ioctl_enotty(self, regs, proto, syscall, fd_arg, cmd, arg):
        """Triggered when ioctl returns -ENOTTY (-25)."""
        ret = self.panda.from_unsigned_guest(syscall.retval)
        if ret == -25:
            path = yield from osi.get_fd_name(fd_arg)
            if path and path_interesting(path):
                self.log_ioctl_failure(path, cmd)

    # --- Telemetry & Logging Methods ---

    def centralized_log(self, path, event, event_details=None):
        if not path_interesting(path):
            return
    
        if path.startswith("/proc/"):
            # Collapse PID paths to prevent log explosion
            path = re.sub(r"/proc/\d+", "/proc/PID", path)
    
        if path not in self.file_failures:
            self.file_failures[path] = {}
    
        if event not in self.file_failures[path]:
            self.file_failures[path][event] = {"count": 0}
    
        if "count" not in self.file_failures[path][event]:
            self.file_failures[path][event]["count"] = 0
    
        self.file_failures[path][event]["count"] += 1
    
        if event_details is not None:
            if "details" not in self.file_failures[path][event]:
                self.file_failures[path][event]["details"] = []
            self.file_failures[path][event]["details"].append(event_details)
    
    def log_ioctl_failure(self, path, cmd):
        if ignore_ioctl_path(path) or ignore_cmd(cmd):
            return
    
        if path not in self.file_failures:
            self.file_failures[path] = {}
    
        if "ioctl" not in self.file_failures[path]:
            self.file_failures[path]["ioctl"] = {}
    
        first = False
        if cmd not in self.file_failures[path]["ioctl"]:
            self.file_failures[path]["ioctl"][cmd] = {"count": 0}
            first = True
    
        self.file_failures[path]["ioctl"][cmd]["count"] += 1
        
        if first:
            # Output intermediate results when a new missing IOCTL is detected
            if self.log_missing:
                self.dump_results()
            self.logger.debug(f"New ioctl failure observed: {cmd:x} on {path}")
    
    def dump_results(self):
        """Flushes the sorted failures telemetry to disk."""
        if not self.outdir:
            return
        with open(pjoin(self.outdir, outfile_missing), "w") as f:
            out = sort_file_failures(self.file_failures)
            yaml.dump(out, f, sort_keys=False)
    
    def uninit(self):
        """Plugin teardown logic ensures final metrics are written."""
        if self.log_missing:
            self.dump_results()