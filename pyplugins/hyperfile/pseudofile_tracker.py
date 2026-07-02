"""
Pseudofile Tracker Plugin
=========================

This plugin tracks guest attempts to access missing pseudofiles and monitors
the configured pseudofile models.

Purpose
-------

- Monitors syscalls for -ENOENT and -ENOTTY to track missing pseudofile accesses.
- Logs access attempts to missing files in `pseudofiles_failures.yaml`, ranked
  by impact and annotated with a suggested starting model per path.
- Exports the currently configured pseudofile models to `pseudofiles_modeled.yaml`.

Output format
-------------

Entries in `pseudofiles_failures.yaml` are ranked by impact
(crashing_callers >> distinct_callers > hits):

```yaml
/dev/watchdog:
  impact: {hits: 243, distinct_callers: 2, crashing_callers: 0}
  callers: [init:1, watchdogd:412]
  events:
    ioctl:
      2147768064: {count: 240}
    open: {count: 3}
  suggest:
    read: {model: zero}
    ioctl: {'*': {model: return_const, val: 0}}
```

`suggest` is a valid `pseudofiles:` value: paste it into your config as
`pseudofiles: {<path>: <suggest block>}` and refine from there.

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
from typing import Optional, Union, List

from pydantic import Field
from penguin import Plugin, plugins, yaml, PluginArgs
from apis.syscalls import ValueFilter

outfile_missing = "pseudofiles_failures.yaml"
outfile_models = "pseudofiles_modeled.yaml"
crashes_file = "crashes.yaml"  # written by the crashes plugin (may be absent)

AT_FDCWD = -100

O_ACCMODE = 0o3
O_WRONLY = 0o1
O_RDWR = 0o2

# Impact-score weights: any crashing caller outranks any realistic number of
# distinct callers, which in turn outrank any raw hit count.
SCORE_CRASHING_CALLER = 1_000_000
SCORE_DISTINCT_CALLER = 1_000

failures_header = """\
# Guest accesses to unmodeled /dev, /proc, and /sys paths, ranked by impact
# (crashing_callers >> distinct_callers > hits).
#
# Each entry's `suggest` block is a heuristic starting model and is a valid
# `pseudofiles:` value -- paste it into your config as:
#   pseudofiles:
#     <path>:
#       <suggest block>
# then refine: swap a `zero` read for `const_buf` with real contents when a
# parser consumes the file, and confirm ioctl return values against the real
# driver's semantics.
"""

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


def open_access_intents(flags: int) -> set:
    """Map open(2) flags to the access intents implied by O_ACCMODE."""
    acc = flags & O_ACCMODE
    if acc == O_WRONLY:
        return {"write"}
    if acc == O_RDWR:
        return {"read", "write"}
    return {"read"}


def load_crashes(path: str):
    """
    Parse the crashes plugin's crashes.yaml into join keys.

    Returns (pairs, names): the set of (proc, pid) tuples and the set of proc
    names that crashed. Tolerates a missing/empty file (this plugin may run
    without crash tracking) and both the `{crashes: [...]}` dict and a bare
    list of records.
    """
    pairs, names = set(), set()
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        return pairs, names
    if isinstance(data, dict):
        data = data.get("crashes")
    if not isinstance(data, list):
        return pairs, names
    for crash in data:
        if not isinstance(crash, dict) or "proc" not in crash:
            continue
        names.add(crash["proc"])
        if isinstance(crash.get("pid"), int):
            pairs.add((crash["proc"], crash["pid"]))
    return pairs, names


def count_crashing_callers(callers: set, crash_pairs: set, crash_names: set) -> int:
    """
    Distinct callers of a path that later crashed. Prefer the exact
    (proc, pid) match; fall back to the proc name alone so a crash whose pid
    was recycled between the access and the fault still joins.
    """
    return sum(
        1 for name, pid in callers
        if (name, pid) in crash_pairs or name in crash_names
    )


def impact_score(impact: dict) -> int:
    return (
        impact["crashing_callers"] * SCORE_CRASHING_CALLER
        + impact["distinct_callers"] * SCORE_DISTINCT_CALLER
        + impact["hits"]
    )


def suggest_models(events: dict, intents: set) -> dict:
    """
    Heuristic starting model for a failing path, shaped as a valid
    `pseudofiles:` value so it pastes straight into a config.

    - open/stat ENOENT with read intent (or unknown intent) -> read: zero.
      The failure happens at open time, before any read size is observable,
      so small vs. large reads can't be distinguished here; `zero` (a
      one-byte "0" then EOF) is the safe default and the file header points
      users at const_buf when real contents matter.
    - open ENOENT with write intent -> write: discard.
    - ioctl ENOTTY -> catch-all return_const 0.
    """
    suggest = {}
    if "open" in events:
        if not intents or "read" in intents:
            suggest["read"] = {"model": "zero"}
        if "write" in intents:
            suggest["write"] = {"model": "discard"}
    if "ioctl" in events:
        suggest["ioctl"] = {"*": {"model": "return_const", "val": 0}}
    return suggest


class PseudofileTracker(Plugin):
    """
    Passively tracks missing file access and outputs telemetry logs.
    """

    class Args(PluginArgs):
        logging: Optional[Union[str, List[str]]] = Field(
            default=None,
            description="Which telemetry to log: 'all', 'missing', and/or 'modeled'. Defaults to 'all' when unset.",
        )

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
                yield from self._log_open_failure(proto, path, args)

    def _handle_enoent_arg1(self, regs, proto, syscall, dfd_raw, filename_ptr, *args):
        """Triggered when arg1 syscalls fail with -ENOENT."""
        fd = self.panda.from_unsigned_guest(syscall.retval)
        if fd == -self.ENOENT:
            # Cast dfd safely to a signed integer for AT_FDCWD
            dfd = self.panda.from_unsigned_guest(dfd_raw)
            filename = yield from mem.read_str(filename_ptr)
            if filename:
                path = yield from self._resolve_absolute_path(dfd, filename)
                yield from self._log_open_failure(proto, path, args)

    def _handle_ioctl_enotty(self, regs, proto, syscall, fd_arg, cmd, arg):
        """Triggered when ioctl returns -ENOTTY (-25)."""
        ret = self.panda.from_unsigned_guest(syscall.retval)
        if ret == -25:
            path = yield from osi.get_fd_name(fd_arg)
            if not path or not path_interesting(path):
                return
            if ignore_ioctl_path(path) or ignore_cmd(cmd):
                return
            caller = yield from self._get_caller()
            self.log_ioctl_failure(path, cmd, caller=caller)

    def _log_open_failure(self, proto, path, args):
        """Filter, attribute, and record an -ENOENT path failure."""
        path = self._normalize_path(path)
        if path is None:
            return
        caller = yield from self._get_caller()
        self.centralized_log(path, "open", caller=caller,
                             intents=self._open_intents(proto, args))

    def _open_intents(self, proto, args) -> set:
        """Access intents from the failing syscall, when it exposes them."""
        if proto.name in ("sys_open", "sys_openat") and args:
            return open_access_intents(args[0])
        if proto.name == "sys_creat":
            return {"write"}
        # stat/access/readlink and openat2 carry no O_ACCMODE flags
        return set()

    def _get_caller(self):
        """Identify the current process as (name, pid) (one portal round-trip)."""
        try:
            proc = yield from osi.get_proc()
            if proc is not None:
                return (proc.name, proc.pid)
        except Exception as e:
            self.logger.debug(f"Failed to resolve calling process: {e}")
        return None

    def record_default_hit(self, path, op, details=None):
        """Record that a synthesized default model actively served an access.

        Folds the hit into the same failures view as genuine -ENOENT/-ENOTTY
        failures (events default_read/default_write/default_ioctl), so an
        active default surfaces as "needs a real model". Called by the
        Pseudofiles plugin, already deduplicated per (op, cmd) at the model.
        """
        if not self.log_missing:
            return
        event = f"default_{op}"
        self.centralized_log(path, event, details or None)
        self.logger.debug(f"Default model served {op} on {path} {details or ''}")
        self.dump_results()

    # --- Telemetry & Logging Methods ---

    def _normalize_path(self, path):
        """Filter to pseudofile candidates; collapse PID paths to prevent log explosion."""
        if not path_interesting(path):
            return None
        return re.sub(r"/proc/\d+", "/proc/PID", path)

    def _record_for(self, path):
        return self.file_failures.setdefault(
            path, {"events": {}, "callers": set(), "intents": set()}
        )

    def centralized_log(self, path, event, caller=None, intents=None, event_details=None):
        record = self._record_for(path)

        first = event not in record["events"]
        ev = record["events"].setdefault(event, {"count": 0})
        ev["count"] += 1

        if caller:
            record["callers"].add(caller)
        if intents:
            record["intents"].update(intents)

        if event_details is not None:
            ev.setdefault("details", []).append(event_details)

        if first and self.log_missing:
            # Flush eagerly so results survive runs that never reach uninit
            # (SIGKILL, emulator crash) -- see rehosting/penguin#175.
            self.dump_results()

    def log_ioctl_failure(self, path, cmd, caller=None):
        record = self._record_for(path)
        ioctls = record["events"].setdefault("ioctl", {})

        first = cmd not in ioctls
        ioctls.setdefault(cmd, {"count": 0})["count"] += 1

        if caller:
            record["callers"].add(caller)

        if first:
            # Output intermediate results when a new missing IOCTL is detected
            if self.log_missing:
                self.dump_results()
            self.logger.debug(f"New ioctl failure observed: {cmd:x} on {path}")

    def _render_failures(self):
        """Shape internal state into the impact-ranked on-disk format."""
        # Re-read on every flush so crashes that happen after an access are
        # reflected in later dumps (and in the final one at uninit).
        crash_pairs, crash_names = load_crashes(pjoin(self.outdir, crashes_file))

        rendered = {}
        for path, record in self.file_failures.items():
            events = sort_file_failures(record["events"])
            impact = {
                "hits": get_total_counts(events),
                "distinct_callers": len(record["callers"]),
                "crashing_callers": count_crashing_callers(
                    record["callers"], crash_pairs, crash_names
                ),
            }
            entry = {"impact": impact}
            if record["callers"]:
                entry["callers"] = [
                    f"{name}:{pid}" for name, pid in sorted(record["callers"])
                ]
            entry["events"] = events
            suggest = suggest_models(record["events"], record["intents"])
            if suggest:
                entry["suggest"] = suggest
            rendered[path] = entry

        return dict(
            sorted(
                rendered.items(),
                key=lambda pair: impact_score(pair[1]["impact"]),
                reverse=True,
            )
        )

    def dump_results(self):
        """Flushes the impact-ranked failures telemetry to disk."""
        if not self.outdir:
            return
        text = yaml.dump(self._render_failures(), sort_keys=False)
        # PyYAML can't emit comments, so annotate the suggest keys post-hoc.
        text = re.sub(
            r"^(\s+suggest:)$",
            r"\1  # TODO: heuristic starting point -- verify before relying on it",
            text,
            flags=re.MULTILINE,
        )
        with open(pjoin(self.outdir, outfile_missing), "w") as f:
            f.write(failures_header)
            f.write(text)

    def uninit(self):
        """Plugin teardown logic ensures final metrics are written."""
        if self.log_missing:
            self.dump_results()
