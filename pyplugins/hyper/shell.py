"""
# Shell Coverage Plugin

This module implements the Shell Coverage (BBCov) plugin for the Penguin hypervisor environment.
It tracks shell script execution coverage, traces, and environment variable usage by listening to
hypercall events from the guest. The plugin writes coverage, trace, and environment information
to CSV files for later analysis.

## Usage

The plugin is loaded by the Penguin framework and responds to "igloo_shell" events.

### Output Files

- `shell_cov.csv`: Coverage data (filename, line number, pid)
- `shell_cov_trace.csv`: Trace data (filename:lineno, contents)
- `shell_env.csv`: Environment variable data (filename, lineno, pid, envs)

## Arguments

- `outdir`: Output directory for generated CSV files.
- `fs`: Path to the tar archive containing the filesystem.
- `verbose`: If set, enables debug logging.

## Classes

- `BBCov`: Main plugin class for handling shell coverage and environment logging.

"""

import tarfile
from os.path import join

from penguin import plugins, Plugin
from typing import Any, Optional

HC_CMD_LOG_LINENO = 0
HC_CMD_LOG_ENV_ARGS = 1

outfile_cov = "shell_cov.csv"
outfile_trace = "shell_cov_trace.csv"
outfile_env = "shell_env.csv"


class BBCov(Plugin):
    """
    BBCov is a plugin that logs shell script coverage, traces, and environment variable usage.

    **Arguments:**
    - `outdir` (str): Output directory for generated CSV files.
    - `fs` (str): Path to the tar archive containing the filesystem.
    - `verbose` (bool): Enables debug logging if True.
    """

    def __init__(self, panda: Any) -> None:
        """
        Initialize the BBCov plugin.

        - Sets up output files for coverage, trace, and environment data.
        - Loads the filesystem tar archive.
        - Subscribes to the "igloo_shell" event.

        **Parameters:**
        - `panda` (Any): The PANDA instance.

        **Returns:** None
        """
        self.pointer_size = panda.bits // 8
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.fs_tar = self.get_arg("fs")
        self.fs_missing_files = set()

        self.read_scripts = {}  # filename -> contents
        self.last_line = None

        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # initialize outfiles:
        with open(join(self.outdir, outfile_cov), "w") as f:
            f.write("filename,lineno,pid\n")

        with open(join(self.outdir, outfile_trace), "w") as f:
            f.write("filename:lineno,contents\n")

        with open(join(self.outdir, outfile_env), "w") as f:
            f.write("filename,lineno,pid,envs\n")

        self.seen_unknown = set()
        plugins.subscribe(plugins.Events, "igloo_shell", self.igloo_shell_cb)

    def igloo_shell_cb(self, cpu: Any, hc_type: int, argptr: int, length: int) -> None:
        """
        Callback for handling igloo_shell hypercall events.

        **Parameters:**
        - `cpu` (Any): The CPU object.
        - `hc_type` (int): Hypercall type.
        - `argptr` (int): Pointer to arguments in guest memory.
        - `length` (int): Number of arguments.

        **Returns:** None
        """
        hc_type = hc_type & 0xFFFFFFFF
        length = length & 0xFFFFFFFF

        try:
            argv = self.panda.virtual_memory_read(
                cpu, argptr, self.pointer_size * length, fmt="ptrlist"
            )
        except ValueError:
            argv = []

        if hc_type == HC_CMD_LOG_LINENO:
            self.log_line_no(cpu, argv)
            return
        elif hc_type == HC_CMD_LOG_ENV_ARGS:
            self.log_env_args(cpu, argv)
            return

        if hc_type not in self.seen_unknown:
            self.seen_unknown.add(hc_type)
            self.logger.debug(f"Shell: unknown hc_type : {hc_type:x}")

    def log_line_no(self, cpu: Any, argv: list) -> None:
        """
        Log coverage information for a shell script line.

        **Parameters:**
        - `cpu` (Any): The CPU object.
        - `argv` (list): List of argument pointers.

        **Returns:** None
        """
        if len(argv) != 3:
            self.logger.warning(f"Invalid argv in log_line_no: {argv}")
            return
        file_str_ptr, lineno_ptr, pid_ptr = argv

        filename = self.try_read_string(cpu, file_str_ptr)
        if filename is None:
            filename = f"[error reading guest memory at {file_str_ptr:#x}]"
        if filename.startswith("/igloo/"):
            return
        lineno = self.try_read_int(cpu, lineno_ptr)
        pid = self.try_read_int(cpu, pid_ptr)

        # Populate read_scripts or fs_missing_files with this script
        if filename not in self.read_scripts and filename not in self.fs_missing_files:
            # Read filename as a path out of self.fs_tar which is a tar arcive
            with tarfile.open(self.fs_tar, "r") as tar:
                try:
                    f = tar.extractfile("." + filename)
                    if f:
                        self.read_scripts[filename] = (
                            f.read().decode("latin-1", errors="replace").splitlines()
                        )
                    else:
                        self.fs_missing_files.add(filename)
                except KeyError:
                    self.fs_missing_files.add(filename)

        # Read the line out of the file, if we can
        try:
            line = self.read_scripts[filename][lineno - 1]
        except (KeyError, IndexError):
            line = None

        # If we get here and still have a last line, we need to dump it
        if self.last_line is not None:
            old_filename, old_lineno, old_line = self.last_line
            self.last_line = None
            with open(join(self.outdir, outfile_trace), "a") as f:
                f.write(f"{old_filename}:{old_lineno},{old_line}\n")

        if line:
            self.last_line = (filename, lineno, line)
        else:
            self.last_line = None

        with open(join(self.outdir, outfile_cov), "a") as f:
            f.write(f"{filename},{lineno},{pid}\n")

    def log_env_args(self, cpu: Any, argv: list) -> None:
        """
        Log environment variable information for a shell script line.

        **Parameters:**
        - `cpu` (Any): The CPU object.
        - `argv` (list): List of argument pointers.

        **Returns:** None
        """
        if len(argv) != 6:
            self.logger.warning(f"Invalid argv in log_env_args: {argv}")
            return
        file_str_ptr, lineno_ptr, pid_ptr, envs_ptr, env_vals_ptr, envs_count_ptr = argv
        filename = self.try_read_string(cpu, file_str_ptr)
        if filename is None:
            filename = f"[error reading guest memory at {file_str_ptr:#x}]"

        if filename.startswith("/igloo/"):
            return
        lineno = self.try_read_int(cpu, lineno_ptr)
        pid = self.try_read_int(cpu, pid_ptr)

        try:
            envs_count = self.panda.virtual_memory_read(
                cpu, envs_count_ptr, 4, fmt="int"
            )

            env_str_ptrs = self.panda.virtual_memory_read(
                cpu, envs_ptr, self.pointer_size * envs_count, fmt="ptrlist"
            )
            env_vals_ptrs = self.panda.virtual_memory_read(
                cpu, env_vals_ptr, self.pointer_size * envs_count, fmt="ptrlist"
            )

            env_names = [self.try_read_string(
                cpu, ptr) for ptr in env_str_ptrs]
            env_vals = [self.try_read_string(cpu, ptr)
                        for ptr in env_vals_ptrs]

            envs = list(zip(env_names, env_vals))
        except ValueError:
            envs = []

        if self.last_line is not None:
            # If we just got env info for the last line, let's write it out with data now
            if (
                self.last_line[2]
                and self.last_line[0] == filename
                and self.last_line[1] == lineno
            ):
                line = self.last_line[2]

                # We want to replace "$anything" with "$anything(=VALUE)" for each env
                for varname, val in envs:
                    if val is None:
                        val = "UNSET"
                    line = line.replace(f"${varname}", f"$({varname}=>{val})")
                    line = line.replace(
                        f"${{{varname}}}", f"${{{varname}=>{val}}}")

                self.last_line = None
                with open(join(self.outdir, outfile_trace), "a") as f:
                    f.write(f"{filename}:{lineno},{line}\n")

        with open(join(self.outdir, outfile_env), "a") as f:
            f.write(f"{filename},{lineno},{pid},{envs}\n")

    def try_read_string(self, cpu: Any, ptr: int) -> Optional[str]:
        """
        Attempt to read a string from guest memory.

        **Parameters:**
        - `cpu` (Any): The CPU object.
        - `ptr` (int): Pointer to the string in guest memory.

        **Returns:**
        - `Optional[str]`: The string read, or None if not available.
        """
        if ptr == 0:
            return None

        try:
            return self.panda.read_str(cpu, ptr)
        except ValueError:
            return "[virtual mem read fail]"

    def try_read_int(self, cpu: Any, ptr: int) -> Optional[int]:
        """
        Attempt to read an integer from guest memory.

        **Parameters:**
        - `cpu` (Any): The CPU object.
        - `ptr` (int): Pointer to the integer in guest memory.

        **Returns:**
        - `Optional[int]`: The integer read, or None if not available.
        """
        if ptr == 0:
            return None

        try:
            return self.panda.virtual_memory_read(cpu, ptr, 4, fmt="int")
        except ValueError:
            return "[virtual mem read fail]"
