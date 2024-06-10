from pandare import PyPlugin
from os.path import join
import tarfile
from penguin import getColoredLogger


# crc32("busybox")
EXPECTED_MAGIC = 0x8507fae1

HC_CMD_LOG_LINENO = 0
HC_CMD_LOG_ENV_ARGS = 1

outfile_cov = "shell_cov.csv"
outfile_trace = "shell_cov_trace.csv"
outfile_env = "shell_env.csv"

class BBCov(PyPlugin):
    def __init__(self, panda):
        self.pointer_size = panda.bits // 8
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.fs_tar = self.get_arg("fs")
        self.fs_missing_files = set()

        self.read_scripts = {} # filename -> contents
        self.last_line = None

        self.logger = getColoredLogger("plugins.shell")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # initialize outfiles:
        with open(join(self.outdir, outfile_cov), "w") as f:
            f.write("filename,lineno,pid\n")

        with open(join(self.outdir, outfile_trace), "w") as f:
            f.write("filename:lineno,contents\n")

        with open(join(self.outdir, outfile_env), "w") as f:
            f.write("filename,lineno,pid,envs\n")

        @self.panda.cb_guest_hypercall
        def cb_hypercall(cpu):
            magic = self.panda.arch.get_arg(cpu, 0, convention='syscall') & 0xFFFFFFFF
            if magic != EXPECTED_MAGIC:
                return False

            hc_type = self.panda.arch.get_arg(cpu, 1, convention="syscall")
            argptr =  self.panda.arch.get_arg(cpu, 2, convention='syscall')
            length = self.panda.arch.get_arg(cpu, 3, convention='syscall')

            hc_type = hc_type & 0xffffffff
            length = length & 0xffffffff

            try:
                argv = self.panda.virtual_memory_read(cpu, argptr, self.pointer_size * length, fmt="ptrlist")
            except ValueError:
                argv = []

            if hc_type == HC_CMD_LOG_LINENO:
                self.log_line_no(cpu, argv)
                return True

            elif hc_type == HC_CMD_LOG_ENV_ARGS:
                self.log_env_args(cpu, argv)
                return True

            return False

    def log_line_no(self, cpu, argv):
        if len(argv) != 3:
            self.logger.warning(f"Invalid argv in log_line_no: {argv}")
            return
        file_str_ptr, lineno_ptr, pid_ptr = argv

        filename = self.try_read_string(cpu, file_str_ptr)
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
                        self.read_scripts[filename] = f.read().decode("latin-1", errors='replace').splitlines()
                    else:
                        self.fs_missing_files.add(filename)
                except KeyError:
                    self.fs_missing_files.add(filename)
        
        # Read the line out of the file, if we can
        try:
            line = self.read_scripts[filename][lineno-1]
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

        # This is too verbose even for debug
        #self.logger.debug(f"filename: {filename}, lineno = {lineno}, pid = {pid}")
        with open(join(self.outdir, outfile_cov), "a") as f:
            f.write(f"{filename},{lineno},{pid}\n")

    def log_env_args(self, cpu, argv):
        if len(argv) != 6:
            self.logger.warning(f"Invalid argv in log_env_args: {argv}")
            return
        file_str_ptr, lineno_ptr, pid_ptr, envs_ptr, env_vals_ptr, envs_count_ptr = argv
        filename = self.try_read_string(cpu, file_str_ptr)
        if filename is None:
            # We failed to read guest virtual memory. Nothing we can do since we haven't setup
            # a good retry mechanism for this yet.
            filename = f'[error reading guest memory at {file_str_ptr:#x}]'

        if filename.startswith("/igloo/"):
            return
        lineno = self.try_read_int(cpu, lineno_ptr)
        pid = self.try_read_int(cpu, pid_ptr)

        try:
            envs_count = self.panda.virtual_memory_read(cpu, envs_count_ptr, 4, fmt='int')

            env_str_ptrs = self.panda.virtual_memory_read(
                cpu, envs_ptr, self.pointer_size * envs_count, fmt="ptrlist"
            )
            env_vals_ptrs = self.panda.virtual_memory_read(
                cpu, env_vals_ptr, self.pointer_size * envs_count, fmt="ptrlist"
            )

            env_names = [self.try_read_string(cpu, ptr) for ptr in env_str_ptrs]
            env_vals = [self.try_read_string(cpu, ptr) for ptr in env_vals_ptrs]

            envs = list(zip(env_names, env_vals))
        except ValueError:
            envs = []

        if self.last_line is not None:
            # If we just got env info for the last line, let's write it out with data now
            if self.last_line[2] and self.last_line[0] == filename and self.last_line[1] == lineno:
                line = self.last_line[2]

                # We want to replace "$anything" with "$anything(=VALUE)" for each env
                for (varname, val) in envs:
                    if val is None:
                        val = "UNSET"
                    line = line.replace(f"${varname}", f"$({varname}=>{val})")
                    line = line.replace(f"${{{varname}}}", f"${{{varname}=>{val}}}")

                self.last_line = None
                with open(join(self.outdir, outfile_trace), "a") as f:
                    f.write(f"{filename}:{lineno},{line}\n")

        #print(f"filename: {filename}, lineno = {lineno}, pid = {pid}, envs: {envs}")
        with open(join(self.outdir, outfile_env), "a") as f:
            f.write(f"{filename},{lineno},{pid},{envs}\n")

    def try_read_string(self, cpu, ptr):
        if ptr == 0:
            return None

        try:
            return self.panda.read_str(cpu, ptr)
        except ValueError:
            return "[virtual mem read fail]"

    def try_read_int(self, cpu, ptr):
        if ptr == 0:
            return None

        try:
            return self.panda.virtual_memory_read(cpu, ptr, 4, fmt='int')
        except ValueError:
            return "[virtual mem read fail]"
