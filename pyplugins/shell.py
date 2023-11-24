from pandare import PyPlugin
from os.path import join


# crc32("busybox")
EXPECTED_MAGIC = 0x8507fae1

HC_CMD_LOG_LINENO = 0
HC_CMD_LOG_ENV_ARGS = 1

outfile_cov = "shell_cov.csv"
outfile_env = "shell_env.csv"

class BBCov(PyPlugin):
    def __init__(self, panda):
        self.pointer_size = panda.bits // 8
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        

        # initialize outfiles:
        with open(join(self.outdir, outfile_cov), "w") as f:
            f.write("filename,lineno,pid\n")

        with open(join(self.outdir, outfile_env), "w") as f:
            f.write("filename,lineno,pid,envs\n")

        @self.panda.cb_guest_hypercall
        def cb_hypercall(cpu):
            magic = self.panda.arch.get_arg(cpu, 0, convention='syscall')
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
        assert(len(argv) == 3)
        file_str_ptr, lineno_ptr, pid_ptr = argv

        filename = self.try_read_string(cpu, file_str_ptr)
        if filename.startswith("/igloo/"):
            return
        lineno = self.try_read_int(cpu, lineno_ptr)
        pid = self.try_read_int(cpu, pid_ptr)
        #print(f"filename: {filename}, lineno = {lineno}, pid = {pid}")
        with open(join(self.outdir, outfile_cov), "a") as f:
            f.write(f"{filename},{lineno},{pid}\n")

    def log_env_args(self, cpu, argv):
        assert(len(argv) == 6)
        file_str_ptr, lineno_ptr, pid_ptr, envs_ptr, env_vals_ptr, envs_count_ptr = argv
        filename = self.try_read_string(cpu, file_str_ptr)

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
