from pandare import PyPlugin
import logging
import re
import coloredlogs
logging.basicConfig(level=logging.DEBUG)
coloredlogs.DEFAULT_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
coloredlogs.install()

class PhpTrace2(PyPlugin):
    '''
    Assume filesystem modified to make /igloo/trace.php run. Just collect results
    '''
    def __init__(self, panda):
        self.logger = logging.getLogger("PhpTrace")
        self.only_new = self.get_arg_bool("only_new")
        self.panda  = panda
        self.ppp_cb_boilerplate('on_php_coverage')
        self.seen = set()

        @panda.ppp("syscalls2", "on_sys_write_return")
        def post_write(cpu, pc, fd, buf, count):
            if self.target_fd(cpu, fd, context='igloo_write'):
                count = self.panda.arch.get_retval(cpu, convention='syscall')
                try:
                    buf = self.panda.virtual_memory_read(cpu, buf, count)
                except ValueError:
                    self.logger.warning("Could not read coverage details: ignoring")
                    return
                file, line, *code = buf.split(b",")
                code = b",".join(code)

                code_key = (file, line)
                if self.only_new:
                    if code_key in self.seen:
                        # Previously seen this, don't report again
                        return
                    self.seen.add(code_key)

                self.ppp_run_cb('on_php_coverage', file.decode(), int(line), code.decode())

    def target_fd(self, cpu, fd, context=None):
        if fd == 0xffffffff:
            #self.logger.info(f"fd=-1 in {context}")
            return False
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL:
            self.logger.info(f"Unknown proc in {context}")
            return False
        fname_obj = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
        if fname_obj == self.panda.ffi.NULL:
            #self.logger.info(f"Bad filename in {self.panda.ffi.string(proc.name)} from proc {context}")
            return False
        fname = self.panda.ffi.string(fname_obj).decode()
        #self.logger.debug(f"Filename: {fname}")

        if context == 'igloo_write':
            if fname == '/tmp/igloo_log.txt':
                return True
            else:
                return False
        else:
            if not fname.endswith(".php"):
                return False
            if fname == DEBUG_PATH:
                return False # Don't instrument our debug script!

        #self.logger.info(f"Found php file descriptor in proc {self.panda.ffi.string(proc.name)} with context {context}: {fname}")
        return fname

