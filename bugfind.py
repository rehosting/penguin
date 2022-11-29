import re
import logging
import coloredlogs

from os.path import dirname
from sys import path
path.append(dirname(__file__))
from sys import path
path.append("/igloo/")
from qemuPython import QemuPyplugin

coloredlogs.install(level='INFO')

class BugFind(QemuPyplugin):
    '''
    On syscalls, check for the string PANDA. For now just log
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('BugFind')
        self.outdir = outdir

        self.pending_execve = None
        self.execve_args = []
        self.execve_env = []
        self.sc_line_re = re.compile(r'([a-z0-9_]*) \[PID: (\d*) \(([a-zA-Z0-9/\-:_\. ]*)\)], file: (.*)')

    def examine_execve(self, parent, argv, envp):
        if "PANDA" in str(argv, envp):
            self.logger.warning(f"Command injection in {parent}: {argv} with env {envp}")

    def examine_file(self, procname, pid, sc_name, filename):
        if "PANDA" in filename:
            self.logger.warning(f"Path control in {procname}: {sc_name} called with {filename}")

    def on_output(self, line):
        if self.pending_execve is not None:
            # If it's a syscall and we're parsing an execve, consume
            # and combine details until we get a non-execve output
            if line.startswith('execve ARG'):
                if 'execve ARG ' in line:
                    self.execve_args.append(line.split('execve ARG ')[1])
                else:
                    self.execve_args.append("")
                return
            elif line.startswith('execve ENV:'): # This one has a :, the others don't
                if "execve ENV: "in line:
                    self.execve_env.append(line.split('execve ENV: ')[1])
                else:
                    self.execve_env.append("")
                return
            elif line == 'execve END':
                # Note argv will be empty for init, but shouldn't be anything else
                arg0 = self.execve_args[0] if len(self.execve_args) else 'init'

                if 'IGLOOIZED' not in str(self.execve_args):
                    # XXX: If we introduce new execs, we should try filtering them here
                    # E.g., our custom php interpreter does a grep for IGLOOIZED and for >?
                    self.examine_execve(self.pending_execve, self.execve_args, self.execve_env)


                self.execve_args = []
                self.execve_env = []
                self.pending_execve = None
                return
            else:
                self.logger.warning(f"Unexpected: in execve got other log message: '{line}', startswith={line.startswith('execve ARG ')}")

        if m := self.sc_line_re.match(line):
            # If this line is an execve, parse it
            (sc_name , pid, procname, filename) = m.groups()
            if sc_name == 'execve':
                self.pending_execve = procname # Name of the process doing the execve
            else:
                self.examine_file(procname, pid, sc_name, filename)

    def uninit(self):
        # TODO, log to disk
        pass
