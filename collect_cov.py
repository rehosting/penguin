import re
import logging
import coloredlogs

# Add pandata to path
from os.path import dirname
from sys import path
path.append(dirname(__file__))

from sys import path
path.append("/igloo/")
from qemuPython import QemuPyplugin

coloredlogs.install(level='INFO')

class CollectCoverage(QemuPyplugin):
    '''
    Collect three types of coverage:
    1) Execve-based: name of unique programs run                -> outdir/all_progs.txt
    2) Execve-based with args/envp: unique argv+envp lists seen -> outdir/all_execs.txt
    3) For IGLOO-aware interpreters, source line coverage       -> outdir/coverage.[lang]
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('CollectCoverage')

        self.outdir = outdir
        self.seen_cov = set()
        self.started_logging = set() # Track which lang-specific covfiles we've written to
        self.coverage = {}
        self.log_no = 0

        self.all_progs = set() # All distinct programs run in guest (argv[0])
        self.all_execs = set() # All distinct commands run in guest (full argv+envp)

        self.pending_execve = None
        self.execve_args = []
        self.execve_env = []
        self.execve_line_re = re.compile(r'execve \[PID: (\d*) \(([a-zA-Z0-9/\-:_\. ]*)\)]')

    def log_procs(self):
        with open(self.outdir + "/all_progs.txt", "w") as f:
            for x in self.all_progs:
                f.write(str(x)+"\n")

        with open(self.outdir + "/all_execs.txt", "w") as f:
            for x in self.all_execs:
                f.write(str(x)+"\n")

    def log_cov(self):
        # At "log" we sort and write to file for final results
        for lang, files in self.coverage.items():
            path = self.outdir + f"/coverage.{lang}"

            # Reset file contents
            with open(path, "w") as f:
                f.write(f"filename, line_number, code_repr\n")
                for file, data in files.items():
                    for line, code in sorted(data.items()):
                        f.write(f"{file},{line},{repr(code)}\n")

    def record_cov(self, lang, file, line, code):
        # At "record" we append to file for intermediate results
        if (lang, file, line) in self.seen_cov:
            return # Skip duplicates
        self.seen_cov.add((lang, file, line))
        if "IGLOOIZED" in code:
            return # Artifact from our introspection, ignore these lines

        path = self.outdir + f"/coverage.{lang}"
        if lang not in self.started_logging:
            # Clear / create the output files the first write
            open(path, "w").close()
            self.started_logging.add(lang)

        # Write intermediate result to file (not-sorted)
        with open(path, "a") as f:
            # Append
            f.write(f"{file},{line},{repr(code)}\n")

        # Store coverage info so we can later output sorted
        if lang not in self.coverage:
            self.coverage[lang] = {}
        if file not in self.coverage[lang]:
            self.coverage[lang][file] = {}
        self.coverage[lang][file][line] = code

    def on_output(self, line):
        if line.startswith('COV: '):
            lang, file, line, code = line[5:].split(",", 3)
            line = int(line)
            self.record_cov(lang, file, line, code)
            return

        elif self.pending_execve is not None:
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
                self.all_progs.add((self.pending_execve, arg0))
                self.all_execs.add((self.pending_execve, tuple(str(x) for x in self.execve_args), tuple(str(x) for x in self.execve_env)))

                self.execve_args = []
                self.execve_env = []
                self.pending_execve = None
                return
            else:
                self.logger.warning(f"Unexpected: in execve got other log message: '{line}', startswith={line.startswith('execve ARG ')}")

        if m := self.execve_line_re.match(line):
            # If this line is an execve, parse it
            m = m.groups()
            self.pending_execve = m[1] # Name of the process doing the execve

    def uninit(self):
        self.log_cov()
        self.log_procs()
