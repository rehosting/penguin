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
    Collect all coverage from IGLOO-aware interpreters run by any
    process in the guest. Record into outdir.
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('CollectCoverage')

        self.outdir = outdir
        self.seen_cov = set()
        self.started_logging = set()

    def log_cov(self, lang, file, line, code):
        path = self.outdir + f"/coverage.{lang}"

        # Clear / create the output files the first time
        if lang not in self.started_logging:
            open(path, "w").close()
            self.started_logging.add(lang)

        with open(path, "a") as f:
            f.write(f"{file},{line},{repr(code)}\n")

    def on_output(self, line):
        if line.startswith('COV: '):
            lang, file, line, code = line[5:].split(",", 3)
            if (lang, file, line) in self.seen_cov:
                # Skip duplicates
                return

            self.seen_cov.add((lang, file, line))

            if "IGLOOIZED" in line:
                # Artifact from our introspection, ignore these lines
                return

            self.log_cov(lang, file, line, code)
