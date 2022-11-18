from pandare import PyPlugin

# Add pandata to path
from os.path import dirname
from sys import path
path.append(dirname(__file__))

import logging
import coloredlogs
coloredlogs.install(level='INFO')

# TODO: refactor to be generic collector

class CollectCoverage(PyPlugin):
    def __init__(self, panda):
        self.logger = logging.getLogger('CollectCoverage')
        outdir = self.get_arg("outdir") # may be None

        self.outfiles = {}
        if outdir:
            self.outfiles['php'] = outdir + "/php_coverage.txt"

        # Clear / create the file
        for f in self.outfiles.values():
            open(f, "w").close()

        from phptrace2 import PhpTrace2
        panda.pyplugins.load(PhpTrace2, {'only_new': True})
        panda.pyplugins.ppp.PhpTrace2.ppp_reg_cb('on_php_coverage', self.on_php_coverage)

    def on_php_coverage(self, file, line, code):
        self.logger.info(f"PHP: {file}:{line}")
        if 'php' in self.outfiles:
            with open(self.outfiles['php'], "a") as f:
                f.write(f"{file},{line}\n")
