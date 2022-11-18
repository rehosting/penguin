import re
import logging
import coloredlogs
from pandare import PyPlugin

# Add pandata to path
from os.path import dirname
from sys import path
path.append(dirname(__file__))

coloredlogs.install(level='INFO')

# TODO: refactor to be generic collector

class CollectCoverage(PyPlugin):
    def __init__(self, panda):
        self.logger = logging.getLogger('CollectCoverage')
        outdir = self.get_arg("outdir") # may be None
        self.ppp_cb_boilerplate('on_post_param') # Triggered when we see a post param accessed in source
        self.ppp_cb_boilerplate('on_get_param') # Triggered when we see a get param accessed in source

        self.outfiles = {}
        if outdir:
            self.outfiles['php'] = outdir + "/php_coverage.txt"

        # Clear / create the file
        for f in self.outfiles.values():
            open(f, "w").close()

        from phptrace2 import PhpTrace2
        panda.pyplugins.load(PhpTrace2, {'only_new': True})
        panda.pyplugins.ppp.PhpTrace2.ppp_reg_cb('on_php_coverage', self.on_php_coverage)
        self.php_post_re = re.compile(r"""\$_post\[['"]([a-za-z0-9_]*)['"]""")
        self.php_get_re = re.compile(r"""\$_get\[['"]([a-za-z0-9_]*)['"]""")

    def on_php_coverage(self, file, line_no, code):

        if param := self.php_post_re.findall(code):
            self.ppp_run_cb('on_post_param', param)

        if param := self.php_get_re.findall(code):
            self.ppp_run_cb('on_get_param', param)

        self.logger.info(f"PHP: {file}:{line_no}")
        if 'php' in self.outfiles:
            with open(self.outfiles['php'], "a") as f:
                f.write(f"{file},{line_no},    {repr(code)}\n")
