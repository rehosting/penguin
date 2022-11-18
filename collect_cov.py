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
        self.ppp_cb_boilerplate('on_cookie_param') # Triggered when we see an access of a cookie value (Not yet implemented)

        self.outfiles = {}
        if outdir:
            self.outfiles['php'] = outdir + "/php_coverage.txt"

        # Clear / create the file
        for f in self.outfiles.values():
            open(f, "w").close()

        from phptrace2 import PhpTrace2
        panda.pyplugins.load(PhpTrace2, {'only_new': True})
        panda.pyplugins.ppp.PhpTrace2.ppp_reg_cb('on_php_coverage', self.on_php_coverage)
        self.php_post_re = re.compile(r"""\$_POST\[['"]([a-zA-Z0-9_]*)['"]""")
        self.php_get_re = re.compile(r"""\$_GET\[['"]([a-zA-Z0-9_]*)['"]""")
        self.php_request_re = re.compile(r"""\$_REQUEST\[['"]([a-zA-Z0-9_]*)['"]""")

    def on_php_coverage(self, file, line_no, code):

        for param in self.php_post_re.findall(code):
            self.ppp_run_cb('on_post_param', param)

        for param in self.php_request_re.findall(code):
            # REQUEST pulls data from GET and POST, for now just assume post?
            self.ppp_run_cb('on_post_param', param)

        for param in self.php_get_re.findall(code):
            self.ppp_run_cb('on_get_param', param)

        self.logger.info(f"PHP: {file}:{line_no}")
        if 'php' in self.outfiles:
            with open(self.outfiles['php'], "a") as f:
                f.write(f"{file},{line_no},    {repr(code)}\n")
