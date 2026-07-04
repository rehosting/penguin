import logging

import coloredlogs

from .common import getColoredLogger, yaml
from .plugin_manager import plugins, Plugin, PluginArgs

from os.path import join, dirname

# version.txt is generated during the container build. When importing from a
# source checkout (e.g. the host-side unit tests) it may be absent, so fall
# back to a dev placeholder instead of failing the import.
try:
    with open(join(dirname(__file__), "version.txt")) as _vf:
        VERSION = _vf.read().strip() or "0.0.0+dev"
except OSError:
    VERSION = "0.0.0+dev"
