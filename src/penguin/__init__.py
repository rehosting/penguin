import logging

import coloredlogs

from .common import getColoredLogger, yaml
from .plugin_manager import plugins

from os.path import join, dirname

VERSION = open(join(dirname(__file__), "version.txt")).read().strip()
