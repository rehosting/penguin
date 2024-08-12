import logging

import coloredlogs

from .common import getColoredLogger, yaml

from os.path import join, dirname

VERSION = open(join(dirname(__file__), "version.txt")).read().strip()
