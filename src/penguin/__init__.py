from .common import yaml
import coloredlogs

VERSION="1.0.0"

LOG_FMT = '%(asctime)s %(name)s %(levelname)s %(message)s'

coloredlogs.install(level='INFO', fmt=LOG_FMT)