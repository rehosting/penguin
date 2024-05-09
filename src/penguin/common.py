import hashlib
import logging
import re
import coloredlogs
import yaml

# Hex integers
def int_to_hex_representer(dumper, data):
    if data > 10:
        # Values < 10 can be base 10
        return dumper.represent_scalar('tag:yaml.org,2002:int', data)
    return dumper.represent_scalar('tag:yaml.org,2002:int', hex(data))

def hex_to_int_constructor(loader, node):
    if node.value.startswith('0x'):
        return int(loader.construct_scalar(node), 16)
    return int(loader.construct_scalar(node))

# Multi-line strings
# strings are represented as a literal block instead of "line1\nline2"
# so they're like key: | then on the next line we have line1. Then an actual newline, then line2.
def literal_presenter(dumper, data):
    # Multiline strings get |, single line strings get nothing fancy
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

# Constructor. Just need special handling for loading tuples
#yaml.SafeLoader.add_constructor('tag:yaml.org,2002:python/tuple', tuple_constructor)
yaml.SafeLoader.add_constructor('tag:yaml.org,2002:int', hex_to_int_constructor)

# Representer. Need special handling for dumping literals and tuples. Support base dumper or safe
yaml.Dumper.add_representer(str, literal_presenter)
yaml.SafeDumper.add_representer(str, literal_presenter)
yaml.Dumper.add_representer(tuple, int_to_hex_representer)
yaml.SafeDumper.add_representer(tuple, int_to_hex_representer)
#yaml.Dumper.add_representer(tuple, tuple_representer)
#yaml.SafeDumper.add_representer(tuple, tuple_representer)


def hash_yaml(section_to_hash):
    section_string = yaml.dump(section_to_hash, sort_keys=True)

    # Encode the string to bytes.
    section_bytes = section_string.encode('utf-8')

    # Create a hash using hashlib.
    hash_object = hashlib.sha256()
    hash_object.update(section_bytes)
    hash_digest = hash_object.hexdigest()
    return hash_digest

class PathHighlightingFormatter(coloredlogs.ColoredFormatter):
    def format(self, record):
        message = super().format(record)
        # This regex can be adjusted to better match your specific path formats
        message = re.sub(r'(/[^ ]*)', coloredlogs.ansi_wrap(r'\1', color='blue', bold=True), message)

        # Also find and replace ip:port with green bold
        message = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})', coloredlogs.ansi_wrap(r'\1', color='green', bold=True), message)
        return message

def getColoredLogger(name, level='INFO'):
    logger = logging.getLogger(name)
    logger.setLevel(level)  # Set the logger level

    # Set formatter with custom path highlighting
    formatter = PathHighlightingFormatter(fmt='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S')

    # Check if the logger already has handlers to prevent duplicate logs
    if not logger.handlers:
        # Create and configure a stream handler
        handler = logging.StreamHandler()
        handler.setLevel(level)  # Set the handler level
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        # Check if requested level is different from the current level
        if logger.getEffectiveLevel() != level:
            logger.warning(f"Logger %s already configured with level %s", name, logger.getEffectiveLevel())
            logger.warning("To change the level of an existing logger, please use the setLevel method instead of getColoredLogger")

    # Prevent log messages from propagating to parent loggers (i.e., penguin.manager should not also log for penguin)
    logger.propagate = False

    return logger
