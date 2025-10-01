import hashlib
import logging
import re
import coloredlogs
import yaml
from os.path import join, isfile
from yamlcore import CoreDumper


# Hex integers
def int_to_hex_representer(dumper, data):
    if not isinstance(data, int):
        raise ValueError(f"YAML representer received non-integer: {data}. Something has gone very wrong")

    if data > 10:
        # Values < 10 can be base 10
        return dumper.represent_scalar("tag:yaml.org,2002:int", data)
    return dumper.represent_scalar("tag:yaml.org,2002:int", hex(data))


# Multi-line strings
# strings are represented as a literal block instead of "line1\nline2"
# so they're like key: | then on the next line we have line1. Then an actual newline, then line2.
def literal_presenter(dumper, data):
    # Multiline strings get |, single line strings get nothing fancy
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


# Representer. Need special handling for dumping literals and tuples. Support base dumper or safe
yaml.Dumper.add_representer(str, literal_presenter)
yaml.SafeDumper.add_representer(str, literal_presenter)
yaml.Dumper.add_representer(tuple, int_to_hex_representer)
yaml.SafeDumper.add_representer(tuple, int_to_hex_representer)
# yaml.Dumper.add_representer(tuple, tuple_representer)
# yaml.SafeDumper.add_representer(tuple, tuple_representer)


def hash_yaml(section_to_hash):
    section_string = yaml.dump(section_to_hash, sort_keys=False,
                               Dumper=CoreDumper)

    # Encode the string to bytes.
    section_bytes = section_string.encode("utf-8")

    # Create a hash using hashlib.
    hash_object = hashlib.sha256()
    hash_object.update(section_bytes)
    hash_digest = hash_object.hexdigest()
    return hash_digest


def patch_config(logger, base_config, patch):
    if not patch:
        # Empty patch, possibly an empty file or one with all comments
        return base_config

    # Merge configs.
    def _recursive_update(base, new, config_option):
        if base is None:
            return new
        if new is None:
            return base

        if hasattr(base, "merge"):
            return base.merge(new)

        if hasattr(base, "model_fields_set"):
            result = dict()
            for base_key in base.model_fields_set:
                result[base_key] = getattr(base, base_key)
            if base.model_extra is not None:
                for base_key, base_value in base.model_extra.items():
                    result[base_key] = base_value
            for new_key in new.model_fields_set:
                new_value = getattr(new, new_key)
                if new_key in result:
                    result[new_key] = _recursive_update(
                        result[new_key],
                        new_value,
                        f"{config_option}.{new_key}" if config_option else new_key,
                    )
                else:
                    result[new_key] = new_value
            if new.model_extra is not None:
                for new_key, new_value in new.model_extra.items():
                    if new_key in result:
                        result[new_key] = _recursive_update(
                            result[new_key],
                            new_value,
                            f"{config_option}.{new_key}" if config_option else new_key,
                        )
                    else:
                        result[new_key] = new_value
            return type(base)(**result)

        if isinstance(base, list):
            return base + new

        if isinstance(base, dict):
            result = dict()
            for key, base_value in base.items():
                if key in new:
                    new_value = new[key]
                    result[key] = _recursive_update(
                        base_value,
                        new_value,
                        f"{config_option}.{key}" if config_option else key,
                    )
                else:
                    result[key] = base_value
            for new_key, new_value in new.items():
                if new_key not in base:
                    result[new_key] = new_value
            return result

        if base == new:
            return base

        base_str = yaml.dump(base).strip().removesuffix("...").strip()
        new_str = yaml.dump(new).strip().removesuffix("...").strip()
        change_str = (
            f"\n```\n{base_str}\n```↓\n```\n{new_str}\n```"
            if "\n" in base_str + new_str
            else f"`{base_str}` → `{new_str}`"
        )
        logger.warning(f"patch conflict: {config_option}: {change_str}")

        return new

    return _recursive_update(base_config, patch, None)


class PathHighlightingFormatter(coloredlogs.ColoredFormatter):
    def format(self, record):
        message = super().format(record)
        # This regex can be adjusted to better match your specific path formats
        message = re.sub(
            r"(/[^ ]*)", coloredlogs.ansi_wrap(r"\1", color="blue", bold=True), message
        )

        # Also find and replace ip:port with green bold
        message = re.sub(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})",
            coloredlogs.ansi_wrap(r"\1", color="green", bold=True),
            message,
        )
        return message


def getColoredLogger(name):
    """
    Get or create a coloredlogger at INFO.
    """
    logger = logging.getLogger(name)
    level = logging.INFO

    # Set formatter with custom path highlighting
    formatter = PathHighlightingFormatter(
        fmt="%(asctime)s %(name)s %(levelname)s %(message)s", datefmt="%H:%M:%S"
    )

    # Check if the logger already has handlers to prevent duplicate logs
    if not logger.handlers:
        # Create and configure a stream handler
        handler = logging.StreamHandler()
        logger.setLevel(level)
        handler.setLevel(level)  # Set the handler level
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Prevent log messages from propagating to parent loggers (i.e., penguin.manager should not also log for penguin)
    logger.propagate = False

    if not hasattr(logger, 'custom_set_level'):
        # Save the original setLevel method before replacing it
        original_set_level = logger.setLevel

        def custom_set_level(level):
            # Call the original method, not the monkeypatched one
            original_set_level(level)
            for handler in logger.handlers:
                handler.setLevel(level)

        logger.custom_set_level = custom_set_level

        # Replace the setLevel method with our custom one
        logger.setLevel = custom_set_level

    return logger


def get_inits_from_proj(proj_dir):
    '''
    Given a project directory, find a default init from
    static/InitFinder.yaml

    Raises RuntimeError if no init can be found.
    '''

    inits_path = join(*[proj_dir, "static", "InitFinder.yaml"])
    if isfile(join(inits_path)):
        with open(inits_path, "r") as f:
            options = yaml.safe_load(f)
            return options


def dict_to_frozenset(d):
    # Recursively convert dictionaries and lists to frozensets and tuples
    if isinstance(d, dict):
        return frozenset((k, dict_to_frozenset(v)) for k, v in d.items())
    elif isinstance(d, list):
        return tuple(dict_to_frozenset(item) for item in d)
    else:
        return d


def frozenset_to_dict(fs):
    # Recursively convert frozensets and tuples back to dictionaries and lists
    if isinstance(fs, frozenset):
        return {k: frozenset_to_dict(v) for k, v in fs}
    elif isinstance(fs, tuple):
        return [frozenset_to_dict(item) for item in fs]
    else:
        return fs
