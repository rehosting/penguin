import hashlib
import logging
import re
import coloredlogs
import yaml
from os.path import join, isfile, basename
from yamlcore import CoreDumper, CoreLoader

_redirect_handler: logging.Handler | None = None


def redirect_logs_to(handler: logging.Handler) -> None:
    """
    Replace stderr StreamHandlers with `handler` for all current and future
    penguin/plugins/config loggers.
    """
    global _redirect_handler
    _redirect_handler = handler
    for name, lg in list(logging.Logger.manager.loggerDict.items()):
        if not isinstance(lg, logging.Logger):
            continue
        if not (name == "penguin" or name.startswith("penguin.")
                or name == "plugins" or name.startswith("plugins.")
                or name == "config"):
            continue
        # Strict type check: drop plain StreamHandler, keep FileHandler/NullHandler/etc.
        lg.handlers = [h for h in lg.handlers if type(h) is not logging.StreamHandler]
        if handler not in lg.handlers:
            lg.addHandler(handler)


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
CoreDumper.add_representer(str, literal_presenter)
CoreDumper.add_representer(int, int_to_hex_representer)
yaml.add_constructor(
    'tag:yaml.org,2002:binary',
    yaml.constructor.SafeConstructor.construct_yaml_binary,
    Loader=CoreLoader,
)
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


def patch_config(logger, base_config, patch, patch_name="patch", origin_map=None, verbose=False):
    # Initialize origin map if it wasn't passed in
    if origin_map is None:
        origin_map = {}

    # Helper to recursively claim ownership of keys in the origin map
    def _record_origins(obj, path_prefix, source_name):
        if hasattr(obj, "model_fields_set"):
            for k in obj.model_fields_set:
                _record_origins(getattr(obj, k), f"{path_prefix}.{k}" if path_prefix else k, source_name)
            if obj.model_extra is not None:
                for k, val in obj.model_extra.items():
                    _record_origins(val, f"{path_prefix}.{k}" if path_prefix else k, source_name)
        elif isinstance(obj, dict):
            for k, val in obj.items():
                _record_origins(val, f"{path_prefix}.{k}" if path_prefix else k, source_name)
        else:
            # Leaves and lists get recorded directly
            origin_map[path_prefix] = source_name

    if not patch:
        # Empty patch, possibly an empty file or one with all comments
        return base_config

    # If this is the very first run, populate the origin map with the base config
    if not origin_map:
        _record_origins(base_config, "", "base_config")

    # Merge configs.
    def _recursive_update(base, new, config_option):
        if base is None:
            _record_origins(new, config_option, patch_name)
            return new
        if new is None:
            return base

        if hasattr(base, "merge"):
            origin_map[config_option] = patch_name
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
                full_path = f"{config_option}.{new_key}" if config_option else new_key
                if new_key in result:
                    result[new_key] = _recursive_update(
                        result[new_key],
                        new_value,
                        full_path,
                    )
                else:
                    result[new_key] = new_value
                    _record_origins(new_value, full_path, patch_name)

            if new.model_extra is not None:
                for new_key, new_value in new.model_extra.items():
                    full_path = f"{config_option}.{new_key}" if config_option else new_key
                    if new_key in result:
                        result[new_key] = _recursive_update(
                            result[new_key],
                            new_value,
                            full_path,
                        )
                    else:
                        result[new_key] = new_value
                        _record_origins(new_value, full_path, patch_name)
            return type(base)(**result)

        if isinstance(base, list):
            # We treat list appends differently, no "conflict" per se, just an addition
            return base + new

        if isinstance(base, dict):
            result = dict()
            for key, base_value in base.items():
                full_path = f"{config_option}.{key}" if config_option else key
                if key in new:
                    new_value = new[key]
                    result[key] = _recursive_update(
                        base_value,
                        new_value,
                        full_path,
                    )
                else:
                    result[key] = base_value
            for new_key, new_value in new.items():
                if new_key not in base:
                    full_path = f"{config_option}.{new_key}" if config_option else new_key
                    result[new_key] = new_value
                    _record_origins(new_value, full_path, patch_name)
            return result

        if base == new:
            return base

        # --> WE HAVE A CONFLICT <--
        previous_source = origin_map.get(config_option, "base_config")

        # Clean up long paths to just the filenames
        prev_file = basename(previous_source)
        new_file = basename(patch_name)

        # Strip out Pydantic '.root' noise from the config key
        clean_option = config_option.replace(".root", "")

        if verbose:
            base_str = yaml.dump(base).strip().removesuffix("...").strip()
            new_str = yaml.dump(new).strip().removesuffix("...").strip()
            change_str = (
                f"\n```\n{base_str}\n```↓\n```\n{new_str}\n```"
                if "\n" in base_str + new_str
                else f"`{base_str}` → `{new_str}`"
            )

            # Use a much tighter logging format
            logger.info(
                f"conflict: {clean_option}: {change_str} ({prev_file} -> {new_file})"
            )

        # Claim ownership of the newly overwritten key
        origin_map[config_option] = patch_name
        return new

    return _recursive_update(base_config, patch, "")


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
        if _redirect_handler is not None:
            # Logs are being redirected: skip the default stderr StreamHandler.
            logger.setLevel(level)
            logger.addHandler(_redirect_handler)
        else:
            # Default: stderr.
            handler = logging.StreamHandler()
            logger.setLevel(level)
            handler.setLevel(level)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
    elif _redirect_handler is not None and _redirect_handler not in logger.handlers:
        # Redirect was set after this logger was already created — swap.
        logger.handlers = [h for h in logger.handlers if type(h) is not logging.StreamHandler]
        logger.addHandler(_redirect_handler)

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
