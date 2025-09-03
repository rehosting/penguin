import hashlib
import logging
import re
from pathlib import Path
import coloredlogs
import yaml
from os.path import join, isfile
from yamlcore import CoreLoader, CoreDumper
from penguin.penguin_config.structure import PatchPolicy, Main as ConfigSchema


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


def patch_config(base_config, patch):
    def _merge_string_value(base_val, new_val, policy):
        """Merge string values according to the specified policy"""
        if not isinstance(base_val, str) or not isinstance(new_val, str):
            return new_val  # Fall back to override for non-strings

        if policy == PatchPolicy.MERGE_SPACE:
            return f"{base_val} {new_val}".strip()
        elif policy == PatchPolicy.MERGE_NEWLINE:
            return f"{base_val}\n{new_val}".strip()
        else:  # default to OVERRIDE
            return new_val

    def _get_field_patch_policy(section_name: str, field_name: str) -> PatchPolicy:
        """Extract patch policy from schema metadata"""
        try:
            # Get the section model class from Main's fields
            main_field_info = ConfigSchema.model_fields.get(section_name)
            if not main_field_info or not hasattr(main_field_info, 'annotation'):
                return PatchPolicy.OVERRIDE

            # Extract the actual model class from the annotation
            section_model_class = main_field_info.annotation
            # Handle Optional[ModelClass] annotations
            if hasattr(section_model_class, '__origin__') and hasattr(section_model_class, '__args__'):
                section_model_class = section_model_class.__args__[0]

            # Now get the field info from the section model
            field_info = section_model_class.model_fields.get(field_name)
            if field_info and hasattr(field_info, 'annotation'):
                annotation = field_info.annotation
                if hasattr(annotation, '__metadata__'):
                    # Look for PatchPolicy in the metadata tuple
                    for metadata_item in annotation.__metadata__:
                        if isinstance(metadata_item, PatchPolicy):
                            return metadata_item
        except Exception:
            pass

        return PatchPolicy.OVERRIDE    # Merge configs.
    def _recursive_update(base, new):
        for k, v in new.items():
            if isinstance(v, dict):
                base[k] = _recursive_update(base.get(k, {}), v)
            elif isinstance(v, list):
                # Append
                base[k] = base.get(k, []) + v
            else:
                base[k] = v
        return base

    if issubclass(type(patch), Path):
        with open(patch, "r") as f:
            patch = yaml.load(f, Loader=CoreLoader)
    if not patch:
        # Empty patch, possibly an empty file or one with all comments
        return base_config
    for key, value in patch.items():
        # Check if the key already exists in the base_config
        if key in base_config:
            # If the value is a dictionary, update subfields
            if isinstance(value, dict):
                # Handle field-level merge policies for this section
                for field_name, field_value in value.items():
                    if (isinstance(field_value, str) and field_name in base_config[key]
                            and isinstance(base_config[key][field_name], str)):
                        merge_policy = _get_field_patch_policy(key, field_name)
                        if merge_policy != PatchPolicy.OVERRIDE:
                            base_config[key][field_name] = _merge_string_value(
                                base_config[key][field_name], field_value, merge_policy)
                            # Remove this field from the patch since we handled it
                            value = {k: v for k, v in value.items() if k != field_name}

                # Recursive update to handle nested dictionaries
                base_config[key] = _recursive_update(base_config.get(key, {}), value)
            elif isinstance(value, list):
                # Merge lists
                seen = set()
                combined = base_config[key] + value
                base_config[key] = [x for x in combined if not (x in seen or seen.add(x))]
            else:
                # Replace the base value with the incoming value
                base_config[key] = value
        else:
            # New key, add all data directly
            base_config[key] = value
    return base_config


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
