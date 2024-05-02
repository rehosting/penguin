import yaml
import hashlib

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