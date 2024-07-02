import hashlib
import heapq
import importlib
import os
import subprocess
from threading import Lock
from typing import List, Tuple

from .analyses import PenguinAnalysis
from .common import hash_yaml
from .defaults import default_plugin_path


class WeightedItem:
    def __init__(self, item, weight):
        self.item = item
        self.weight = weight

    def __lt__(self, other):
        return -self.weight < -other.weight


class WeightedList:
    def __init__(self):
        self.items = []
        self.lock = Lock()

    def insert(self, weight, item):
        with self.lock:
            heapq.heappush(self.items, WeightedItem(item, weight))

    def pop(self):
        # Returns item, weight
        with self.lock:
            if self.items:
                weighted_item = heapq.heappop(self.items)
                return weighted_item.weight, weighted_item.item
            else:
                return None, None


class AtomicCounter:
    def __init__(self, initial=0):
        self.value = initial
        self._lock = Lock()

    def increment(self):
        with self._lock:
            self.value += 1
            return self.value

    def decrement(self):
        with self._lock:
            self.value -= 1
            return self.value

    def get(self):
        with self._lock:
            return self.value


def get_file_hash(filepath: str) -> str:
    hasher = hashlib.md5()
    with open(filepath, "rb") as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


def read_output_files(stdout_file: str, stderr_file: str) -> Tuple[str, str]:
    stdout_data, stderr_data = "", ""
    if os.path.isfile(stdout_file):
        with open(stdout_file, "r") as file:
            stdout_data = file.read()
    if os.path.isfile(stderr_file):
        with open(stderr_file, "r") as file:
            stderr_data = file.read()
    return stdout_data, stderr_data


def REAL_run_command_with_output(
    cmd: List[str], stdout_file: str, stderr_file: str
) -> Tuple[str, str]:
    with open(stdout_file, "w") as stdout, open(stderr_file, "w") as stderr:
        try:
            # Start the process
            process = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
            # Wait for the process to complete
            process.wait()
        except Exception as e:
            import traceback

            # Extract traceback details and report
            exc_type, exc_value, exc_traceback = traceback.sys.exc_info()
            traceback_details = traceback.format_exception(
                exc_type, exc_value, exc_traceback
            )
            error_msg = f"An error occurred: {str(e)}\n"
            error_msg += "".join(traceback_details)
            return error_msg, ""

        # Check the process exit code
        if (
            process.returncode != 0 and process.returncode != 120
        ):  # Assuming 120 is an acceptable error code
            out, err = read_output_files(stdout_file, stderr_file)
            return (
                f"Error running {cmd}: Got return code {process.returncode}: {out}",
                err,
            )

        return None, None


def run_command_with_output(cmd: List[str], ignore1, ignore2) -> Tuple[str, str]:
    try:
        # Start the subprocess and capture stdout and stderr directly
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Wait for the process to complete and capture the output
        stdout, stderr = process.communicate()

        # return process.returncode, stdout, stderr
        return None, None
    except Exception as e:
        # Capture any exceptions that occur
        return -1, "", f"An exception occurred: {str(e)}"


def hash_image_inputs(proj_dir, conf):
    """Create a hash of all the inputs of the image creation process"""

    static_files = conf["static_files"]

    # Hash contents of fs
    #
    # TODO: Replace this with Python 3.11's hashlib.hash_file()
    with open(os.path.join(proj_dir, conf["core"]["fs"]), "rb") as f:
        fs_hash = hashlib.sha256()
        while True:
            data = f.read(0x1000)
            if not data:
                break
            fs_hash.update(data)

    # Include nvram keys in the hash
    config_nvram = conf["nvram"] if "nvram" in conf else {}
    for k, val in config_nvram.items():
        if isinstance(val, str):
            encoded = val.encode()
        elif isinstance(val, int):
            encoded = str(val).encode()
        else:
            raise ValueError(f"Unknown type for nvram value {k}: {type(val)}")
        fs_hash.update(encoded)

    fs_hash = fs_hash.hexdigest()

    # If we ever add other ways to import static files, this assert should
    # remind us that the file contents need to be hashed
    assert all(
        "contents" in f or "host_path"
        for f in static_files.values()
        if f["type"] == "file"
    )

    # We'll include the files in our hash by reading them into our temporary
    # dict of data. This seems safer than doing hashing ourselves and merging.
    for f in static_files.values():
        if f["type"] == "host_path":
            with open(f["host_path"], "rb") as f:
                f["contents"] = f.read()

    return hash_yaml([static_files, fs_hash, conf.get("lib_inject")])


def _load_penguin_analysis_from(plugin_file):
    """
    Given a path to a python file, load it and find the first class
    that subclasses PenguinAnalysis. Instantiate it with run_dir and
    return it.
    """

    # Absolute path to the plugin
    file_path = os.path.join(default_plugin_path, plugin_file)
    module_name = os.path.splitext(os.path.basename(plugin_file))[
        0
    ]  # e.g., 'core' for 'core.py'
    spec = importlib.util.spec_from_file_location(module_name, file_path)

    # If it was relative to our module, we'd use this
    # spec = importlib.util.spec_from_file_location(default_plugin_path, plugin_file)

    if spec is None:
        raise ValueError(f"Unable to resolve plugin {plugin_file}")

    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)

    # For each class in the plugin, check if it subclasses PenguinAnalysis
    # If so, add it to our list of classes
    for class_name in dir(plugin):
        if not hasattr(plugin, class_name):
            continue
        cls = getattr(plugin, class_name)
        try:
            if not issubclass(cls, PenguinAnalysis) or cls is PenguinAnalysis:
                continue
        except TypeError:
            continue  # cls isn't actually a class
        return cls()  # Instantiate the class and return it

    raise ValueError(f"Unable to find a PenguinAnalysis subclass in {plugin_file}")


def get_mount_type(path):
    try:
        stat_output = subprocess.check_output(["stat", "-f", "-c", "%T", path])
        return stat_output.decode("utf-8").strip().lower()
    except subprocess.CalledProcessError:
        return None


def get_mitigation_providers(config: dict):
    """
    Given a config, pull out all the enabled mitigation providers,
    load them and return a dict of {ANALYSIS_TYPE: analysis class object}

    Skip plugins that are disabled in config.
    Raise an error if version of a plugin mismatches the config version
    """
    mitigation_providers = {}  # ANALYSIS_TYPE -> analysis class object
    for plugin_name, details in config["plugins"].items():
        if "enabled" in details and not details["enabled"]:
            # Disabled plugin - skip
            continue
        try:
            analysis = _load_penguin_analysis_from(plugin_name + ".py")
        except ValueError:
            continue
        mitigation_providers[analysis.ANALYSIS_TYPE] = analysis
        if details["version"] != analysis.VERSION:
            raise ValueError(
                f"Config specifies plugin {plugin_name} at version {details['version']} but we got {analysis.VERSION}"
            )

        # print(f"Loaded {plugin_name} at version {details['version']}")
    return mitigation_providers
