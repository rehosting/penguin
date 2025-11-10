"""
penguin.utils
=============

Utility functions and classes for the Penguin emulation environment.

This module provides helpers for file hashing, weighted lists, atomic counters,
filesystem and kernel management, plugin analysis loading, and mitigation provider discovery.

"""

import base64
import hashlib
import heapq
import importlib
import json
import os
import subprocess
import penguin
from threading import Lock
from typing import List, Tuple, Any, Optional, Dict

from .analyses import PenguinAnalysis
from .defaults import default_plugin_path, static_dir as STATIC_DIR

logger = penguin.getColoredLogger("utils.get_kernel")


class WeightedItem:
    def __init__(self, item: Any, weight: float) -> None:
        """
        :param item: The item to store.
        :type item: Any
        :param weight: The weight associated with the item.
        :type weight: float
        """
        self.item: Any = item
        self.weight: float = weight

    def __lt__(self, other: "WeightedItem") -> bool:
        """
        Compare WeightedItems by their weight.

        :param other: Another WeightedItem.
        :type other: WeightedItem
        :return: True if self is less than other.
        :rtype: bool
        """
        return -self.weight < -other.weight


class WeightedList:
    def __init__(self) -> None:
        """
        Initialize an empty WeightedList.
        """
        self.items: List[WeightedItem] = []
        self.lock: Lock = Lock()

    def insert(self, weight: float, item: Any) -> None:
        """
        Insert an item with a given weight.

        :param weight: The weight for the item.
        :type weight: float
        :param item: The item to insert.
        :type item: Any
        """
        with self.lock:
            heapq.heappush(self.items, WeightedItem(item, weight))

    def pop(self) -> Tuple[Optional[float], Optional[Any]]:
        """
        Pop the item with the highest weight.

        :return: Tuple of (weight, item) or (None, None) if empty.
        :rtype: tuple[Optional[float], Optional[Any]]
        """
        with self.lock:
            if self.items:
                weighted_item = heapq.heappop(self.items)
                return weighted_item.weight, weighted_item.item
            else:
                return None, None


class AtomicCounter:
    def __init__(self, initial: int = 0) -> None:
        """
        Atomic integer counter.

        :param initial: Initial value.
        :type initial: int
        """
        self.value: int = initial
        self._lock: Lock = Lock()

    def increment(self) -> int:
        """
        Atomically increment the counter.

        :return: The new value.
        :rtype: int
        """
        with self._lock:
            self.value += 1
            return self.value

    def decrement(self) -> int:
        """
        Atomically decrement the counter.

        :return: The new value.
        :rtype: int
        """
        with self._lock:
            self.value -= 1
            return self.value

    def get(self) -> int:
        """
        Get the current value atomically.

        :return: The current value.
        :rtype: int
        """
        with self._lock:
            return self.value


def get_file_hash(filepath: str) -> str:
    """
    Compute the MD5 hash of a file.

    :param filepath: Path to the file.
    :type filepath: str
    :return: Hex digest string.
    :rtype: str
    """
    hasher = hashlib.md5()
    with open(filepath, "rb") as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


def read_output_files(stdout_file: str, stderr_file: str) -> Tuple[str, str]:
    """
    Read the contents of stdout and stderr files.

    :param stdout_file: Path to stdout file.
    :type stdout_file: str
    :param stderr_file: Path to stderr file.
    :type stderr_file: str
    :return: Tuple of (stdout_data, stderr_data).
    :rtype: tuple[str, str]
    """
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
) -> Tuple[Optional[str], Optional[str]]:
    """
    Run a command and write output to files.

    :param cmd: Command as a list of arguments.
    :type cmd: list[str]
    :param stdout_file: Path to stdout file.
    :type stdout_file: str
    :param stderr_file: Path to stderr file.
    :type stderr_file: str
    :return: Tuple of (error_msg, stderr) or (None, None) on success.
    :rtype: tuple[Optional[str], Optional[str]]
    """
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


def run_command_with_output(cmd: List[str], ignore1: Any, ignore2: Any) -> Tuple[Any, Any]:
    """
    Run a command and capture stdout/stderr.

    :param cmd: Command as a list of arguments.
    :type cmd: list[str]
    :param ignore1: Ignored.
    :param ignore2: Ignored.
    :return: Tuple of (None, None) on success, or (-1, "", error_msg) on exception.
    :rtype: tuple[Any, Any]
    """
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


def get_arch_subdir(config: Dict[str, Any]) -> str:
    """
    Get the architecture subdirectory name for the given config.

    :param config: Configuration dictionary.
    :type config: dict[str, Any]
    :return: Architecture subdirectory string.
    :rtype: str
    """
    arch = config["core"]["arch"]
    if arch == "intel64":
        return "x86_64"
    elif arch in ["powerpc64el", "powerpc64le"]:
        return "powerpc64"
    else:
        return arch


def get_arch_dir(config: Dict[str, Any]) -> str:
    """
    Get the full architecture directory path.

    :param config: Configuration dictionary.
    :type config: dict[str, Any]
    :return: Directory path string.
    :rtype: str
    """
    return f"{STATIC_DIR}/{get_arch_subdir(config)}"


def get_driver_kmod_path(config: Dict[str, Any]) -> str:
    """
    Get the path to the driver kernel module.

    :param config: Configuration dictionary.
    :type config: dict[str, Any]
    :return: Path string.
    :rtype: str
    """
    kernel_path = os.path.dirname(config["core"]["kernel"])
    arch_dir = get_arch_subdir(config)
    if arch_dir == "aarch64":
        arch_dir = "arm64"
    return f"{kernel_path}/igloo.ko.{arch_dir}"


def hash_image_inputs(proj_dir: str, conf: Dict[str, Any]) -> str:
    """
    Create a hash of all the inputs of the image creation process.

    In the new build process this is just the preinit script and the
    modification time of the base filesystem (since we don't control
    its contents).

    We specifically do NOT include the busybox binary in this hash despite
    its potential effect on the image because we expect them to be fairly
    standard at least over the very small number of lines.

    :param proj_dir: Project directory.
    :type proj_dir: str
    :param conf: Configuration dictionary.
    :type conf: dict[str, Any]
    :return: Hex digest string.
    :rtype: str
    """
    from penguin.defaults import default_preinit_script
    hsh = hashlib.sha256()
    hsh.update(default_preinit_script.encode())
    fs = os.path.join(proj_dir, conf["core"]["fs"])
    arch_dir = get_arch_dir(conf)
    for FILE in ["busybox", "hyp_file_op", "send_portalcall", get_driver_kmod_path(conf)]:
        path = os.path.join(arch_dir, FILE)
        hsh.update(get_file_hash(path).encode())
    modification_timestamp = os.path.getmtime(fs)
    hsh.update(f"{modification_timestamp}".encode())
    # add the fstype - if it changes we need to rebuild
    hsh.update("ext4".encode())
    return hsh.hexdigest()


def _load_penguin_analysis_from(plugin_file: str) -> PenguinAnalysis:
    """
    Given a path to a python file, load it and find the first class
    that subclasses PenguinAnalysis. Instantiate it with run_dir and
    return it.

    :param plugin_file: Path to the plugin file.
    :type plugin_file: str
    :return: Instance of PenguinAnalysis subclass.
    :rtype: PenguinAnalysis
    :raises ValueError: If no subclass is found.
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


def get_mount_type(path: str) -> Optional[str]:
    """
    Get the filesystem type of the mount at the given path.

    :param path: Path to check.
    :type path: str
    :return: Filesystem type string or None.
    :rtype: str or None
    """
    try:
        stat_output = subprocess.check_output(["stat", "-f", "-c", "%T", path])
        return stat_output.decode("utf-8").strip().lower()
    except subprocess.CalledProcessError:
        return None


def construct_empty_fs(path: str) -> None:
    """
    Construct an empty filesystem archive at the given path.

    :param path: Path to create the archive.
    :type path: str
    """
    subprocess.check_output(f"tar -czf {path} -T /dev/null", shell=True)


def get_mitigation_providers(config: dict) -> Dict[str, Any]:
    """
    Given a config, pull out all the enabled mitigation providers,
    load them and return a dict of {ANALYSIS_TYPE: analysis class object}

    Skip plugins that are disabled in config.
    Raise an error if version of a plugin mismatches the config version.

    :param config: Configuration dictionary.
    :type config: dict
    :return: Dictionary mapping ANALYSIS_TYPE to analysis class object.
    :rtype: dict[str, Any]
    :raises ValueError: On version mismatch.
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
        # plugin versions are now optional
        if "version" in details and details["version"] != analysis.VERSION:
            raise ValueError(
                f"Config specifies plugin {plugin_name} at version {details['version']} but we got {analysis.VERSION}"
            )

        # print(f"Loaded {plugin_name} at version {details['version']}")
    return mitigation_providers


def get_kernel(conf: dict, proj_dir: str) -> str:
    """
    Get the kernel path for the given configuration and project directory.

    :param conf: Configuration dictionary.
    :type conf: dict
    :param proj_dir: Project directory.
    :type proj_dir: str
    :return: Path to the kernel file.
    :rtype: str
    :raises ValueError: If kernel cannot be found or multiple kernels found.
    """
    kernel = conf["core"].get("kernel", None)
    if kernel:
        if os.path.exists(kernel) and os.path.isfile(kernel):
            return kernel
    from penguin.q_config import load_q_config
    from glob import glob
    q_config = load_q_config(conf)
    kernel_fmt = q_config.get("kernel_fmt", "vmlinux")
    kernel_whole = q_config.get('kernel_whole', f"vmlinux.{q_config['arch']}")
    options = [
        f"/igloo_static/kernels/*/{kernel_fmt}.{q_config['arch']}",
        f"/igloo_static/kernels/*/{kernel_whole}",
    ]
    kernels = []
    for opt in options:
        kernels = glob(opt)
        if len(kernels) == 1:
            return kernels[0]
        elif len(kernels) != 0:
            # kernel can be a substring of the version
            # but must match exactly one
            if kernel is not None:
                options = [i for i in kernels if kernel in i]
                if len(options) == 1:
                    return options[0]
                elif len(options) == 0:
                    logger.warning(f"Kernel input '{kernel}' did not match any of the options.")
                else:
                    logger.warning(f"Kernel '{kernel}' matched {len(options)} options: {options}. It must match exactly one.")
                # If kernel path was set but doesn't exist, treat as unset
                kernel = None

            # For old configurations without kernel specified, try using KernelVersionFinder
            if kernel is None:
                try:
                    logger.info("Multiple kernels found, trying to suggest one using static analysis")
                    from .static_analyses import KernelVersionFinder
                    fs_path = os.path.join(proj_dir, conf["core"].get("fs"))
                    if fs_path and os.path.exists(fs_path):
                        # Extract filesystem to temporary location and analyze
                        import tempfile
                        import tarfile
                        with tempfile.TemporaryDirectory() as temp_dir:
                            with tarfile.open(fs_path, 'r:*') as tar:
                                tar.extractall(temp_dir)
                            finder = KernelVersionFinder()
                            result = finder.run(temp_dir, {})
                            if result and result.get("selected_kernel"):
                                suggested_version = result["selected_kernel"]
                                # Find matching kernel from available options
                                for k in kernels:
                                    if suggested_version in k:
                                        logger.info(f"Suggested kernel: {k} based on static analysis")
                                        return k
                    else:
                        logger.error(f"Could not open {fs_path} to analyze for kernel version")
                except Exception as e:
                    logger.error(f"Error during KernelVersionFinder analysis: {e}")

            raise ValueError(f"Multiple kernels found for {q_config['arch']}: {kernels}")
    if len(kernels) == 0:
        raise ValueError(f"Kernel not found for {q_config['arch']}")


def get_available_kernel_versions() -> List[Tuple[int, ...]]:
    """
    Scan /igloo_static/kernels and return a list of available kernel versions
    as tuples of integers, e.g., [(5, 15, 0), (6, 1, 55)]

    :return: List of kernel version tuples.
    :rtype: list[tuple[int, ...]]
    """
    kernels_dir = os.path.join(STATIC_DIR, "kernels")
    if not os.path.isdir(kernels_dir):
        return []

    versions = []
    for entry in os.listdir(kernels_dir):
        entry_path = os.path.join(kernels_dir, entry)
        if os.path.isdir(entry_path):
            try:
                version_tuple = get_penguin_kernel_version({"core": {"kernel": entry_path}})
                versions.append(version_tuple)
            except ValueError:
                continue  # Skip directories that don't represent valid versions

    return versions


def get_penguin_kernel_version(conf: dict) -> Tuple[int, ...]:
    """
    Extract kernel version tuple from conf['core']['kernel'].

    Expected path format:
        /igloo_static/kernels/<VERSION>/<kernel_filename>

    <VERSION> may have a suffix (e.g., 6.1.55-custom); the suffix after the first
    '-' is ignored. Only leading dot-separated numeric components are returned.

    :param conf: Configuration dictionary.
    :type conf: dict
    :return: Tuple of integers representing the version, e.g., (6, 1, 55)
    :rtype: tuple[int, ...]
    :raises ValueError: If the version cannot be determined.
    """
    kernel_path = conf["core"].get("kernel")
    if not kernel_path:
        raise ValueError("Missing conf['core']['kernel']")

    parts = [p for p in kernel_path.split("/") if p]
    try:
        k_idx = parts.index("kernels")
        version_part = parts[k_idx + 1]
    except (ValueError, IndexError):
        raise ValueError(f"Kernel path does not contain a version segment: {kernel_path}")

    # Drop suffix after '-' if present (e.g., 6.1.55-custom -> 6.1.55)
    base_version = version_part.split("-", 1)[0]

    nums = []
    for token in base_version.split("."):
        if token.isdigit():
            nums.append(int(token))
        else:
            break

    if not nums:
        raise ValueError(f"Unable to parse numeric version from: {version_part}")

    return tuple(nums)


class Base64BytesEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that converts bytes objects to base64 strings.
    Used for outputting the config as JSON.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return {
                "__type__": "bytes",
                "__data__": base64.b64encode(obj).decode('ascii')
            }
        return super().default(obj)
