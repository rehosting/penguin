"""
penguin.static_analyses
=======================

Filesystem-analysis helpers shared by penguin core and the init plugins in
pyplugins/init/ (the analysis classes themselves live there).
"""

import os
import re

from subprocess import check_output, PIPE, SubprocessError

from penguin import getColoredLogger
from penguin.utils import get_available_kernel_versions
from penguin.defaults import DEFAULT_KERNEL

logger = getColoredLogger("penguin.static_analyses")


class FileSystemHelper:
    @staticmethod
    def find_regex(
        target_regex: re.Pattern,
        extract_root: str,
        ignore: list | tuple | None = None
    ) -> dict:
        """
        Search the filesystem for matches to a regex pattern using ripgrep.

        :param target_regex: Compiled regex pattern to match.
        :param extract_root: Root directory to search.
        :param ignore: Optional list/tuple of matches to ignore.
        :return: Dict of {match: {"count": int, "files": [str]}}
        """
        results = {}
        if not ignore:
            ignore = tuple()
        elif isinstance(ignore, list):
            ignore = tuple(ignore)

        pattern_str = target_regex.pattern
        extract_path_str = str(extract_root)

        try:
            # Get list of files containing matches
            file_list_output = check_output(
                f"rg --files-with-matches -a '{pattern_str}' '{extract_path_str}'",
                stderr=PIPE,
                shell=True,
            )

            # Process each file with Python's regex to extract actual matches
            if file_list_output:
                for filepath in file_list_output.decode().splitlines():
                    if not os.path.isfile(filepath) or os.path.islink(filepath):
                        continue

                    # open the file and read the content
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                    except Exception as e:
                        logger.warning(f"failed to read file {filepath}: {e}")
                        continue
                    # apply regex pattern to find matches
                    matches = target_regex.findall(content)
                    for match in matches:
                        if match in ignore:
                            continue
                        if match not in results:
                            results[match] = {"count": 0, "files": set()}
                        results[match]["count"] += 1
                        results[match]["files"].add(filepath)
        except (SubprocessError, FileNotFoundError) as e:
            if e.returncode == 1:
                return {}
            else:
                logger.warning(f"Failed to run ripgrep: {e} - falling back to pure Python regex")
                return FileSystemHelper._find_regex_python(target_regex, extract_root, ignore)

        return results

    @staticmethod
    def _find_regex_python(
        target_regex: re.Pattern,
        extract_root: str,
        ignore: list | None = None
    ) -> dict:
        """
        Fallback implementation using Python's built-in regex.

        :param target_regex: Compiled regex pattern to match.
        :param extract_root: Root directory to search.
        :param ignore: Optional list of matches to ignore.
        :return: Dict of {match: {"count": int, "files": [str]}}
        """
        results = {}
        if not ignore:
            ignore = []

        # iterate through each file in the extracted root directory
        for root, dirs, files in os.walk(extract_root):
            for filename in files:
                filepath = os.path.join(root, filename)

                # skip our files in the "./igloo" path
                if filepath.startswith(os.path.join(extract_root, "igloo")):
                    continue

                # skip non-regular files if `only_files` is true
                if not os.path.isfile(filepath) or os.path.islink(filepath):
                    continue

                # open the file and read the content
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception as e:
                    logger.warning(f"failed to read file {filepath}: {e}")
                    continue

                # apply regex pattern to find matches
                matches = target_regex.findall(content)
                for match in matches:
                    if match in ignore:
                        continue
                    if match not in results:
                        results[match] = {"count": 0, "files": set()}
                    results[match]["count"] += 1
                    results[match]["files"].add(filepath)

        return results


def is_kernel_version(name: str) -> bool:
    """
    Check if a string matches a kernel version pattern.

    :param name: Version string.
    :return: True if matches kernel version pattern.
    """
    return re.match(r"^\d+\.\d+\.\d+(-[\w\.]+)?$", name) is not None


def select_best_kernel(kernel_versions: set[str]) -> str:
    """
    Select the most recent kernel version and match to available kernels.

    :param kernel_versions: Iterable of kernel version strings.
    :return: Best matching kernel version string.
    """
    if not kernel_versions:
        return DEFAULT_KERNEL

    # Parse kernel versions into tuples for comparison
    def parse_version(ver):
        base = ver.split("-", 1)[0]
        return tuple(int(t) for t in base.split(".") if t.isdigit())

    # Sort kernel_versions by parsed version, descending
    sorted_versions = sorted(kernel_versions, key=parse_version, reverse=True)
    most_recent = sorted_versions[0]

    # Now use the logic from the previous select_best_kernel
    base_version = most_recent.split("-", 1)[0]
    guest_tokens = base_version.split(".")
    guest_version = tuple(int(t) for t in guest_tokens if t.isdigit())
    guest_major = guest_version[0] if guest_version else None

    available_versions = get_available_kernel_versions()

    major_matches = [v for v in available_versions if v[0] == guest_major]

    def version_distance(v):
        maxlen = max(len(v), len(guest_version))
        v_pad = v + (0,) * (maxlen - len(v))
        g_pad = guest_version + (0,) * (maxlen - len(guest_version))
        return sum(abs(a - b) for a, b in zip(v_pad, g_pad))

    if major_matches:
        best = min(major_matches, key=version_distance)
    else:
        best = min(available_versions, key=version_distance)

    best_str = ".".join(str(x) for x in best)
    return best_str


def find_kernel_versions(extract_dir: str) -> dict[str, list[str] | str]:
    """
    Find kernel versions under ``<extract_dir>/lib/modules`` and select the
    best-matching available kernel. Shared by the KernelVersionFinder init
    plugin and runtime kernel resolution (penguin.utils).

    :param extract_dir: Directory containing an extracted filesystem.
    :return: Dict with potential and selected kernel versions.
    """
    potential_kernels = set()

    # Only look at the top-level directories in extract_dir / lib / modules
    modules_path = os.path.join(extract_dir, "lib/modules")
    if os.path.exists(modules_path):
        for d in os.listdir(modules_path):
            d_path = os.path.join(modules_path, d)
            if os.path.isdir(d_path):
                potential_kernels.add(d)

    # Filter potential kernels to match the expected version pattern
    potential_kernels = {d for d in potential_kernels if is_kernel_version(d)}
    selected_kernel = select_best_kernel(potential_kernels)
    return {
        "potential_kernels": sorted(potential_kernels),
        "selected_kernel": selected_kernel,
    }
