import os
import re
from subprocess import check_output, PIPE, SubprocessError
from penguin import getColoredLogger

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
            if hasattr(e, "returncode") and e.returncode == 1:
                return {}
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
