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
        results = {}
        if not ignore:
            ignore = tuple()
        elif isinstance(ignore, list):
            ignore = tuple(ignore)

        pattern_str = target_regex.pattern
        extract_path_str = str(extract_root)

        try:
            file_list_output = check_output(
                f"rg --files-with-matches -a '{pattern_str}' '{extract_path_str}'",
                stderr=PIPE,
                shell=True,
            )

            if file_list_output:
                for filepath in file_list_output.decode().splitlines():
                    if not os.path.isfile(filepath) or os.path.islink(filepath):
                        continue
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                    except Exception as e:
                        logger.warning(f"failed to read file {filepath}: {e}")
                        continue
                    matches = target_regex.findall(content)
                    for match in matches:
                        if match in ignore:
                            continue
                        if match not in results:
                            results[match] = {"count": 0, "files": set()}
                        results[match]["count"] += 1
                        results[match]["files"].add(filepath)
        except (SubprocessError, FileNotFoundError) as e:
            if hasattr(e, 'returncode') and e.returncode == 1:
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
        results = {}
        if not ignore:
            ignore = []

        for root, dirs, files in os.walk(extract_root):
            for filename in files:
                filepath = os.path.join(root, filename)

                if filepath.startswith(os.path.join(extract_root, "igloo")):
                    continue

                if not os.path.isfile(filepath) or os.path.islink(filepath):
                    continue

                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception as e:
                    logger.warning(f"failed to read file {filepath}: {e}")
                    continue

                matches = target_regex.findall(content)
                for match in matches:
                    if match in ignore:
                        continue
                    if match not in results:
                        results[match] = {"count": 0, "files": set()}
                    results[match]["count"] += 1
                    results[match]["files"].add(filepath)

        return results
