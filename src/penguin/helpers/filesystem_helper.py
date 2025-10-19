import os
import re
import subprocess
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
        :return: Dict of {match: {"count": int, "files": set[str]}}
        """
        results: dict[str, dict] = {}
        if not ignore:
            ignore_t = tuple()
        elif isinstance(ignore, list):
            ignore_t = tuple(ignore)
        else:
            ignore_t = ignore

        pattern_str = target_regex.pattern
        root = str(extract_root)

        def _accumulate(filepath: str, content: str) -> None:
            try:
                matches = target_regex.findall(content)
            except Exception as e:
                logger.warning(f"regex findall failed in {filepath}: {e}")
                return

            for m in matches:
                # Support both single-group and multi-group regexes.
                match = m
                if not isinstance(match, str):
                    # Prefer first non-empty group if tuple/list
                    try:
                        match = next((g for g in match if g), match[0])
                    except Exception:
                        match = str(m)

                if match in ignore_t:
                    continue

                if match not in results:
                    results[match] = {"count": 0, "files": set()}
                results[match]["count"] += 1
                results[match]["files"].add(filepath)

        def _scan_files(file_list: list[str]) -> dict:
            for fp in file_list:
                try:
                    if not os.path.isfile(fp) or os.path.islink(fp):
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        _accumulate(fp, f.read())
                except Exception as e:
                    logger.warning(f"failed to read file {fp}: {e}")
                    continue
            return results

        # First try ripgrep without PCRE2; retry with PCRE2 on engine error.
        try:
            # ripgrep exit codes: 0=match, 1=no matches, 2=error
            args = ["rg", "--files-with-matches", "-a", "--no-messages", "-uu", pattern_str, root]
            proc = subprocess.run(args, capture_output=True, text=True)

            if proc.returncode == 1:
                # No matches anywhere: preserve existing behavior (return empty)
                return {}
            elif proc.returncode == 0:
                files = proc.stdout.splitlines()
                return _scan_files(files)
            else:
                # Try again with PCRE2 (look-around etc.) in case the engine failed.
                args_pcre2 = ["rg", "-P", "--files-with-matches", "-a", "--no-messages", "-uu", pattern_str, root]
                proc2 = subprocess.run(args_pcre2, capture_output=True, text=True)
                if proc2.returncode == 1:
                    return {}
                elif proc2.returncode == 0:
                    files = proc2.stdout.splitlines()
                    return _scan_files(files)
                else:
                    logger.warning(
                        f"ripgrep failed (code {proc.returncode}/{proc2.returncode}); "
                        "falling back to pure Python regex walk"
                    )
                    return FileSystemHelper._find_regex_python(target_regex, extract_root, ignore_t)
        except FileNotFoundError:
            # rg not installed; fall back to Python.
            logger.warning("ripgrep not found; falling back to pure Python regex walk")
            return FileSystemHelper._find_regex_python(target_regex, extract_root, ignore_t)
        except Exception as e:
            logger.warning(f"ripgrep error ({e}); falling back to pure Python regex walk")
            return FileSystemHelper._find_regex_python(target_regex, extract_root, ignore_t)

    @staticmethod
    def _find_regex_python(
        target_regex: re.Pattern,
        extract_root: str,
        ignore: list | tuple | None = None
    ) -> dict:
        """
        Fallback implementation using Python's built-in regex.

        Return shape matches find_regex(): {match: {"count": int, "files": set(str)}}
        """
        results: dict[str, dict] = {}
        ignore_t = tuple(ignore or ())

        for root, _, files in os.walk(extract_root):
            for filename in files:
                filepath = os.path.join(root, filename)

                # keep legacy behavior: skip our own ./igloo artifacts
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

                try:
                    matches = target_regex.findall(content)
                except Exception as e:
                    logger.warning(f"regex findall failed in {filepath}: {e}")
                    continue

                for m in matches:
                    match = m
                    if not isinstance(match, str):
                        try:
                            match = next((g for g in match if g), match[0])
                        except Exception:
                            match = str(m)
                    if match in ignore_t:
                        continue

                    if match not in results:
                        results[match] = {"count": 0, "files": set()}
                    results[match]["count"] += 1
                    results[match]["files"].add(filepath)

        return results

    @staticmethod
    def find_regex_scoped(
        target_regex: re.Pattern,
        extract_root: str,
        ignore: list | tuple | None = None,
        globs_include: tuple[str, ...] = (),
        globs_exclude: tuple[str, ...] = ("**/*.so","**/*.ko*","**/*.bin","**/*.o","**/*.pyc","**/proc/**","**/sys/**","**/dev/**"),
        use_pcre2: bool | None = None,
        treat_binary_as_text: bool = True,
    ) -> dict:
        """
        Like find_regex(), but lets callers restrict the search space via ripgrep globs.
        Return shape is IDENTICAL to find_regex(): { match: {"count": int, "files": set(str)} }.
        Safe if rg is missing; falls back to _find_regex_python().
        """
        results: dict[str, dict] = {}
        ignore_t = tuple(ignore or ())
        pattern_str = target_regex.pattern
        root = str(extract_root)

        def _accumulate(filepath: str, content: str) -> None:
            try:
                matches = target_regex.findall(content)
            except Exception as e:
                logger.warning(f"regex findall failed in {filepath}: {e}")
                return
            for m in matches:
                match = m if isinstance(m, str) else (next((g for g in m if g), m[0]) if m else "")
                if not match or match in ignore_t:
                    continue
                r = results.setdefault(match, {"count": 0, "files": set()})
                r["count"] += 1
                r["files"].add(filepath)

        def _scan_files(files: list[str]) -> dict:
            for fp in files:
                try:
                    if not os.path.isfile(fp) or os.path.islink(fp):
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        _accumulate(fp, f.read())
                except Exception as e:
                    logger.warning(f"failed to read file {fp}: {e}")
                    continue
            return results

        try:
            args = ["rg", "--files-with-matches", "--no-messages", "-uu"]
            if treat_binary_as_text:
                args.append("-a")

            # enable PCRE2 if needed or requested
            needs_pcre2 = bool(re.search(r"\(\?<|(?<=\))\?|\(\?>", pattern_str))
            if use_pcre2 or needs_pcre2:
                args.append("-P")

            for g in globs_exclude:
                args += ["--glob", f"!{g}"]
            for g in globs_include:
                args += ["--glob", g]

            args += [pattern_str, root]
            proc = subprocess.run(args, capture_output=True, text=True)

            if proc.returncode == 1:    # no matches
                return {}
            if proc.returncode == 0:
                return _scan_files(proc.stdout.splitlines())

            # engine error? if we didn't already try PCRE2, retry with -P
            if "-P" not in args:
                args_p = args[:]
                args_p.insert(1, "-P")
                proc2 = subprocess.run(args_p, capture_output=True, text=True)
                if proc2.returncode == 1:
                    return {}
                if proc2.returncode == 0:
                    return _scan_files(proc2.stdout.splitlines())

            logger.warning(f"ripgrep failed (code {proc.returncode}); falling back to pure Python")
            return FileSystemHelper._find_regex_python(target_regex, extract_root, list(ignore_t))
        except FileNotFoundError:
            logger.warning("ripgrep not found; falling back to pure Python")
            return FileSystemHelper._find_regex_python(target_regex, extract_root, list(ignore_t))
        except Exception as e:
            logger.warning(f"ripgrep error ({e}); falling back to pure Python")
            return FileSystemHelper._find_regex_python(target_regex, extract_root, list(ignore_t))
