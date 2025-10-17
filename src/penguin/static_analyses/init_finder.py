import os
import stat
import re
from penguin import getColoredLogger
from .base import StaticAnalysis

logger = getColoredLogger("penguin.static_analyses")

class InitFinder(StaticAnalysis):
    '''
    Find potential init scripts and binaries in an extracted filesystem.
    '''
    def run(self, filesystem_root_path: str, prior_results: dict) -> list[str]:
        '''
        Search the filesystem for binaries that might be init scripts.

        :param filesystem_root_path: Root path of extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Sorted list of init script paths.
        '''
        inits = []

        # Walk through the filesystem root and find potential init scripts.
        for root, dirs, files in os.walk(filesystem_root_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if self._is_init_script(filepath, filesystem_root_path):
                    inits.append("/" + os.path.relpath(filepath, filesystem_root_path))

        # Sort inits by length, shortest to longest.
        inits.sort(key=lambda x: len(x))

        target_inits = ["preinit", "init", "rcS"]
        for potential in target_inits[::-1]:
            try:
                idx = [x.split("/")[-1] for x in inits].index(potential)
            except ValueError:
                continue
            match = inits.pop(idx)
            inits.insert(0, match)

        inits = [i for i in inits if len(i) <= 32]

        inits = [
            i for i in inits
            if os.stat(os.path.join(filesystem_root_path, i.lstrip("/"))).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ]

        return inits

    @staticmethod
    def _is_init_script(filepath: str, fsroot: str) -> bool:
        '''
        Determine if a file is a potential init script.

        :param filepath: Path to file.
        :param fsroot: Filesystem root.
        :return: True if file is a potential init script.
        '''
        if filepath.startswith("./igloo"):
            return False

        if not os.path.isfile(filepath) and not os.path.islink(filepath):
            return False

        name = os.path.basename(filepath)
        if any([x in name for x in ["init", "start"]]) and not any(
            [x in name for x in ["inittab", "telinit", "initd"]]
        ):
            if "start" in name and not re.search(r"[\W_\-\.]start[\W_\-\.]", name):
                return False

            if os.path.islink(filepath):
                link_target = os.readlink(filepath)
                if os.path.isabs(link_target):
                    result = os.path.join(fsroot, "./"+link_target)
                else:
                    result = os.path.join(os.path.dirname(filepath), link_target)
                if not os.path.exists(result):
                    logger.warning(
                        f"Potential init '{filepath}' is a symlink to '{link_target}' which does not exist in the filesystem"
                    )
                    return False

            if "init" in name and name.endswith(".init"):
                return False

            if os.path.isfile(filepath) and os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

        elif "rcS" in name:
            if os.path.isfile(filepath) and os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

        return False
