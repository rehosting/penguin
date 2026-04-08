import os
import re
import stat
from penguin.static_plugin import StaticAnalysisPlugin
from penguin import getColoredLogger

logger = getColoredLogger("penguin.static_analyses")

class InitFinder(StaticAnalysisPlugin):
    """
    Find potential init scripts and binaries in an extracted filesystem.
    """
    def run(self) -> list[str]:
        inits = []

        for root, dirs, files in os.walk(self.extracted_fs):
            for filename in files:
                filepath = os.path.join(root, filename)
                if self._is_init_script(filepath, self.extracted_fs):
                    inits.append("/" + os.path.relpath(filepath, self.extracted_fs))

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
            if os.stat(os.path.join(self.extracted_fs, i.lstrip("/"))).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ]

        return inits

    @staticmethod
    def _is_init_script(filepath: str, fsroot: str) -> bool:
        if filepath.startswith(os.path.join(fsroot, "igloo")):
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
