"""
Find potential init scripts and binaries in the extracted filesystem.
"""

import os
import re
import stat

from penguin import getColoredLogger
from penguin.init_plugin import InitPlugin, cached_analysis

logger = getColoredLogger("penguin.init.init_finder")


class InitFinder(InitPlugin):
    '''
    Find potential init scripts and binaries in an extracted filesystem.
    '''
    @cached_analysis
    def inits(self) -> list[str]:
        '''
        Search the filesystem for binaries that might be init scripts.

        :return: Sorted list of init script paths.
        '''
        filesystem_root_path = str(self.ctx.extracted_fs)
        inits = []

        # Walk through the filesystem root and find potential init scripts.
        for root, dirs, files in os.walk(filesystem_root_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if self._is_init_script(filepath, filesystem_root_path):
                    inits.append("/" + os.path.relpath(filepath, filesystem_root_path))

        # Sort inits by length, shortest to longest.
        inits.sort(key=lambda x: len(x))

        # Deprecated: kernel_inits. Filesystem extraction could try analyzing kernel binary
        # to find init argument built into the kernel. We do not currently do this or have a
        # way to pass this information through
        '''
        # Examine `init.txt` in the output directory, if it exists.
        kernel_inits = []
        try:
            with open(os.path.join(output_dir, "init.txt"), "r") as f:
                kernel_inits = [x.strip() for x in f.readlines()]
            os.remove(os.path.join(output_dir, "init.txt"))
        except FileNotFoundError:
            # No `init.txt`, it's okay.
            pass

        if kernel_inits:
            # Combine `kernel_inits` with `inits`, prioritizing `kernel_inits`.
            common_inits = [x for x in kernel_inits if x in inits]
            only_fs_inits = [x for x in inits if x not in common_inits]
            common_inits.sort(key=lambda x: len(x))
            only_fs_inits.sort(key=lambda x: len(x))
            inits = common_inits + only_fs_inits
        '''

        # Now rank our init options, using the same ranking as Firmadyne/Firmae where
        # a few specific inits are prioritized, then fallback to others

        target_inits = ["preinit", "init", "rcS"]
        # If any of these are in our init list, move them to the front
        # but maintain this order (i.e., preinit goes before /init so loop backwards)
        for potential in target_inits[::-1]:
            try:
                idx = [x.split("/")[-1] for x in inits].index(potential)
            except ValueError:
                # No match
                continue
            # Move to front
            match = inits.pop(idx)
            inits.insert(0, match)

        # Remove entries longer than 32 characters.
        inits = [i for i in inits if len(i) <= 32]

        # Final pass to ensure all inits are executable.
        # Trim the first / in the path to ensure it's relative to our extract dir
        inits = [
            i for i in inits
            if os.stat(os.path.join(filesystem_root_path, i[:1])).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ]

        return inits

    def static_result(self) -> list[str]:
        return self.inits

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
            # If 'start' is in the name, ensure it's not part of "restart" or "startup".
            if "start" in name and not re.search(r"[\W_\-\.]start[\W_\-\.]", name):
                return False

            # Handle symlinks: make sure the link target exists.
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

            # If 'init' is in the name, ensure it's not named `.init`.
            if "init" in name and name.endswith(".init"):
                return False

            # Check if the file is executable.
            if os.path.isfile(filepath) and os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

        elif "rcS" in name:
            if os.path.isfile(filepath) and os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

        return False
