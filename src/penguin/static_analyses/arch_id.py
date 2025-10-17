from collections import Counter
import os
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from penguin import getColoredLogger
from .base import StaticAnalysis
from ..arch import arch_filter

logger = getColoredLogger("penguin.static_analyses")

class ArchId(StaticAnalysis):
    """
    Identify the most common architecture in the extracted filesystem.
    """
    def run(self, extracted_fs: str, prior_results: dict) -> str:
        '''
        Count architectures to identify most common.

        If both 32 and 64 bit binaries from the most common architecture are present,
        prefer 64-bit. Raise an error if architecture cannot be determined or is unsupported.

        :param extracted_fs: Path to extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Most common architecture string.
        :raises ValueError: If unable to determine architecture.
        '''

        arch_counts = {32: Counter(), 64: Counter(), "unknown": 0}
        for root, _, files in os.walk(extracted_fs):
            for file_name in files:
                path = os.path.join(root, file_name)

                if (
                    os.path.isfile(path)
                    and not os.path.islink(path)
                    and self._binary_filter(extracted_fs, path)
                ):
                    logger.debug(f"Checking architecture in {path}")
                    with open(path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue
                        f.seek(0)
                        try:
                            ef = ELFFile(f)
                        except ELFError as e:
                            logger.warning(f"Failed to parse ELF file {path}: {e}. Ignoring")
                            continue
                        info = arch_filter(ef)
                    if info.bits is None or info.arch is None:
                        arch_counts["unknown"] += 1
                    else:
                        arch_counts[info.bits][info.arch] += 1

        # If there is at least one intel and non-intel arch,
        # filter out all the intel ones.
        # Some firmwares include x86_64 binaries left-over from the build process that aren't run in the guest.
        intel_archs = ("intel", "intel64")
        archs_list = list(arch_counts[32].keys()) + list(arch_counts[64].keys())
        if any(arch in intel_archs for arch in archs_list) and any(
            arch not in intel_archs for arch in archs_list
        ):
            del arch_counts[32]["intel"]
            del arch_counts[64]["intel64"]

        # Now select the most common architecture.
        # First try the most common 64-bit architecture.
        # Then try the most common 32-bit one.
        best_64 = arch_counts[64].most_common(1)
        best_32 = arch_counts[32].most_common(1)
        if len(best_64) != 0:
            best = best_64[0][0]
            best_count = best_64[0][1]
        elif len(best_32) != 0:
            best = best_32[0][0]
            best_count = best_32[0][1]
        else:
            raise ValueError("Failed to determine architecture of filesystem")

        # If unknown is the most common, we'll raise an error
        if arch_counts["unknown"] > best_count:
            # Dump debug info - which arches have what counts?
            for arch, count in arch_counts[32].items():
                logger.info(f"32-bit arch {arch} has {count} files")

            for arch, count in arch_counts[64].items():
                logger.info(f"64-bit arch {arch} has {count} files")

            # Finally, report unknown count
            logger.info(f"Unknown architecture count: {arch_counts['unknown']}")
            raise ValueError("Failed to determine architecture of filesystem")

        logger.debug(f"Identified architecture: {best}")
        return best

    @staticmethod
    def _binary_filter(fsbase: str, name: str) -> bool:
        """
        Filter for binary files of interest.

        :param fsbase: Base directory.
        :param name: File path.
        :return: True if file is a relevant binary.
        """
        base_directories = ["sbin", "bin", "usr/sbin", "usr/bin"]
        for base in base_directories:
            if name.startswith(os.path.join(fsbase, base)):
                return True
        # Shared libraries, kernel modules, or busybox
        return name.endswith((".so", ".ko")) or \
            ".so." in name or \
            name.endswith("busybox")
