import os
from collections import Counter
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from penguin.static_plugin import StaticAnalysisPlugin
from penguin import getColoredLogger
from penguin.arch import arch_filter

logger = getColoredLogger("penguin.static_analyses")

class ArchId(StaticAnalysisPlugin):
    """
    Identify the most common architecture in the extracted filesystem.
    """
    def run(self) -> str:
        arch_counts = {32: Counter(), 64: Counter(), "unknown": 0}
        for root, _, files in os.walk(self.extracted_fs):
            for file_name in files:
                path = os.path.join(root, file_name)

                if (
                    os.path.isfile(path)
                    and not os.path.islink(path)
                    and self._binary_filter(self.extracted_fs, path)
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

        intel_archs = ("intel", "intel64")
        archs_list = list(arch_counts[32].keys()) + list(arch_counts[64].keys())
        if any(arch in intel_archs for arch in archs_list) and any(
            arch not in intel_archs for arch in archs_list
        ):
            del arch_counts[32]["intel"]
            if "intel64" in arch_counts[64]:
                del arch_counts[64]["intel64"]

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

        if arch_counts["unknown"] > best_count:
            for arch, count in arch_counts[32].items():
                logger.info(f"32-bit arch {arch} has {count} files")
            for arch, count in arch_counts[64].items():
                logger.info(f"64-bit arch {arch} has {count} files")
            logger.info(f"Unknown architecture count: {arch_counts['unknown']}")
            raise ValueError("Failed to determine architecture of filesystem")

        logger.debug(f"Identified architecture: {best}")
        return best

    @staticmethod
    def _binary_filter(fsbase: str, name: str) -> bool:
        base_directories = ["sbin", "bin", "usr/sbin", "usr/bin"]
        for base in base_directories:
            if name.startswith(os.path.join(fsbase, base)):
                return True
        return name.endswith((".so", ".ko")) or \
            ".so." in name or \
            name.endswith("busybox")
