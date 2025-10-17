import os
import re
from penguin.defaults import DEFAULT_KERNEL
from penguin.utils import get_available_kernel_versions
from penguin import getColoredLogger
from .base import StaticAnalysis

logger = getColoredLogger("penguin.static_analyses")

class KernelVersionFinder(StaticAnalysis):
    """
    Find and select the best kernel version from extracted filesystem.
    """
    @staticmethod
    def is_kernel_version(name: str) -> bool:
        """
        Check if a string matches a kernel version pattern.

        :param name: Version string.
        :return: True if matches kernel version pattern.
        """
        return re.match(r"^\d+\.\d+\.\d+(-[\w\.]+)?$", name) is not None

    @staticmethod
    def select_best_kernel(kernel_versions: set[str]) -> str:
        """
        Select the most recent kernel version and match to available kernels.

        :param kernel_versions: Iterable of kernel version strings.
        :return: Best matching kernel version string.
        """
        if not kernel_versions:
            return DEFAULT_KERNEL

        def parse_version(ver):
            base = ver.split("-", 1)[0]
            return tuple(int(t) for t in base.split(".") if t.isdigit())

        sorted_versions = sorted(kernel_versions, key=parse_version, reverse=True)
        most_recent = sorted_versions[0]

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

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str] | str]:
        """
        Run kernel version analysis.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict with potential and selected kernel versions.
        """
        potential_kernels = set()

        modules_path = os.path.join(extract_dir, "lib/modules")
        if os.path.exists(modules_path):
            for d in os.listdir(modules_path):
                d_path = os.path.join(modules_path, d)
                if os.path.isdir(d_path):
                    potential_kernels.add(d)

        potential_kernels = {d for d in potential_kernels if self.is_kernel_version(d)}
        selected_kernel = self.select_best_kernel(potential_kernels)
        return {
            "potential_kernels": sorted(potential_kernels),
            "selected_kernel": selected_kernel,
        }
