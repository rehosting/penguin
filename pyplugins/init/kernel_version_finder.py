"""
Find kernel versions in the filesystem and select the best available match.
"""

from penguin.init_plugin import InitPlugin, cached_analysis
from penguin.static_analyses import find_kernel_versions


class KernelVersionFinder(InitPlugin):
    """
    Find and select the best kernel version from extracted filesystem.
    """
    @cached_analysis
    def versions(self) -> dict[str, list[str] | str]:
        """
        Run kernel version analysis.

        :return: Dict with potential and selected kernel versions.
        """
        return find_kernel_versions(str(self.ctx.extracted_fs))

    def static_result(self) -> dict[str, list[str] | str]:
        return self.versions
