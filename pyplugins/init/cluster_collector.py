"""
Collect summary statistics for the filesystem to help identify clusters.
"""

import os

from subprocess import check_output, CalledProcessError, STDOUT

from penguin import getColoredLogger
from penguin.init_plugin import InitPlugin, cached_analysis

logger = getColoredLogger("penguin.init.cluster_collector")


class ClusterCollector(InitPlugin):
    '''
    Collect summary statistics for the filesystem to help identify clusters.
    '''
    @cached_analysis
    def clusters(self) -> dict[str, list[str]]:
        """
        Collect basename and hash of every executable file.

        :return: Dict with lists of files, executables, and hashes.
        """
        extract_dir = str(self.ctx.extracted_fs)

        # Collect the basename + hash of every executable file in the system
        all_files = set()
        executables = set()
        executable_hashes = set()

        for root, _, files in os.walk(extract_dir):
            for f in files:
                file_path = os.path.join(root, f)

                if os.path.isfile(file_path):
                    all_files.add(os.path.basename(f))

                if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                    executables.add(os.path.basename(f))

                    hash_value = self.compute_file_hash(file_path)
                    if hash_value:
                        executable_hashes.add(hash_value)

        return {
            'files': list(all_files),
            'executables': list(executables),
            'executable_hashes': list(executable_hashes)
        }

    def static_result(self) -> dict[str, list[str]]:
        return self.clusters

    @staticmethod
    def compute_file_hash(file_path: str) -> str | None:
        """
        Compute SHA256 hash of a file.

        :param file_path: Path to file.
        :return: Hex digest string or None on failure.
        """
        try:
            # Use the system's sha256sum binary for better performance
            output = check_output(["sha256sum", file_path], stderr=STDOUT)
            # sha256sum output format: '<hash>  <file_path>'
            return output.decode('utf-8').split()[0]
        except (CalledProcessError, FileNotFoundError, IOError) as e:
            logger.debug(f"Failed to hash file {file_path}: {e}")
            return None
