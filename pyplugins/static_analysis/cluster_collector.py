import os
from subprocess import check_output, CalledProcessError, STDOUT
from penguin.static_plugin import StaticAnalysisPlugin
from penguin import getColoredLogger

logger = getColoredLogger("penguin.static_analyses")

class ClusterCollector(StaticAnalysisPlugin):
    """
    Collect summary statistics for the filesystem to help identify clusters.
    """
    def run(self) -> dict[str, list[str]]:
        all_files = set()
        executables = set()
        executable_hashes = set()

        for root, _, files in os.walk(self.extracted_fs):
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

    @staticmethod
    def compute_file_hash(file_path: str) -> str | None:
        try:
            output = check_output(["sha256sum", file_path], stderr=STDOUT)
            return output.decode('utf-8').split()[0]
        except (CalledProcessError, FileNotFoundError, IOError) as e:
            logger.debug(f"Failed to hash file {file_path}: {e}")
            return None
