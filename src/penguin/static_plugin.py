from abc import ABC

class StaticPlugin(ABC):
    """
    Base class for all static plugins (analyses and patchers).
    """
    # List of plugin class names that this plugin depends on.
    depends_on = []

    def __init__(self, fs_archive: str, extracted_fs: str, prior_results: dict):
        self.enabled = True
        # Set a default name based on the class name, but allow override
        self.plugin_name = self.__class__.__name__
        self.fs_archive = fs_archive
        self.extracted_fs = extracted_fs
        self.prior_results = prior_results


class StaticAnalysisPlugin(StaticPlugin):
    """
    Base class for static analyses.
    """
    def run(self) -> any:
        """
        Run the static analysis and return the result.
        """
        pass

class ConfigPatcherPlugin(StaticPlugin):
    """
    Base class for config patchers.
    """
    def generate(self, patches: dict) -> dict | None:
        """
        Generate a patch dictionary.
        """
        pass
