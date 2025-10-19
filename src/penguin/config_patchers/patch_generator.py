from abc import ABC, abstractmethod

class PatchGenerator(ABC):
    def __init__(self) -> None:
        self.enabled: bool = True
        self.patch_name: str | None = None

    @abstractmethod
    def generate(self, patches: dict) -> dict | None:
        """
        Generate a patch dictionary.

        :param patches: Existing patches dictionary.
        :type patches: dict
        :return: Patch dictionary or None.
        :rtype: dict or None
        """
        raise NotImplementedError("Subclasses should implement this method")
