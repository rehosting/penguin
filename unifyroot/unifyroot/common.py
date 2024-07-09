import glob
import os
import re
import tarfile
from typing import Dict, Set, Optional

class FilesystemInfo:
    """
    Represents information about a filesystem.

    Attributes:
        name (str): The name of the filesystem.
        paths (Set[str]): Set of paths in the filesystem.
        references (Set[str]): Set of references found in the filesystem.
        size (int): Total size of the filesystem in bytes.
    """

    def __init__(self, name: str):
        self.name: str = name
        self.paths: Set[str] = set()
        self.references: Set[str] = set()
        self.size: int = 0

    def add_path(self, path: str) -> None:
        """Add a path to the filesystem."""
        self.paths.add(path)

    def add_reference(self, reference: str) -> None:
        """
        Add a reference to the filesystem.

        Args:
            reference (str): The reference to add. Must not contain spaces.
        """
        assert " " not in reference, "References cannot contain spaces"
        self.references.add(reference)

    def set_size(self, size: int) -> None:
        """Set the total size of the filesystem."""
        self.size = size

class FilesystemRepository:
    """
    Manages a collection of FilesystemInfo objects.

    Attributes:
        filesystems (Dict[str, FilesystemInfo]): A dictionary mapping filesystem names to FilesystemInfo objects.
    """

    def __init__(self):
        self.filesystems: Dict[str, FilesystemInfo] = {}

    def add_filesystem(self, name: str) -> None:
        """
        Add a new filesystem to the repository if it doesn't already exist.

        Args:
            name (str): The name of the filesystem to add.
        """
        if name not in self.filesystems:
            self.filesystems[name] = FilesystemInfo(name)

    def get_filesystem(self, name: str) -> Optional[FilesystemInfo]:
        """
        Retrieve a filesystem by name.

        Args:
            name (str): The name of the filesystem to retrieve.

        Returns:
            Optional[FilesystemInfo]: The FilesystemInfo object if found, None otherwise.
        """
        return self.filesystems.get(name)

    def get_all_filesystems(self) -> Dict[str, FilesystemInfo]:
        """
        Get all filesystems in the repository.

        Returns:
            Dict[str, FilesystemInfo]: A dictionary of all filesystems.
        """
        return self.filesystems

    def add_path_to_filesystem(self, name: str, path: str) -> None:
        """
        Add a path to a specific filesystem.

        Args:
            name (str): The name of the filesystem.
            path (str): The path to add.
        """
        if name in self.filesystems:
            self.filesystems[name].add_path(path)

    def add_reference_to_filesystem(self, name: str, reference: str) -> None:
        """
        Add a reference to a specific filesystem.

        Args:
            name (str): The name of the filesystem.
            reference (str): The reference to add.
        """
        if name in self.filesystems:
            self.filesystems[name].add_reference(reference)

    def set_filesystem_size(self, name: str, size: int) -> None:
        """
        Set the size of a specific filesystem.

        Args:
            name (str): The name of the filesystem.
            size (int): The size to set.
        """
        if name in self.filesystems:
            self.filesystems[name].set_size(size)

class FilesystemLoader:
    """
    Loads filesystem information from tar.gz files into a FilesystemRepository.

    Attributes:
        repository (FilesystemRepository): The repository to store loaded filesystem information.
        load_path (Optional[str]): The path from which filesystems are being loaded.
    """

    def __init__(self, repository: FilesystemRepository):
        self.repository = repository
        self.load_path: Optional[str] = None

    def load_filesystems(self, input_path: str) -> None:
        """
        Load filesystems from a given input path.

        Args:
            input_path (str): Path to a directory containing tar.gz files or a single tar.gz file.

        Raises:
            ValueError: If the input path is neither a directory nor a tar.gz file.
        """
        if input_path.endswith(".tar.gz"):
            glob_target = f"{input_path[:-7]}*.tar.gz"
            self.load_path = os.path.dirname(input_path)
        elif os.path.isdir(input_path):
            glob_target = f"{input_path}/*.tar.gz"
            self.load_path = input_path
        else:
            raise ValueError(f"Input path must be a directory or a .tar.gz file. {input_path} is neither")

        for file in glob.glob(glob_target):
            self._process_tar_file(file)

    def _process_tar_file(self, file_path: str) -> None:
        """
        Process a single tar.gz file and extract filesystem information.

        Args:
            file_path (str): Path to the tar.gz file to process.
        """
        fs_name = os.path.basename(file_path)
        self.repository.add_filesystem(fs_name)

        with tarfile.open(file_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name == ".":
                    continue
                if member.isfile():
                    self.repository.add_path_to_filesystem(fs_name, member.name)
                    self._extract_references(fs_name, tar, member)
                elif member.issym():
                    # Add path of symlink to filesystem
                    # Add reference to target of symlink
                    self.repository.add_path_to_filesystem(fs_name, member.name)

                    relative_linkname = self._resolve_symlink(member.name, member.linkname)
                    #assert(relative_linkname.startswith("./")), f"Resolved symlink path {relative_linkname} does not start with './'"
                    self.repository.add_reference_to_filesystem(fs_name, relative_linkname)

                if member.isdir():
                    self.repository.add_path_to_filesystem(fs_name, member.name)

            self.repository.set_filesystem_size(fs_name, sum(member.size for member in tar.getmembers()))

    def _extract_references(self, fs_name: str, tar: tarfile.TarFile, member: tarfile.TarInfo) -> None:
        """
        Extract references from a file in the tar archive.

        Args:
            fs_name (str): Name of the filesystem.
            tar (tarfile.TarFile): The tar archive being processed.
            member (tarfile.TarInfo): The specific file in the tar archive to process.
        """
        path_regex = re.compile(rb'/[^/\0\n<>"\'! :\?]+(?:/[^/\0\n<>()%"\'! ;:\?]+)+')
        file_content = tar.extractfile(member).read()

        for match in re.findall(path_regex, file_content):
            try:
                decoded_path = match.decode('utf-8')
                if self._is_valid_reference(decoded_path):
                    self.repository.add_reference_to_filesystem(fs_name, decoded_path)
            except UnicodeDecodeError:
                pass


    @staticmethod
    def _resolve_symlink(symlink_path: str, linkname: str) -> str:
        # Get the directory containing the symlink
        symlink_dir = os.path.dirname(symlink_path)

        # Join the symlink's directory with the linkname
        full_path = os.path.join(symlink_dir, linkname)

        # Normalize the path to resolve any '..' or '.'
        normalized_path = os.path.normpath(full_path)

        # Ensure the path starts with './'
        if not normalized_path.startswith('./'):
            normalized_path = './' + normalized_path.lstrip('/')

        return normalized_path

    @staticmethod
    def _is_valid_reference(path: str) -> bool:
        """
        Check if a reference path is valid.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is a valid reference, False otherwise.
        """
        invalid_chars = set(" \t\n^$%*")
        return not (any(char in path for char in invalid_chars) or path.endswith(".c"))
