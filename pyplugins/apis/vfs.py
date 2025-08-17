"""
VFS Plugin for penguin framework

This plugin provides Virtual File System manipulation capabilities,
including the ability to mask file operations at the kernel level.
"""

from penguin import Plugin
from typing import Generator, Any, Optional
from hyper.portal import PortalCmd


class VFS(Plugin):
    """
    VFS Plugin for Virtual File System operations
    
    Provides methods for manipulating the kernel VFS layer, including
    masking file operations and intercepting file system calls.
    """

    def __init__(self) -> None:
        super().__init__()
        self.masked_files = {}  # Track masked files locally

    def mask_file(self, path: str) -> Generator[Any, Any, Any]:
        """
        ### Mask a file's operations at the VFS layer

        This replaces the file's operations structure with a copy that can be
        modified to intercept file system operations.

        **Args:**
        - `path` (`str`): Full path to the file to mask

        **Returns:**
        - `int`: Entry handle for the masked file, or None if masking failed
        """
        if not path or not isinstance(path, str):
            self.logger.error("Path must be a non-empty string")
            return None

        # Send path as null-terminated bytes
        path_bytes = path.encode() + b"\x00"
        
        self.logger.debug(f"Masking file: {path}")
        
        result = yield PortalCmd("vfs_mask_file", size=len(path_bytes), data=path_bytes)
        
        if result:
            self.masked_files[path] = result
            self.logger.info(f"Successfully masked file: {path} (handle: {result:#x})")
            return result
        else:
            self.logger.error(f"Failed to mask file: {path}")
            return None

    def unmask_file(self, path: str) -> Generator[Any, Any, Any]:
        """
        ### Unmask a previously masked file

        Restores the original file operations for the specified file.

        **Args:**
        - `path` (`str`): Full path to the file to unmask

        **Returns:**
        - `bool`: True if successfully unmasked, False otherwise
        """
        # Note: This would require additional kernel support to restore original fops
        # For now, this is a placeholder for future implementation
        if path in self.masked_files:
            del self.masked_files[path]
            self.logger.info(f"Unmasked file: {path}")
            return True
        else:
            self.logger.warning(f"File not found in masked files: {path}")
            return False

    def list_masked_files(self) -> dict:
        """
        ### Get a list of currently masked files

        **Returns:**
        - `dict`: Dictionary mapping file paths to their mask handles
        """
        return self.masked_files.copy()

    def is_file_masked(self, path: str) -> bool:
        """
        ### Check if a file is currently masked

        **Args:**
        - `path` (`str`): Full path to check

        **Returns:**
        - `bool`: True if the file is masked, False otherwise
        """
        return path in self.masked_files