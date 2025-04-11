#!/usr/bin/env python3

import os
import logging
from pathlib import Path
from penguin import getColoredLogger

logger = getColoredLogger("penguin.busybox_generator")

class BusyboxCommandGenerator:
    """
    A class that implements the same interface as LocalGuestFS but instead of
    making changes to the underlying filesystem, it records a set of busybox commands
    that would achieve the same result.
    """
    
    def __init__(self, base_path):
        """
        Initialize with the base path that commands should be relative to.
        
        Args:
            base_path: The base directory path for all operations
        """
        self.base_path = base_path
        self.commands = []
        # Track files/dirs/symlinks that exist or would be created for state management
        self.tracked_files = {}  # path -> {'type': 'file|dir|symlink', 'target': str (for symlinks)}
        self.command_count = 0

    def _add_command(self, command):
        """Add a command to the list with a unique number"""
        self.command_count += 1
        self.commands.append(f"# Command {self.command_count}\n{command}")

    def adjust_path(self, fname):
        """
        Adjust the path to be relative to the base path.
        
        Args:
            fname: The filename or path to adjust
        
        Returns:
            The adjusted path as a string
        """
        fn = Path(fname)
        if fn.is_absolute():
            # Make path relative to base path
            adjusted = os.path.join(self.base_path, "." + str(fn))
        else:
            adjusted = os.path.join(self.base_path, str(fn))
        return adjusted

    def ensure_containing_folders_exists(self, path):
        """
        Generate commands to ensure that all containing folders of a path exist.
        
        Args:
            path: The path whose containing folders should exist
        """
        p = Path(path)
        
        # Start from the root and create each directory in the path
        current_path = ""
        for part in p.parts:
            if not part or part == '/' or part == '.':
                continue
                
            if current_path:
                current_path = os.path.join(current_path, part)
            else:
                current_path = part
                
            if current_path not in self.tracked_files:
                # Only generate mkdir if we haven't already tracked this directory
                self._add_command(f"mkdir -p {self.adjust_path(current_path)}")
                self.tracked_files[current_path] = {'type': 'dir'}

    def write(self, path, content):
        """
        Generate commands to write content to a file.
        
        Args:
            path: The path of the file to write
            content: The content to write (string or bytes)
        """
        self.ensure_containing_folders_exists(os.path.dirname(path))
        
        adjusted_path = self.adjust_path(path)
        
        if isinstance(content, str):
            # Escape single quotes in the content
            escaped_content = content.replace("'", "'\\''")
            self._add_command(f"cat > {adjusted_path} << 'EOF'\n{escaped_content}\nEOF")
        else:
            # For binary content, we would need to use base64
            import base64
            encoded = base64.b64encode(content).decode('ascii')
            self._add_command(f"echo '{encoded}' | base64 -d > {adjusted_path}")
        
        self.tracked_files[path] = {'type': 'file'}

    def exists(self, fname):
        """
        Check if a path would exist after running the generated commands.
        
        Args:
            fname: The path to check
        
        Returns:
            True if the path would exist, False otherwise
        """
        return fname in self.tracked_files

    def is_file(self, d):
        """
        Check if a path would be a file after running the generated commands.
        
        Args:
            d: The path to check
        
        Returns:
            True if the path would be a file, False otherwise
        """
        return d in self.tracked_files and self.tracked_files[d].get('type') == 'file'

    def is_dir(self, d):
        """
        Check if a path would be a directory after running the generated commands.
        
        Args:
            d: The path to check
        
        Returns:
            True if the path would be a directory, False otherwise
        """
        return d in self.tracked_files and self.tracked_files[d].get('type') == 'dir'

    def is_symlink(self, d):
        """
        Check if a path would be a symlink after running the generated commands.
        
        Args:
            d: The path to check
        
        Returns:
            True if the path would be a symlink, False otherwise
        """
        return d in self.tracked_files and self.tracked_files[d].get('type') == 'symlink'

    def resolve_symlink(self, d):
        """
        Resolve a symlink to its target.
        
        Args:
            d: The path to resolve
            
        Returns:
            The resolved path
        """
        base = ""
        for part in d.split("/"):
            if not part:
                continue
            if base:
                current = f"{base}/{part}"
            else:
                current = part
                
            if self.is_symlink(current):
                target = self.readlink(current)
                logger.debug(f"Found (and resolved) symlink {current}->{target}")
                
                if os.path.isabs(target):
                    # If the target is absolute, replace the current path
                    new_d = target + d[len(current):]
                else:
                    # If the target is relative, replace the last component
                    new_d = os.path.normpath(os.path.join(os.path.dirname(current), target)) + d[len(current):]
                
                return self.resolve_symlink(new_d)
                
            base = current
        
        return d

    def mkdir_p(self, d):
        """
        Generate a command to create a directory and its parents.
        
        Args:
            d: The directory path to create
        """
        adjusted_path = self.adjust_path(d)
        self._add_command(f"mkdir -p {adjusted_path}")
        self.tracked_files[d] = {'type': 'dir'}

    def readlink(self, path):
        """
        Get the target of a symlink.
        
        Args:
            path: The symlink path
        
        Returns:
            The target of the symlink
        """
        if path in self.tracked_files and self.tracked_files[path].get('type') == 'symlink':
            return self.tracked_files[path].get('target', '')
        return ""

    def ln_s(self, target, path):
        """
        Generate a command to create a symbolic link.
        
        Args:
            target: The target of the symlink
            path: The path of the symlink to create
        """
        self.ensure_containing_folders_exists(os.path.dirname(path))
        adjusted_path = self.adjust_path(path)
        self._add_command(f"ln -sf {target} {adjusted_path}")
        self.tracked_files[path] = {'type': 'symlink', 'target': target}

    def chmod(self, mode, fpath):
        """
        Generate a command to change the mode of a file.
        
        Args:
            mode: The mode to set (octal)
            fpath: The path to change mode for
        """
        if self.is_symlink(fpath):
            # For symlinks, change the target's permissions
            target = self.readlink(fpath)
            if os.path.isabs(target):
                self.chmod(mode, target)
            else:
                # Convert relative target to absolute
                abs_target = os.path.normpath(os.path.join(os.path.dirname(fpath), target))
                self.chmod(mode, abs_target)
        else:
            adjusted_path = self.adjust_path(fpath)
            self._add_command(f"chmod {oct(mode)[2:]} {adjusted_path}")

    def _mknod(self, t, mode, major, minor, file_path):
        """
        Generate a command to create a device node.
        
        Args:
            t: The type of device ('c' or 'b')
            mode: The mode to set
            major: The major device number
            minor: The minor device number
            file_path: The path to create
        """
        self.ensure_containing_folders_exists(os.path.dirname(file_path))
        adjusted_path = self.adjust_path(file_path)
        self._add_command(f"mknod -m {oct(mode)[2:]} {adjusted_path} {t} {major} {minor}")
        self.tracked_files[file_path] = {'type': 'device'}

    def mknod_b(self, mode, major, minor, file_path):
        """
        Generate a command to create a block device node.
        
        Args:
            mode: The mode to set
            major: The major device number
            minor: The minor device number
            file_path: The path to create
        """
        self._mknod("b", mode, major, minor, file_path)

    def mknod_c(self, mode, major, minor, file_path):
        """
        Generate a command to create a character device node.
        
        Args:
            mode: The mode to set
            major: The major device number
            minor: The minor device number
            file_path: The path to create
        """
        self._mknod("c", mode, major, minor, file_path)

    def mv(self, fr, to):
        """
        Generate a command to move a file or directory.
        
        Args:
            fr: The source path
            to: The destination path
        """
        self.ensure_containing_folders_exists(os.path.dirname(to))
        from_ = self.adjust_path(fr)
        to_ = self.adjust_path(to)
        self._add_command(f"mv {from_} {to_}")
        
        # Update tracking info
        if fr in self.tracked_files:
            file_info = self.tracked_files.pop(fr)
            self.tracked_files[to] = file_info

    def rm(self, path):
        """
        Generate a command to remove a file or empty directory.
        
        Args:
            path: The path to remove
        """
        adjusted_path = self.adjust_path(path)
        self._add_command(f"rm {adjusted_path}")
        
        if path in self.tracked_files:
            del self.tracked_files[path]

    def rm_rf(self, path):
        """
        Generate a command to remove a file or directory recursively.
        
        Args:
            path: The path to remove
        """
        adjusted_path = self.adjust_path(path)
        self._add_command(f"rm -rf {adjusted_path}")
        
        # Remove this path and any paths that start with this path/ from tracked_files
        path_prefix = path
        if not path_prefix.endswith('/'):
            path_prefix += '/'
            
        keys_to_delete = [key for key in self.tracked_files if key == path or key.startswith(path_prefix)]
        for key in keys_to_delete:
            del self.tracked_files[key]

    def get_commands(self):
        """
        Get all the commands generated so far.
        
        Returns:
            A string containing all the generated commands
        """
        return "\n\n".join(self.commands)

    def save_commands(self, output_file):
        """
        Save the generated commands to a file.
        
        Args:
            output_file: The path of the file to save to
        """
        with open(output_file, 'w') as f:
            f.write("#!/bin/sh\n\n")
            f.write("# Busybox commands to replicate filesystem changes\n\n")
            f.write(self.get_commands())
        os.chmod(output_file, 0o755)  # Make the script executable