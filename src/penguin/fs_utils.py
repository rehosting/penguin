#!/usr/bin/env python3

import os
from pathlib import Path
from .gen_image import LocalGuestFS
from .busybox_generator import BusyboxCommandGenerator

def get_fs_handler(base_path, mode="direct", output_script=None):
    """
    Factory function to get a filesystem handler based on the requested mode.
    
    Args:
        base_path: The base directory path for all operations
        mode: The mode of operation - "direct" for direct filesystem changes,
              "busybox" for generating busybox commands
        output_script: Path to save the generated script (only used in busybox mode)
        
    Returns:
        A filesystem handler (LocalGuestFS or BusyboxCommandGenerator)
    """
    if mode == "direct":
        return LocalGuestFS(base_path)
    elif mode == "busybox":
        handler = BusyboxCommandGenerator(base_path)
        if output_script:
            # Register an exit handler to save the commands when done
            import atexit
            atexit.register(handler.save_commands, output_script)
        return handler
    else:
        raise ValueError(f"Unknown filesystem handler mode: {mode}")

def fs_make_config_changes(config, project_dir, mode="direct", fs_base=None, output_script=None):
    """
    Apply configuration changes to a filesystem or generate commands to do so.
    
    Args:
        config: The configuration dictionary
        project_dir: The project directory path
        mode: The mode of operation - "direct" for direct filesystem changes,
              "busybox" for generating busybox commands
        fs_base: The base directory path for direct filesystem changes (only for direct mode)
        output_script: Path to save the generated script (only for busybox mode)
    
    Returns:
        None if mode is "direct", or the generated commands if mode is "busybox"
    """
    from .gen_image import fs_make_config_changes as direct_fs_make_config_changes
    
    if mode == "direct":
        if not fs_base:
            raise ValueError("fs_base must be provided for direct mode")
        return direct_fs_make_config_changes(fs_base, config, project_dir)
    
    elif mode == "busybox":
        # We need a dummy base path just for tracking
        dummy_base = fs_base or "/tmp/dummy_base"
        g = BusyboxCommandGenerator(dummy_base)
        
        # Import the function that uses the fs handler but don't call it directly
        from .gen_image import _modify_guestfs
        
        # Get the files from the config
        files = config.get("static_files", {})
        
        # Process the files in the same order as the original function
        # First directories
        mkdirs = {k: v for k, v in files.items() if v["type"] == "dir"}
        sorted_mkdirs = sorted(mkdirs.items(), key=lambda x: len(x[0]))
        for file_path, file in sorted_mkdirs:
            _modify_guestfs(g, file_path, file, project_dir)
        
        # Next, move operations
        move_from_files = {k: v for k, v in files.items() if v["type"] == "move_from"}
        sorted_move_from_files = sorted(move_from_files.items(), key=lambda x: len(files[x[0]]))
        for file_path, file in sorted_move_from_files:
            _modify_guestfs(g, file_path, file, project_dir)
        
        # Now regular files
        sorted_files = {k: v for k, v in files.items() if v["type"] not in ["move_from", "dir", "symlink", "shim"]}
        sorted_files = sorted(sorted_files.items(), key=lambda x: len(x[0]))
        for file_path, file in sorted_files:
            resolved_file_path = g.resolve_symlink(file_path)
            resolved_file_path = os.path.dirname(resolved_file_path) + "/" + os.path.basename(file_path)
            _modify_guestfs(g, resolved_file_path, file, project_dir)
        
        # Finally symlinks
        symlink_files = {k: v for k, v in files.items() if v["type"] in ["symlink", "shim"]}
        sorted_symlink_files = sorted(symlink_files.items(), key=lambda x: len(files[x[0]].get("target", "")))
        for file_path, file in sorted_symlink_files:
            _modify_guestfs(g, file_path, file, project_dir)
        
        if output_script:
            g.save_commands(output_script)
        
        return g.get_commands()
    
    else:
        raise ValueError(f"Unknown filesystem handler mode: {mode}")