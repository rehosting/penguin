from penguin import Plugin, plugins
from penguin.defaults import static_dir
from os import makedirs, chmod
from os.path import join
import shutil
import os
from typing import Iterator, List, Dict, Tuple, Set, Literal, Optional
from pathlib import Path
from pydantic import BaseModel, Field, RootModel, ConfigDict, ValidationError
from penguin.penguin_config.structure import StaticFiles, StaticFileAction
import tempfile
import keystone
import tarfile

GEN_LIVE_IMAGE_ACTION_MAGIC = 0xf113c0df
BATCH_PATCH_FILES_ACTION_MAGIC = 0xf113c0e0 # Hypercall to patch all files at once


class LiveImage(Plugin):
    """
    Generates a guest filesystem live by creating a setup script that runs on boot.
    This version uses a tarball for file deployment and a single, batched hypercall for patching.
    """

    def __init__(self) -> None:
        super().__init__()
        self.panda.hypercall(GEN_LIVE_IMAGE_ACTION_MAGIC)(self._on_live_image_hypercall)
        self.panda.hypercall(BATCH_PATCH_FILES_ACTION_MAGIC)(self._on_batch_patch_hypercall)

        self.config = self.get_arg("conf")
        self.proj_dir = Path(self.get_arg("proj_dir")).resolve()
        self.shared_dir = Path(self.get_arg("shared_dir")).resolve()
        self.host_files_dir = self.shared_dir / "host_files"
        self.guest_shared_dir = "/igloo/shared/host_files"
        self.host_files_dir.mkdir(parents=True, exist_ok=True)

        self.script_generated = False
        self.patch_queue = []
        self.ensure_init = lambda *args: None
        self._setup_arch_utils()
        plugins.igloodriver.ensure_init()

    def _setup_arch_utils(self):
        """Copies architecture-specific utilities to the shared directory."""
        core_config = self.config.get("core", {})
        arch = core_config.get("arch", "intel64")
        
        arch_map = {"intel64": "x86_64", "powerpc64el": "powerpc64"}
        self.arch = arch
        self.arch_dir_name = arch_map.get(arch, arch)
        
        utils_base_path = Path(static_dir) / self.arch_dir_name
        self._copy_file_to_shared(utils_base_path / "send_hypercall_raw")
        
        igloo_kernel_version = "6.13"
        kernel_module_path = Path(static_dir) / "kernels" / igloo_kernel_version / f"igloo.ko.{self.arch_dir_name}"
        self._copy_file_to_shared(kernel_module_path, "igloo.ko")

    def _copy_file_to_shared(self, host_path: Path, dest_name: str = None) -> Optional[str]:
        """Copies a single file to the shared directory for the guest."""
        if not host_path.is_absolute():
            host_path = self.proj_dir / host_path

        if not host_path.exists():
            self.logger.error(f"Host file not found: {host_path}")
            return None

        final_dest_name = dest_name or host_path.name
        shared_dest_path = self.host_files_dir / final_dest_name

        try:
            shutil.copy(host_path, shared_dest_path)
            shared_dest_path.chmod(0o755)
            return f"{self.guest_shared_dir}/{final_dest_name}"
        except Exception as e:
            self.logger.error(f"Failed to copy {host_path} to {shared_dest_path}: {e}")
            return None

    def _plan_actions(self) -> Iterator[Tuple[str, Dict]]:
        """
        Sorts 'static_files' actions into a logical execution order without validation.
        """
        actions = self.config.get("static_files", {}).items()

        action_order = ["delete", "move", "shim", "dir", "host_file", "inline_file", "binary_patch", "dev", "symlink"]
        
        partitions = {key: [] for key in action_order}
        for path, action in actions:
            action_type = action.get("type")
            if action_type in partitions:
                partitions[action_type].append((path, action))

        for action_type in action_order:
            reverse_sort = action_type == "delete"
            for path, action in sorted(partitions[action_type], key=lambda item: len(item[0]), reverse=reverse_sort):
                yield path, action

    def _generate_setup_script(self) -> str:
        """Builds an efficient setup script using a tarball and a single, batched patch hypercall."""
        post_tar_commands = []
        paths_to_delete = []
        self.patch_queue = [] # Reset for this run
        
        with tempfile.TemporaryDirectory() as staging_dir_str:
            staging_dir = Path(staging_dir_str)
            
            # --- Phase 1: Plan and Stage for Tarball ---
            for file_path, action in self._plan_actions():
                action_type = action.get("type")
                if file_path.startswith("/dev/") or file_path == "/dev" or file_path == "/igloo/utils/busybox":
                    pass # These actions are handled post-tar

                if action_type in ["dir", "host_file", "inline_file"]:
                    staged_path = staging_dir / file_path.lstrip('/')
                    staged_path.parent.mkdir(parents=True, exist_ok=True)
                    if action_type == "dir":
                        staged_path.mkdir(exist_ok=True)
                        staged_path.chmod(action['mode'])
                    elif action_type == "inline_file":
                        # Write as text or bytes depending on type
                        if isinstance(action['contents'], bytes):
                            staged_path.write_bytes(action['contents'])
                        else:
                            staged_path.write_text(action['contents'])
                        staged_path.chmod(action['mode'])
                    elif action_type == "host_file":
                        host_path_str = action['host_path']
                        dest_path_str = file_path
                        # Path resolution: relative to proj_dir if not absolute
                        if not os.path.isabs(host_path_str):
                            source_path_pattern = self.proj_dir / host_path_str
                        else:
                            source_path_pattern = Path(host_path_str)
                        dest_path = Path(dest_path_str)
                        # If the destination contains a wildcard, treat it as a directory and copy each source file into it
                        if '*' in dest_path.name or '?' in dest_path.name:
                            dest_dir = dest_path.parent
                            if dest_dir.is_absolute():
                                dest_dir_path = staging_dir / dest_dir.relative_to('/')
                            else:
                                dest_dir_path = staging_dir / dest_dir
                            dest_dir_path.mkdir(parents=True, exist_ok=True)
                            self.logger.debug(f"Globbing for host_file: {source_path_pattern.parent}/{source_path_pattern.name}")
                            glob_matches = list(source_path_pattern.parent.glob(source_path_pattern.name))
                            self.logger.debug(f"Found {len(glob_matches)} files for host_file source glob: {source_path_pattern}")
                            if not glob_matches:
                                self.logger.warning(f"No files matched for host_file source glob: {source_path_pattern}")
                            for host_src in glob_matches:
                                if host_src.is_file():
                                    staged_file_path = dest_dir_path / host_src.name
                                    shutil.copy(host_src, staged_file_path)
                                    if 'mode' in action:
                                        staged_file_path.chmod(action['mode'])
                        # Only expand globs in the source, never in the destination
                        elif '*' in source_path_pattern.name or '?' in source_path_pattern.name:
                            self.logger.debug(f"Globbing for host_file: {source_path_pattern.parent}/{source_path_pattern.name}")
                            glob_matches = list(source_path_pattern.parent.glob(source_path_pattern.name))
                            self.logger.debug(f"Found {len(glob_matches)} files for host_file source glob: {source_path_pattern}")
                            if not glob_matches:
                                self.logger.warning(f"No files matched for host_file source glob: {source_path_pattern}")
                            for host_src in glob_matches:
                                if host_src.is_file():
                                    staged_file_path = staged_path / host_src.name
                                    staged_file_path.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.copy(host_src, staged_file_path)
                                    if 'mode' in action:
                                        staged_file_path.chmod(action['mode'])
                        else: # Handle single file
                            host_src = source_path_pattern
                            if not host_src.exists():
                                self.logger.error(f"Host file not found: {host_src}")
                                continue
                            staged_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy(host_src, staged_path)
                            staged_path.chmod(action['mode'])

                # Queue or generate commands for post-tar execution
                elif action_type == "binary_patch":
                    self.patch_queue.append((file_path, action))
                elif action_type == "delete":
                    paths_to_delete.append(file_path)
                elif action_type == "symlink":
                    post_tar_commands.append(f"ln -sf '{action['target']}' '{file_path}'")
                elif action_type == "shim":
                    orig_path = f"/igloo/utils/{Path(file_path).name}.orig"
                    post_tar_commands.append(f"mv '{file_path}' '{orig_path}'")
                    post_tar_commands.append(f"ln -sf '{action['target']}' '{file_path}'")
                elif action_type == "move":
                    post_tar_commands.append(f"mv '{action['from']}' '{file_path}'")
                    if action.get('mode') is not None:
                        post_tar_commands.append(f"chmod {oct(action['mode'])[2:]} '{file_path}'")
                elif action_type == "dev":
                    dev_char = 'c' if action['devtype'] == 'char' else 'b'
                    post_tar_commands.append(f"mknod '{file_path}' {dev_char} {action['major']} {action['minor']}")
                    post_tar_commands.append(f"chmod {oct(action['mode'])[2:]} '{file_path}'")

            # --- Phase 2: Ensure all staged files are readable before creating the tarball ---
            for root, dirs, files in os.walk(staging_dir):
                for name in files:
                    fpath = os.path.join(root, name)
                    try:
                        st = os.stat(fpath)
                        if not (st.st_mode & 0o400):
                            os.chmod(fpath, st.st_mode | 0o400)
                    except Exception as e:
                        self.logger.warning(f"Could not set read permission on {fpath}: {e}")
                for name in dirs:
                    dpath = os.path.join(root, name)
                    try:
                        st = os.stat(dpath)
                        if not (st.st_mode & 0o400):
                            os.chmod(dpath, st.st_mode | 0o400)
                    except Exception as e:
                        self.logger.warning(f"Could not set read permission on {dpath}: {e}")

            # --- Phase 2: Create and copy the tarball ---
            tarball_host_path = self.host_files_dir / "filesystem.tar.gz"
            self.logger.info(f"Creating filesystem tarball at {tarball_host_path}...")
            with tarfile.open(tarball_host_path, "w") as tar:
                tar.add(staging_dir, arcname='.')
            tarball_guest_path = f"{self.guest_shared_dir}/filesystem.tar.gz"

        # --- Phase 3: Assemble the final guest script ---
        script_lines = [
            "#!/igloo/utils/busybox sh",
            "set -e",
            "export PATH=/igloo/utils:$PATH",
            "export LD_PRELOAD_OLD=$LD_PRELOAD"
            "export LD_PRELOAD=",
            "exec > /igloo/shared/host_files/live_image_guest.log 2>&1",
            "for util in chmod cp mkdir rm ln mknod tar mv stat; do /igloo/utils/busybox ln -sf /igloo/utils/busybox /igloo/utils/$util; done",
        ]
        
        if paths_to_delete:
            script_lines.append(f"rm -rf {' '.join([f'{p}' for p in paths_to_delete])}")
            
        script_lines.append(f"tar -xf {tarball_guest_path} -C /")
        
        # --- Phase 4: Batch-process binary patches ---
        if self.patch_queue:
            patch_staging_cmds = []
            patch_return_cmds = []
            
            for i, (file_path, _) in enumerate(self.patch_queue):
                shared_file_name = f"patch_{i}"
                shared_file_guest_path = f"{self.guest_shared_dir}/{shared_file_name}"
                patch_staging_cmds.append(f"ORIG_PERMS_{i}=$(stat -c %a '{file_path}')")
                patch_staging_cmds.append(f"mv '{file_path}' '{shared_file_guest_path}'")
                patch_return_cmds.append(f"mv '{shared_file_guest_path}' '{file_path}'")
                patch_return_cmds.append(f"chmod \"$ORIG_PERMS_{i}\" '{file_path}'")

            script_lines.append("\n# Staging all files for patching")
            script_lines.extend(patch_staging_cmds)
            
            script_lines.append("\n# Triggering single batched patch hypercall")
            script_lines.append(f"/igloo/shared/host_files/send_hypercall_raw {BATCH_PATCH_FILES_ACTION_MAGIC:#x}")

            script_lines.append("\n# Moving all patched files back")
            script_lines.extend(patch_return_cmds)

        script_lines.extend(post_tar_commands)
        script_lines.extend("export LD_PRELOAD=$LD_PRELOAD_OLD")
        return "\n".join(script_lines) + "\n"

    def _apply_patch_to_file_content(self, original_content: bytes, action: Dict) -> Optional[bytes]:
        """Applies a patch to a byte string and returns the new bytes."""
        if bool(action.get('hex_bytes')) == bool(action.get('asm')):
            self.logger.error(f"Binary patch must have exactly one of 'hex_bytes' or 'asm'.")
            return None

        if action.get('asm'):
            patch_bytes = self._gen_asm_patch_bytes(action['asm'], action.get('mode'))
            if patch_bytes is None: return None
        else:
            patch_bytes = bytes.fromhex(action['hex_bytes'].replace(" ", ""))

        file_offset = action['file_offset']
        return (
            original_content[:file_offset] +
            patch_bytes +
            original_content[file_offset + len(patch_bytes):]
        )

    def _gen_asm_patch_bytes(self, asm_code: str, user_mode: Optional[str]) -> Optional[bytes]:
        """Assembles assembly code into bytes using Keystone."""
        if keystone is None:
            self.logger.error("Cannot assemble code because keystone-engine is not installed.")
            return None
        
        arch_map = {"armel": keystone.KS_ARCH_ARM, "aarch64": keystone.KS_ARCH_ARM64, "mipsel": keystone.KS_ARCH_MIPS, "mipseb": keystone.KS_ARCH_MIPS, "intel64": keystone.KS_ARCH_X86}
        mode_map = {"aarch64": keystone.KS_MODE_LITTLE_ENDIAN, "mipsel": keystone.KS_MODE_MIPS32 | keystone.KS_MODE_LITTLE_ENDIAN, "mipseb": keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN, "intel64": keystone.KS_MODE_64}

        ks_arch = arch_map.get(self.arch)
        if self.arch == "armel":
            arm_mode = user_mode or "arm"
            ks_mode = keystone.KS_MODE_THUMB if arm_mode == "thumb" else keystone.KS_MODE_ARM
            ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
        else:
            ks_mode = mode_map.get(self.arch)

        if ks_arch is None or ks_mode is None:
            self.logger.error(f"Unsupported architecture for assembly: {self.arch}")
            return None
            
        try:
            ks = keystone.Ks(ks_arch, ks_mode)
            encoding, _ = ks.asm(asm_code)
            return bytes(encoding)
        except Exception as e:
            self.logger.error(f"Keystone assembly failed for arch {self.arch}: {e}")
            return None

    def _on_batch_patch_hypercall(self, cpu):
        """Handles a single hypercall to patch all files in the queue."""
        self.logger.info(f"Batch patching {len(self.patch_queue)} files...")
        
        for i, (guest_path, action) in enumerate(self.patch_queue):
            shared_file_name = f"patch_{i}"
            host_side_path = self.host_files_dir / shared_file_name
            
            self.logger.debug(f"Patching guest file '{guest_path}' via shared file '{host_side_path}'")

            try:
                original_content = host_side_path.read_bytes()
                patched_content = self._apply_patch_to_file_content(original_content, action)
                
                if patched_content is None:
                    self.logger.error(f"Failed to generate patch for {guest_path}")
                    self.panda.arch.set_retval(cpu, -1, convention="syscall")
                    return # Abort on first failure

                host_side_path.write_bytes(patched_content)

            except Exception as e:
                self.logger.error(f"Error during file patch of {host_side_path}: {e}", exc_info=True)
                self.panda.arch.set_retval(cpu, -1, convention="syscall")
                return # Abort on first failure
        
        self.logger.info("Batch patching completed successfully.")
        self.panda.arch.set_retval(cpu, 0, convention="syscall")

    def _on_live_image_hypercall(self, cpu):
        """The main entry point triggered by the guest's hypercall."""
        if self.script_generated:
            self.panda.arch.set_retval(cpu, 0, convention="syscall")
            return

        self.logger.info("Live image hypercall received. Generating setup script...")
        
        try:
            script_content = self._generate_setup_script()
            script_path = self.host_files_dir / "gen_live_image.sh"
            script_path.write_text(script_content)
            script_path.chmod(0o755)
            
            self.logger.info(f"Successfully generated setup script at {script_path}")
            self.script_generated = True
            self.panda.arch.set_retval(cpu, 0, convention="syscall")
        
        except Exception as e:
            self.logger.error(f"Failed to generate live image script: {e}", exc_info=True)
            # Set error retval to max unsigned for register size
            max_unsigned = (1 << self.panda.bits) - 1
            self.panda.arch.set_retval(cpu, max_unsigned, convention="syscall")