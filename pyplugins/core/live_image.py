from penguin import Plugin, plugins
import shutil
import os
from typing import Iterator, Dict, Tuple, Optional, Callable
from pathlib import Path
import tempfile
import keystone
import tarfile
import shlex

GEN_LIVE_IMAGE_ACTION_FINISHED = 0xf113c1df
# Hypercall to patch all files at once
BATCH_PATCH_FILES_ACTION_MAGIC = 0xf113c0e0
MAGIC_GET = 0xf113c0e1
MAGIC_PUT = 0xf113c0e2
MAGIC_GET_PERM = 0xf113c0e3
MAGIC_GETSIZE = 0xf113c0e4
REPORT_ERROR = 0xfa14487


class LiveImage(Plugin):
    """
    Generates a guest filesystem live by creating a setup script that runs on boot.
    This version uses a tarball for file deployment and a single, batched hypercall for patching.
    """

    def __init__(self) -> None:
        self._staging_dir_obj = tempfile.TemporaryDirectory()
        self.staged_dir = self._staging_dir_obj.name
        self.proj_dir = Path(self.get_arg("proj_dir")).resolve()
        self.script_generated = False
        self.fs_generated = False
        self.patch_queue = []
        self.config = self.get_arg("conf")
        core_config = self.config.get("core", {})
        self.arch = core_config.get("arch", "intel64")
        self.ensure_init = lambda *args: None
        self._init_callbacks = []

    def fs_init(self, func: Optional[Callable] = None):
        """
        Decorator for registering fs init callbacks.
        Can be used as @plugins.live_image.fs_init
        """
        def decorator(f):
            self._init_callbacks = self._init_callbacks + [f]
            return f
        if func is not None:
            return decorator(func)
        return decorator

    def _plan_actions(self) -> Iterator[Tuple[str, Dict]]:
        """
        Sorts 'static_files' actions into a logical execution order without validation.
        """
        actions = self.get_arg("conf").get("static_files", {}).items()

        action_order = ["delete", "move", "shim", "dir", "host_file",
                        "inline_file", "binary_patch", "dev", "symlink"]

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
        """Builds an efficient setup script using hyp_file_op for file transfer, not shared_dir."""
        post_tar_commands = []
        paths_to_delete = []
        self.patch_queue = []  # Reset for this run
        move_sources_to_remove = []
        staging_dir = Path(self.staged_dir)
        from collections import defaultdict
        mode_groups = defaultdict(list)  # mode(str without leading 0) -> [paths]
        needed_parent_dirs = set()
        path_modes = {}  # track mode per path for later glob compression

        def record_mode(path: str, mode_val: int):
            if mode_val is None:
                return
            mode_str = oct(mode_val)[2:]
            mode_groups[mode_str].append(path)
            path_modes[path] = mode_str

        def record_parent_dirs(p: str):
            # Record the immediate parent; deeper parents will be recorded as we see their children.
            parent = str(Path(p).parent)
            if parent != '/' and parent != '.':
                needed_parent_dirs.add(parent)

        shim_orig_names = set()
        shim_orig_counts = {}
        libnvram = staging_dir / "igloo" / "libnvram"
        libnvram.mkdir(parents=True, exist_ok=True)
        # --- Phase 1: Plan and Stage for Tarball ---
        for file_path, action in self._plan_actions():
            action_type = action.get("type")
            if file_path.startswith("/dev/") or file_path == "/dev":
                pass  # These actions are handled post-tar

            if action_type in ["dir", "host_file", "inline_file"]:
                record_parent_dirs(file_path)
                staged_path = staging_dir / file_path.lstrip('/')
                staged_path.parent.mkdir(parents=True, exist_ok=True)
                if action_type == "dir":
                    staged_path.mkdir(exist_ok=True)
                    if 'mode' in action:
                        record_mode(file_path, action['mode'])
                elif action_type == "inline_file":
                    if isinstance(action['contents'], bytes):
                        staged_path.write_bytes(action['contents'])
                    else:
                        staged_path.write_text(action['contents'])
                    if 'mode' in action:
                        record_mode(file_path, action['mode'])
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
                            dest_dir_path = staging_dir / \
                                dest_dir.relative_to('/')
                        else:
                            dest_dir_path = staging_dir / dest_dir
                        dest_dir_path.mkdir(parents=True, exist_ok=True)
                        self.logger.debug(
                            f"Globbing for host_file: {source_path_pattern.parent}/{source_path_pattern.name}")
                        glob_matches = list(
                            source_path_pattern.parent.glob(source_path_pattern.name))
                        self.logger.debug(
                            f"Found {len(glob_matches)} files for host_file source glob: {source_path_pattern}")
                        if not glob_matches:
                            self.logger.warning(
                                f"No files matched for host_file source glob: {source_path_pattern}")
                        for host_src in glob_matches:
                            if host_src.is_file():
                                staged_file_path = dest_dir_path / host_src.name
                                shutil.copy(host_src, staged_file_path)
                                if 'mode' in action:
                                    record_mode(str(Path(dest_dir) / host_src.name if dest_dir.is_absolute() else (dest_dir / host_src.name)), action['mode'])
                    # Only expand globs in the source, never in the destination
                    elif '*' in source_path_pattern.name or '?' in source_path_pattern.name:
                        self.logger.debug(
                            f"Globbing for host_file: {source_path_pattern.parent}/{source_path_pattern.name}")
                        glob_matches = list(
                            source_path_pattern.parent.glob(source_path_pattern.name))
                        self.logger.debug(
                            f"Found {len(glob_matches)} files for host_file source glob: {source_path_pattern}")
                        if not glob_matches:
                            self.logger.warning(
                                f"No files matched for host_file source glob: {source_path_pattern}")
                        for host_src in glob_matches:
                            if host_src.is_file():
                                staged_file_path = staged_path / host_src.name
                                staged_file_path.parent.mkdir(
                                    parents=True, exist_ok=True)
                                shutil.copy(host_src, staged_file_path)
                                if 'mode' in action:
                                    record_mode(str(Path(file_path) / host_src.name), action['mode'])
                    else:  # Handle single file
                        host_src = source_path_pattern
                        if not host_src.exists():
                            self.logger.error(
                                f"Host file not found: {host_src} (static_files entry: {file_path} -> {action})")
                            raise FileNotFoundError(
                                f"Host file not found: {host_src} (static_files entry: {file_path} -> {action})")
                        staged_path.parent.mkdir(
                            parents=True, exist_ok=True)
                        shutil.copy(host_src, staged_path)
                        if 'mode' in action:
                            record_mode(file_path, action['mode'])

            # Queue or generate commands for post-tar execution
            elif action_type == "binary_patch":
                self.patch_queue.append((file_path, action))
            elif action_type == "delete":
                paths_to_delete.append(file_path)
            elif action_type == "symlink":
                post_tar_commands.append(
                    f"ln -sf {shlex.quote(action['target'])} {shlex.quote(file_path)}")
            elif action_type == "shim":
                # Place .orig in /igloo/shims and ensure unique name
                base_name = Path(file_path).name
                orig_dir = "/igloo/shims"
                orig_base = f"{base_name}.orig"
                orig_path = f"{orig_dir}/{orig_base}"
                if orig_path in shim_orig_names:
                    count = shim_orig_counts.get(orig_path, 1)
                    while f"{orig_dir}/{base_name}_{count}.orig" in shim_orig_names:
                        count += 1
                    orig_path = f"{orig_dir}/{base_name}_{count}.orig"
                    shim_orig_counts[orig_path] = count
                shim_orig_names.add(orig_path)
                post_tar_commands.append(
                    f"mv {shlex.quote(file_path)} {shlex.quote(orig_path)}")
                # Symlink to the new .orig path
                post_tar_commands.append(
                    f"ln -sf {shlex.quote(orig_path)} {shlex.quote(file_path)}")
            elif action_type == "move":
                post_tar_commands.append(
                    f"cp {shlex.quote(action['from'])} {shlex.quote(file_path)}")
                if action.get('mode') is not None:
                    record_mode(file_path, action['mode'])
                move_sources_to_remove.append(action['from'])
            elif action_type == "dev":
                # Ensure parent directory exists in the tarball
                parent_dir = Path(file_path).parent
                if str(parent_dir) != '.':
                    staged_parent_dir = staging_dir / \
                        str(parent_dir).lstrip('/')
                    staged_parent_dir.mkdir(parents=True, exist_ok=True)

                dev_char = 'c' if action['devtype'] == 'char' else 'b'
                paths_to_delete.append(file_path)
                post_tar_commands.append(
                    f"mknod {shlex.quote(file_path)} {dev_char} {action['major']} {action['minor']}")
                if action.get('mode') is not None:
                    record_mode(file_path, action['mode'])

        # /igloo/shims is guaranteed to exist in the base image
        igloo_shims = staging_dir / "igloo" / "shims"
        igloo_shims.mkdir(parents=True, exist_ok=True)

        # --- Phase 2: Ensure all staged files are readable before creating the tarball ---
        for root, dirs, files in os.walk(staging_dir):
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    st = os.stat(fpath)
                    if not (st.st_mode & 0o400):
                        os.chmod(fpath, st.st_mode | 0o400)
                except Exception as e:
                    self.logger.warning(
                        f"Could not set read permission on {fpath}: {e}")
            for name in dirs:
                dpath = os.path.join(root, name)
                try:
                    st = os.stat(dpath)
                    if not (st.st_mode & 0o400):
                        os.chmod(dpath, st.st_mode | 0o400)
                except Exception as e:
                    self.logger.warning(
                        f"Could not set read permission on {dpath}: {e}")

        # --- Phase 2: Create and copy the tarball ---
        tarball_host_path = Path(staging_dir) / "filesystem.tar"
        self.logger.info(
            f"Creating filesystem tarball at {tarball_host_path}...")
        with tarfile.open(tarball_host_path, "w") as tar:
            tar.add(staging_dir, arcname='.')
        self.logger.info(
            f"Filesystem tarball created at {tarball_host_path}")

        # --- Phase 3: Assemble the final guest script ---
        script_lines = [
            "#!/igloo/boot/busybox sh",
            "export PATH=/igloo/boot:$PATH",
            "exec > /igloo/boot/live_image_guest.log 2>&1",
            "for util in chmod echo cp mkdir rm ln mknod tar mv time stat readlink dirname sh; do /igloo/boot/busybox ln -sf /igloo/boot/busybox /igloo/boot/$util; done",
            "",
            "run_or_report() {",
            "  err_line=$1; shift",
            "  hex_line=$(printf '%x' \"$err_line\")",
            "  \"$@\"",
            "  rc=$?",
            "  if [ $rc -ne 0 ]; then",
            "    /igloo/boot/hyp_file_op put /igloo/boot/live_image_guest.log live_image_guest.log",
            f"    /igloo/boot/send_portalcall {REPORT_ERROR:#x} $hex_line",
            "    echo \"ERROR: Command failed: $* (exit $rc) at line $err_line ($hex_line)\" >&2",
            "    exit $rc",
            "  fi",
            "}",
            "",
            "ensure_dir() {",
            "  d=\"$1\"",
            "  if [ -L \"$d\" ]; then",
            "    t=$(readlink \"$d\")",
            "    case \"$t\" in /*) tgt=\"$t\" ;; *) tgt=\"$(dirname \"$d\")/$t\" ;; esac",
            "    mkdir -p \"$tgt\"",
            "  else",
            "    mkdir -p \"$d\" || true",
            "  fi",
            "}",
            ""
        ]

        def add_run_or_report(cmd):
            line_num = len(script_lines) + 1
            script_lines.append(f"run_or_report {line_num} {cmd}")

        if paths_to_delete:
            add_run_or_report(f"rm -rf {' '.join([shlex.quote(p) for p in paths_to_delete])}")
        # Use hyp_file_op to get the tarball and extract
        add_run_or_report("/igloo/boot/hyp_file_op get filesystem.tar /igloo/boot/filesystem.tar")
        # Replace inline symlink logic with ensure_dir calls
        for d in sorted(needed_parent_dirs):
            add_run_or_report(f"ensure_dir {shlex.quote(d)}")
        add_run_or_report("tar x -om -f /igloo/boot/filesystem.tar -C / --no-same-permissions")

        # --- Phase 4: Batch-process binary patches ---
        if self.patch_queue:
            patch_staging_cmds = []
            patch_return_cmds = []

            for i, (file_path, _) in enumerate(self.patch_queue):
                shared_file_name = f"patch_{i}"
                patch_staging_cmds.append(
                    f"/igloo/boot/hyp_file_op put {shlex.quote(file_path)} {shlex.quote(os.path.basename(shared_file_name))}")
            script_lines.append("\n# Staging all files for patching")
            for cmd in patch_staging_cmds:
                add_run_or_report(cmd)

            script_lines.append("\n# Triggering single batched patch hypercall")
            add_run_or_report(f"/igloo/boot/send_portalcall {BATCH_PATCH_FILES_ACTION_MAGIC:#x}")

            for i, (file_path, _) in enumerate(self.patch_queue):
                shared_file_name = f"patch_{i}"
                patch_return_cmds.append(
                    f"/igloo/boot/hyp_file_op get {shlex.quote(shared_file_name)} {shlex.quote(file_path)}")
            script_lines.append("\n# Moving all patched files back")
            for cmd in patch_return_cmds:
                add_run_or_report(cmd)

        for cmd in post_tar_commands:
            add_run_or_report(cmd)
        # Add grouped chmod commands with /igloo/<folder>/* compression
        # Build map folder -> set of modes for its descendant paths
        igloo_folder_modes = defaultdict(set)  # /igloo/<folder> -> {mode_str}
        igloo_folder_paths = defaultdict(list)  # /igloo/<folder> -> [paths]
        for p, m in path_modes.items():
            if p.startswith('/igloo/'):
                parts = p.split('/')
                if len(parts) >= 3:  # / igloo <folder> ...
                    folder_root = '/'.join(parts[:3])  # /igloo/<folder>
                    # Consider only descendants, not the folder root itself for wildcard scope
                    if p != folder_root:
                        igloo_folder_modes[folder_root].add(m)
                        igloo_folder_paths[folder_root].append(p)
        # Determine compressible folders
        compress_globs = []  # (mode_str, glob_pattern)
        compressed_paths = set()
        MIN_COMPRESS_COUNT = 10
        for folder, modeset in igloo_folder_modes.items():
            # Build per-mode lists for this folder
            per_mode_paths = defaultdict(list)
            for p in igloo_folder_paths[folder]:
                per_mode_paths[path_modes[p]].append(p)
            # Case 1: all descendants same mode -> single wildcard
            if len(per_mode_paths) == 1:
                mode_str = next(iter(per_mode_paths.keys()))
                compress_globs.append((mode_str, f"{folder}"))
                compressed_paths.update(per_mode_paths[mode_str])
            else:
                # Case 2: multiple modes; compress any mode with large count
                for mode_str, plist in per_mode_paths.items():
                    if len(plist) >= MIN_COMPRESS_COUNT:
                        compress_globs.append((mode_str, f"{folder}"))
                        compressed_paths.update(plist)
        # Remove compressed paths from mode_groups
        for mode_str, paths in list(mode_groups.items()):
            if paths:
                mode_groups[mode_str] = [p for p in paths if p not in compressed_paths]
        # Emit compressed glob chmods first per mode
        by_mode_globs = defaultdict(list)
        for mode_str, glob_pat in compress_globs:
            by_mode_globs[mode_str].append(glob_pat)
        for mode_str, globs in by_mode_globs.items():
            # combine globs in chunks
            chunk = []
            for g in globs:
                chunk.append(g)
                if len(chunk) >= 20:
                    add_run_or_report(f"chmod -R {mode_str} {' '.join(chunk)}")
                    chunk = []
            if chunk:
                add_run_or_report(f"chmod -R {mode_str} {' '.join(chunk)}")
        # Emit remaining explicit paths
        for mode_str, paths in mode_groups.items():
            if not paths:
                continue
            chunk = []
            for p in paths:
                chunk.append(shlex.quote(p))
                if len(chunk) >= 50:
                    add_run_or_report(f"chmod -R {mode_str} {' '.join(chunk)}")
                    chunk = []
            if chunk:
                add_run_or_report(f"chmod -R {mode_str} {' '.join(chunk)}")
        if move_sources_to_remove:
            add_run_or_report(f"rm -f {' '.join([shlex.quote(p) for p in move_sources_to_remove])}")
        add_run_or_report(f"/igloo/boot/send_portalcall {GEN_LIVE_IMAGE_ACTION_FINISHED:#x}")
        return "\n".join(script_lines) + "\n"

    def _apply_patch_to_file_content(self, original_content: bytes, action: Dict) -> Optional[bytes]:
        """Applies a patch to a byte string and returns the new bytes."""
        if bool(action.get('hex_bytes')) == bool(action.get('asm')):
            self.logger.error(
                "Binary patch must have exactly one of 'hex_bytes' or 'asm'.")
            return None

        if action.get('asm'):
            patch_bytes = self._gen_asm_patch_bytes(
                action['asm'], action.get('mode'))
            if patch_bytes is None:
                return None
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
            self.logger.error(
                "Cannot assemble code because keystone-engine is not installed.")
            return None

        arch_map = {"armel": keystone.KS_ARCH_ARM, "aarch64": keystone.KS_ARCH_ARM64,
                    "mipsel": keystone.KS_ARCH_MIPS, "mipseb": keystone.KS_ARCH_MIPS, "intel64": keystone.KS_ARCH_X86}
        mode_map = {"aarch64": keystone.KS_MODE_LITTLE_ENDIAN, "mipsel": keystone.KS_MODE_MIPS32 | keystone.KS_MODE_LITTLE_ENDIAN,
                    "mipseb": keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN, "intel64": keystone.KS_MODE_64}

        ks_arch = arch_map.get(self.arch)
        if self.arch == "armel":
            arm_mode = user_mode or "arm"
            ks_mode = keystone.KS_MODE_THUMB if arm_mode == "thumb" else keystone.KS_MODE_ARM
            ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
        else:
            ks_mode = mode_map.get(self.arch)

        if ks_arch is None or ks_mode is None:
            self.logger.error(
                f"Unsupported architecture for assembly: {self.arch}")
            return None

        try:
            ks = keystone.Ks(ks_arch, ks_mode)
            encoding, _ = ks.asm(asm_code)
            return bytes(encoding)
        except Exception as e:
            self.logger.error(
                f"Keystone assembly failed for arch {self.arch}: {e}")
            return None

    @plugins.portalcall.portalcall(BATCH_PATCH_FILES_ACTION_MAGIC)
    def _on_batch_patch_hypercall(self):
        """Handles a single hypercall to patch all files in the queue."""
        self.logger.info(f"Batch patching {len(self.patch_queue)} files...")

        staged_dir = getattr(self, "staged_dir", None)
        if staged_dir is None:
            staged_dir = tempfile.gettempdir()

        for i, (guest_path, action) in enumerate(self.patch_queue):
            shared_file_name = f"patch_{i}"
            host_side_path = Path(staged_dir) / shared_file_name

            self.logger.debug(
                f"Patching guest file '{guest_path}' via staged file '{host_side_path}'")

            try:
                original_content = host_side_path.read_bytes()
                patched_content = self._apply_patch_to_file_content(
                    original_content, action)

                if patched_content is None:
                    self.logger.error(
                        f"Failed to generate patch for {guest_path}")
                    return -1

                host_side_path.write_bytes(patched_content)

            except Exception as e:
                self.logger.error(
                    f"Error during file patch of {host_side_path}: {e}", exc_info=True)
                return -1

        self.logger.info("Batch patching completed successfully.")
        return 0

    @plugins.portalcall.portalcall(GEN_LIVE_IMAGE_ACTION_FINISHED)
    def _on_live_image_finished(self):
        self.fs_generated = True
        for cb in self._init_callbacks:
            # If class-level, resolve method
            if hasattr(cb, '__self__') or (hasattr(cb, '__qualname__') and '.' in cb.__qualname__):
                class_name = cb.__qualname__.split('.')[0]
                method_name = cb.__qualname__.split('.')[-1]
                instance = getattr(plugins, class_name, None)
                if instance and hasattr(instance, method_name):
                    bound_cb = getattr(instance, method_name)
                    cb_to_call = bound_cb
                else:
                    self.logger.error(
                        f"Could not resolve class method {cb.__qualname__} for module_init")
                    continue
            else:
                cb_to_call = cb
            cb_to_call()
        return 0

    @plugins.portalcall.portalcall(REPORT_ERROR)
    def _on_report_error(self, line_num):
        """Handles guest error reporting via hypercall."""
        self.logger.error("LiveImage guest error reported via hypercall.")
        self.logger.error(
            f"Error reported at line {line_num} in guest script.")
        # Print gen_live_image.sh script bytes
        script_bytes = self._get_gen_live_image_script_bytes()
        output = "gen_live_image.sh contents:\n"
        for i, line in enumerate(script_bytes.decode("utf-8", errors="replace").splitlines()):
            output += f"{i+1}\t| {line.rstrip()}\n"
        self.logger.error(output)
        # Print last few lines from guest log
        log_path = Path(self.staged_dir) / "live_image_guest.log"
        try:
            output = "live_image_guest.log contents:\n"
            with open(log_path, "r") as f:
                for line in f.readlines():
                    output += f"{line.rstrip()}\n"
            self.logger.error(output)
        except Exception as e:
            self.logger.error(f"Could not read guest log: {e}")
        # Stop the system
        self.logger.error("Halting system due to guest error.")
        self.panda.end_analysis()

    def _get_gen_live_image_script_bytes(self):
        if not hasattr(self, '_gen_live_image_script_bytes') or self._gen_live_image_script_bytes is None:
            script_content = self._generate_setup_script()
            self._gen_live_image_script_bytes = script_content.encode()
        return self._gen_live_image_script_bytes

    @plugins.portalcall.portalcall(MAGIC_GET)
    def portalcall_get(self, path_ptr, offset, chunk_size, buffer_ptr):
        path = yield from plugins.mem.read_str(path_ptr)
        self.logger.debug(
            f"portalcall_get: path={path}, offset={offset}, chunk_size={chunk_size}, buffer_ptr={buffer_ptr}")
        # On-demand generation for gen_live_image.sh
        if path == "gen_live_image.sh":
            script_bytes = self._get_gen_live_image_script_bytes()
            script_len = len(script_bytes)
            if offset >= script_len:
                self.logger.debug(
                    f"portalcall_get: offset {offset} >= script_len {script_len}, returning 0 bytes")
                return 0
            end = min(offset + chunk_size, script_len)
            data = script_bytes[offset:end]
            self.logger.debug(
                f"portalcall_get: gen_live_image.sh, writing {len(data)} bytes")
            yield from plugins.mem.write_bytes(buffer_ptr, data)
            return len(data)
        staged_dir = getattr(self, "staged_dir", None)
        if staged_dir is None:
            staged_dir = tempfile.gettempdir()
        file_path = Path(staged_dir) / path.lstrip("/")
        if offset == 0 and chunk_size == 0:
            if not file_path.exists():
                self.logger.debug(
                    f"portalcall_get: file not found {file_path}")
                return -1
            size = file_path.stat().st_size
            self.logger.debug(f"portalcall_get: file size {size}")
            return size
        if not file_path.exists():
            self.logger.debug(f"portalcall_get: file not found {file_path}")
            return -1
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(chunk_size)
        self.logger.debug(
            f"portalcall_get: writing {len(data)} bytes from file {file_path}")
        yield from plugins.mem.write_bytes(buffer_ptr, data)
        return len(data)

    @plugins.portalcall.portalcall(MAGIC_PUT)
    def portalcall_put(self, path_ptr, offset, chunk_size, buffer_ptr):
        path = yield from plugins.mem.read_str(path_ptr)
        staged_dir = getattr(self, "staged_dir", None)
        if staged_dir is None:
            staged_dir = tempfile.gettempdir()
        file_path = Path(staged_dir) / path.lstrip("/")
        data = yield from plugins.mem.read_bytes(buffer_ptr, chunk_size)
        with open(file_path, "r+b" if file_path.exists() else "wb") as f:
            f.seek(offset)
            f.write(data)
        return len(data)

    @plugins.portalcall.portalcall(MAGIC_GET_PERM)
    def portalcall_get_perm(self, path_ptr):
        path = yield from plugins.mem.read_str(path_ptr)
        staged_dir = getattr(self, "staged_dir", None)
        if staged_dir is None:
            staged_dir = tempfile.gettempdir()
        file_path = Path(staged_dir) / path.lstrip("/")
        if not file_path.exists():
            return -1
        try:
            mode = file_path.stat().st_mode & 0o7777
            return mode
        except Exception:
            return -1

    @plugins.portalcall.portalcall(MAGIC_GETSIZE)
    def portalcall_getsize(self, path_ptr):
        path = yield from plugins.mem.read_str(path_ptr)
        if path == "gen_live_image.sh":
            script_bytes = self._get_gen_live_image_script_bytes()
            return len(script_bytes)
        staged_dir = getattr(self, "staged_dir", None)
        if staged_dir is None:
            staged_dir = tempfile.gettempdir()
        file_path = Path(staged_dir) / path.lstrip("/")
        if not file_path.exists():
            return -1
        try:
            size = file_path.stat().st_size
            return size
        except Exception:
            return -1
