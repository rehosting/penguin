"""
LiveImage Plugin
================

Generates a guest filesystem live by creating a setup script that runs on boot.
This version uses a tarball for file deployment and a single, batched hypercall for patching.

Overview
--------

- Stages files and directories for deployment using a tarball.
- Supports various file actions: delete, move, shim, dir, host_file, inline_file, binary_patch, dev, symlink.
- Efficient setup script generation using hyp_file_op for file transfer.
- Batch processing of binary patches via a single hypercall.
- Optional pre-patch verification of expected bytes (``expect`` /
  ``on_mismatch``) and per-patch provenance (``why`` / ``tag``), recorded in
  ``binary_patches.yaml`` in the run output directory.
- Handles permissions, symlinks, device nodes, and error reporting.

Usage
-----

The plugin is loaded by the Penguin framework and manages guest filesystem setup and patching.

Arguments
---------

- ``proj_dir``: Project directory for resolving host files.
- ``conf``: Configuration dictionary specifying static files and actions.

Classes
-------

- LiveImage: Main plugin class for guest filesystem setup and patching.

"""

from penguin import Plugin, plugins, yaml
from penguin.penguin_config.structure import normalize_hex_string
from penguin.plugin_manager import resolve_bound_method_from_class
from penguin.defaults import static_dir as STATIC_DIR
from penguin.utils import get_arch_subdir
from penguin.boot_env import partition_boot_env, render_env_blob
import json
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

# Virtual file (generated on demand, never staged) holding penguin's internal
# boot env as `export K=V` lines. preinit.sh fetches and sources it after
# insmod so the knobs land in PID1's env instead of riding the kernel cmdline.
BOOT_ENV_FILENAME = "igloo_env.sh"


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
        self._patch_base_offset = {}
        self.config = self.get_arg("conf")
        core_config = self.config.get("core", {})
        self.arch = core_config.get("arch", "x86_64")
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
        Sorts 'static_files' actions into a logical execution order.
        """
        actions = self.get_arg("conf").get("static_files", {}).items()

        action_order = ["delete", "move", "shim", "dir", "host_file",
                        "inline_file", "binary_patch", "dev", "symlink"]

        partitions = {key: [] for key in action_order}
        for path, action in actions:
            action_type = action.get("type")
            if action_type not in partitions:
                raise ValueError(f"Unknown static_files action type {action_type!r} for {path}")
            partitions[action_type].append((path, action))

        for action_type in action_order:
            reverse_sort = action_type == "delete"
            for path, action in sorted(partitions[action_type], key=lambda item: len(item[0]), reverse=reverse_sort):
                yield path, action

    def _stage_tool_closure(self, staging_dir: Path) -> None:
        """Stage the per-arch debugging-tool wrappers (python3, strace,
        gdbserver, ltrace, iptables).

        penguin-tools ships, per arch:
          <STATIC_DIR>/closures/<arch>/closure.tar.gz  -- /nix/store/... closure
          <STATIC_DIR>/closures/<arch>/manifest.json   -- {tool: in-store exe}

        The closure itself (~150-300MB, ~8.4k files) is large, image-level, and
        content-stable, so it is *baked into the base image* once at
        /igloo/nix/store/... (see gen_image.tar_add_tool_closure) and reused
        across configs/runs -- NOT re-shipped here every boot. This method only
        stages the tiny per-tool /igloo/utils/<tool> wrappers, which run the
        pristine binary inside a private mount namespace with /igloo/nix
        bind-mounted onto /nix so the binary's own absolute /nix/store
        interpreter/rpath resolve unchanged. (Pristine binaries instead of the
        old ELF-rewritten musl bundles fix intermittent wrong-mm SIGSEGVs on
        MIPS -- penguin #823.)
        """
        arch_dir = get_arch_subdir(self.config)
        closure_dir = Path(STATIC_DIR) / "closures" / arch_dir
        manifest_path = closure_dir / "manifest.json"
        closure_tar = closure_dir / "closure.tar.gz"
        if not manifest_path.is_file() or not closure_tar.is_file():
            self.logger.warning(
                f"No tool closure at {closure_dir}; debugging tools "
                f"(python3/strace/gdbserver/ltrace/iptables) unavailable for {arch_dir}")
            return

        with open(manifest_path) as f:
            tool_manifest = json.load(f)

        # The closure store and the /nix mountpoint are baked into the base
        # image; create the mountpoint here too so a forced-reuse of an old,
        # pre-bake cached image still has the bind target (cheap, idempotent).
        (staging_dir / "nix").mkdir(parents=True, exist_ok=True)

        utils_dir = staging_dir / "igloo" / "utils"
        utils_dir.mkdir(parents=True, exist_ok=True)
        for tool, exe in tool_manifest.items():
            # busybox unshare -m runs the inner sh in a fresh mount namespace;
            # the bind mount is private to it and torn down on exit. $0 is the
            # in-store exe, "$@" the caller's args.
            wrapper = (
                "#!/igloo/utils/sh\n"
                "exec /igloo/utils/busybox unshare -m /igloo/utils/sh -c "
                "'/igloo/utils/busybox mount -o bind /igloo/nix /nix && exec \"$0\" \"$@\"' "
                f"{shlex.quote(exe)} \"$@\"\n"
            )
            wrapper_path = utils_dir / tool
            wrapper_path.write_text(wrapper)
            wrapper_path.chmod(0o755)
        self.logger.info(
            f"Staged tool wrappers for {arch_dir} (closure baked into base image): "
            f"{', '.join(sorted(tool_manifest))}")

    def _generate_setup_script(self) -> str:
        """Builds an efficient setup script using hyp_file_op for file transfer, not shared_dir."""
        post_tar_commands = []
        paths_to_delete = []
        self.patch_queue = []  # Reset for this run
        self._patch_base_offset = {}  # index -> window base offset (set in Phase 4)
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
                            raise FileNotFoundError(
                                f"No files matched for host_file source glob: {source_path_pattern} "
                                f"(static_files entry: {file_path} -> {action})")
                        staged_matches = [host_src for host_src in glob_matches if host_src.is_file() or host_src.is_dir()]
                        if not staged_matches:
                            raise FileNotFoundError(
                                f"No files or directories matched for host_file source glob: {source_path_pattern} "
                                f"(static_files entry: {file_path} -> {action})")
                        for host_src in staged_matches:
                            staged_file_path = dest_dir_path / host_src.name
                            if host_src.is_dir():
                                shutil.copytree(host_src, staged_file_path, symlinks=True, dirs_exist_ok=True)
                            else:
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
                            raise FileNotFoundError(
                                f"No files matched for host_file source glob: {source_path_pattern} "
                                f"(static_files entry: {file_path} -> {action})")
                        staged_matches = [host_src for host_src in glob_matches if host_src.is_file() or host_src.is_dir()]
                        if not staged_matches:
                            raise FileNotFoundError(
                                f"No files or directories matched for host_file source glob: {source_path_pattern} "
                                f"(static_files entry: {file_path} -> {action})")
                        for host_src in staged_matches:
                            staged_file_path = staged_path / host_src.name
                            staged_file_path.parent.mkdir(
                                parents=True, exist_ok=True)
                            if host_src.is_dir():
                                shutil.copytree(host_src, staged_file_path, symlinks=True, dirs_exist_ok=True)
                            else:
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
                        if not (host_src.is_file() or host_src.is_dir()):
                            raise FileNotFoundError(
                                f"Host file is not a regular file or directory: {host_src} "
                                f"(static_files entry: {file_path} -> {action})")
                        staged_path.parent.mkdir(
                            parents=True, exist_ok=True)
                        if host_src.is_dir():
                            shutil.copytree(host_src, staged_path, symlinks=True, dirs_exist_ok=True)
                        else:
                            shutil.copy(host_src, staged_path)
                        if 'mode' in action:
                            record_mode(file_path, action['mode'])

                # A placed host_file/inline_file may carry 'patches' to apply
                # after it lands in the guest. Expand them into the same Phase 4
                # binary_patch pipeline by queueing a synthetic binary_patch
                # against this path (which now resolves to the staged file).
                synth = self._synth_file_patch_action(file_path, action)
                if synth is not None:
                    self.patch_queue.append((file_path, synth))

            # Queue or generate commands for post-tar execution
            elif action_type == "binary_patch":
                self.patch_queue.append((file_path, action))
            elif action_type == "delete":
                paths_to_delete.append(file_path)
            elif action_type == "symlink":
                record_parent_dirs(file_path)
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
                    "sh -c "
                    + shlex.quote(
                        f"test -e {shlex.quote(file_path)} || "
                        f"{{ echo {shlex.quote('ERROR: static_files shim source missing: ' + file_path)} >&2; exit 1; }}"
                    ))
                post_tar_commands.append(
                    f"mv {shlex.quote(file_path)} {shlex.quote(orig_path)}")
                # Symlink to the target specified in configuration
                post_tar_commands.append(
                    f"ln -sf {shlex.quote(action['target'])} {shlex.quote(file_path)}")
            elif action_type == "move":
                post_tar_commands.append(
                    "sh -c "
                    + shlex.quote(
                        f"test -e {shlex.quote(action['from'])} || "
                        f"{{ echo {shlex.quote('ERROR: static_files move source missing: ' + action['from'])} >&2; exit 1; }}"
                    ))
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

        # Stage the per-arch debugging-tool runtime closure + wrappers. This is
        # image-level (not project-level) data, so it is staged here on every
        # run rather than baked into the config by an init-time patch generator.
        self._stage_tool_closure(staging_dir)

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

        def add_require_exists(path: str, action_type: str):
            msg = f"ERROR: static_files {action_type} source missing: {path}"
            add_run_or_report(
                "sh -c "
                + shlex.quote(
                    f"test -e {shlex.quote(path)} || "
                    f"{{ echo {shlex.quote(msg)} >&2; exit 1; }}"
                )
            )

        if paths_to_delete:
            add_run_or_report(f"rm -rf {' '.join([shlex.quote(p) for p in paths_to_delete])}")
        # Use hyp_file_op to get the tarball and extract
        add_run_or_report("/igloo/boot/hyp_file_op get filesystem.tar /igloo/boot/filesystem.tar")
        # Replace inline symlink logic with ensure_dir calls
        for d in sorted(needed_parent_dirs):
            add_run_or_report(f"ensure_dir {shlex.quote(d)}")
        add_run_or_report("tar x -om -f /igloo/boot/filesystem.tar -C / --no-same-permissions")

        # --- Phase 4: Batch-process binary patches ---
        # Only the byte window each patch touches is shipped host<->guest (via
        # hyp_file_op --range), not the whole target file, so patching a few
        # bytes of a large binary no longer streams the entire file twice. The
        # host records each window's base offset so the batch hypercall can
        # apply edits (whose offsets are absolute) against the window.
        if self.patch_queue:
            patch_staging_cmds = []
            patch_return_cmds = []

            for i, (file_path, action) in enumerate(self.patch_queue):
                shared_file_name = f"patch_{i}"
                base_off, win_len = self._patch_window(action)
                self._patch_base_offset[i] = base_off
                self._check_patch_within_file(file_path, base_off, win_len)
                add_require_exists(file_path, "binary_patch")
                patch_staging_cmds.append(
                    f"/igloo/boot/hyp_file_op put {shlex.quote(file_path)} "
                    f"{shlex.quote(os.path.basename(shared_file_name))} "
                    f"--range {base_off:#x} {win_len:#x}")
            script_lines.append("\n# Staging patch windows")
            for cmd in patch_staging_cmds:
                add_run_or_report(cmd)

            script_lines.append("\n# Triggering single batched patch hypercall")
            add_run_or_report(f"/igloo/boot/send_portalcall {BATCH_PATCH_FILES_ACTION_MAGIC:#x}")

            for i, (file_path, _) in enumerate(self.patch_queue):
                shared_file_name = f"patch_{i}"
                base_off = self._patch_base_offset[i]
                patch_return_cmds.append(
                    f"/igloo/boot/hyp_file_op get {shlex.quote(shared_file_name)} "
                    f"{shlex.quote(file_path)} --range {base_off:#x}")
            script_lines.append("\n# Writing patched windows back")
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

    @staticmethod
    def _parse_hex(s: str) -> bytes:
        """Parse a hex byte string, allowing an optional 0x prefix and spaces.
        Delegates to the schema's normalize_hex_string so the config-load
        validator and this build-time parser accept exactly the same inputs.
        Raises ValueError on invalid/odd-length hex."""
        return bytes.fromhex(normalize_hex_string(s))

    @staticmethod
    def _synth_file_patch_action(file_path: str, action: Dict) -> Optional[Dict]:
        """Turn a placed ``host_file``/``inline_file`` that carries a
        ``patches`` list into the equivalent standalone ``binary_patch`` action
        to queue against its staged path, so both go through one pipeline.

        Returns ``None`` when the action has no patches. Raises ValueError if
        the file uses a glob source or destination, since the patch target
        would then be ambiguous (which of the matched files?). Glob detection
        matches the staging code, which only treats a wildcard in the final
        path component (``dest_path.name`` / source ``name``) as a glob.
        """
        patches = action.get("patches")
        if not patches:
            return None
        dest_name = os.path.basename(file_path)
        src_name = os.path.basename(action.get("host_path") or "")
        if any(c in dest_name or c in src_name for c in ("*", "?")):
            raise ValueError(
                f"static_files {action.get('type')} {file_path}: 'patches' "
                "cannot be combined with a glob source or destination — the "
                "patch target would be ambiguous. Give each file its own "
                "host_file/inline_file entry with its own patches.")
        return {"type": "binary_patch", "patches": list(patches)}

    def _normalize_patch_entries(self, action: Dict) -> Tuple[Optional[list], Optional[str]]:
        """Expand a binary_patch action into a flat list of per-offset edit
        dicts. An action uses *either* the inline single-edit form
        (file_offset + hex_bytes/asm) *or* the ``patches`` list, not both.
        Returns ``(entries, error)``."""
        patches = action.get("patches")
        # Per-edit fields carried at the action level are meaningless once
        # 'patches' is used (each entry carries its own), so reject that mix
        # loudly. on_mismatch is omitted here: it defaults to "fail" in the
        # schema, so an action-level value can't be told apart from the default.
        action_level = [k for k in ("file_offset", "hex_bytes", "asm", "mode",
                                    "expect", "why", "tag")
                        if action.get(k) is not None]
        if patches:
            if action_level:
                return None, ("binary_patch: per-edit fields must go inside each "
                              f"'patches' entry, not at the action level "
                              f"(saw action-level {action_level})")
            return list(patches), None
        if action.get("file_offset") is None:
            return None, ("binary_patch: needs 'file_offset' (inline single edit) "
                          "or a non-empty 'patches' list")
        # Inline single edit: reuse every patch-relevant field from the action
        # (all but the wrapper keys) so new fields flow through automatically.
        entry = {k: v for k, v in action.items() if k not in ("type", "patches")}
        return [entry], None

    def _entry_patch_bytes(self, entry: Dict) -> Tuple[Optional[bytes], Optional[str]]:
        """Compute the bytes one edit writes (assemble asm or parse hex).
        Returns ``(patch_bytes, error)``."""
        has_hex = bool(entry.get("hex_bytes"))
        has_asm = bool(entry.get("asm"))
        if has_hex == has_asm:
            return None, "must have exactly one of 'hex_bytes' or 'asm'"
        if has_asm:
            pb = self._gen_asm_patch_bytes(entry["asm"], entry.get("mode"))
            if pb is None:
                return None, "failed to assemble asm"
            return pb, None
        try:
            return self._parse_hex(entry["hex_bytes"]), None
        except ValueError as e:
            return None, f"invalid hex_bytes {entry['hex_bytes']!r}: {e}"

    def _verify_entry(self, original_content: bytes, entry: Dict,
                      patch_bytes: bytes, base_offset: int = 0) -> Tuple[str, str]:
        """Apply one edit's ``expect``/``on_mismatch`` policy against the
        pristine file bytes. Returns ``(status, detail)`` where status is
        'applied', 'skipped', or 'failed'.

        ``expect`` is checked over its own length (which may differ from the
        patch length). If the bytes at the offset already equal the patch
        bytes, the edit is an idempotent skip under *every* policy.

        ``base_offset`` is subtracted from the edit's ``file_offset`` before
        indexing ``original_content``, so the caller can pass just a window of
        the file (starting at ``base_offset``) instead of the whole thing;
        recorded/reported offsets stay absolute. Defaults to 0 (whole file).
        """
        off = entry["file_offset"]
        pos = off - base_offset
        if not entry.get("expect"):
            return "applied", ""
        try:
            expect_bytes = self._parse_hex(entry["expect"])
        except ValueError as e:
            return "failed", f"invalid expect {entry['expect']!r}: {e}"
        current = original_content[pos:pos + len(expect_bytes)]
        if current == expect_bytes:
            return "applied", ""
        if original_content[pos:pos + len(patch_bytes)] == patch_bytes:
            return "skipped", "already patched (bytes at offset equal the patch bytes)"
        mismatch = (
            f"expected {expect_bytes.hex()} at offset {off:#x} "
            f"but found {current.hex() or '<EOF>'} "
            f"(file is {len(original_content)} bytes)")
        policy = entry.get("on_mismatch") or "fail"
        if policy == "skip":
            return "skipped", mismatch
        if policy == "warn":
            return "applied", f"patched despite mismatch: {mismatch}"
        return "failed", mismatch

    @staticmethod
    def _patch_record(entry: Dict, result: str, detail: str) -> Dict:
        """Build one provenance record (ordered: offset, result, tag, why, detail)."""
        rec = {}
        if entry.get("file_offset") is not None:
            rec["file_offset"] = hex(entry["file_offset"])
        rec["result"] = result
        for k in ("tag", "why"):
            if entry.get(k):
                rec[k] = entry[k]
        if detail:
            rec["detail"] = detail
        return rec

    def _apply_binary_patch(self, original_content: bytes, action: Dict,
                            base_offset: int = 0) -> Tuple[Optional[bytes], list, bool]:
        """Apply every edit of one binary_patch action to a single buffer.

        Returns ``(new_content, records, failed)``:
          - ``records``: one provenance dict per edit.
          - ``new_content``: the patched bytes, or None if any edit failed.
          - ``failed``: True if any edit failed (fail-policy mismatch, bad
            bytes, or an overlapping write range). The caller must then abort
            and leave the file untouched.

        All edits are applied to one buffer in a single pass; overlapping write
        ranges are detected up front and rejected so no edit can silently
        clobber another.

        ``base_offset`` is subtracted from each edit's ``file_offset`` before
        indexing ``original_content``, so the caller may pass just a window of
        the file (starting at ``base_offset``). ``new_content`` is then that
        window with the edits applied; recorded offsets stay absolute. Defaults
        to 0 (``original_content`` is the whole file).
        """
        entries, err = self._normalize_patch_entries(action)
        if err:
            return None, [{"result": "failed", "detail": err}], True

        # Compute the bytes each edit writes first — needed both to apply and to
        # compute write ranges for overlap detection.
        computed = [(entry, *self._entry_patch_bytes(entry)) for entry in entries]

        # Reject overlapping write ranges [off, off+len). Verifying against the
        # pristine buffer below is only equivalent to "verify against original"
        # because disjoint ranges cannot perturb one another. Compared pairwise
        # (not just adjacent) so a range fully contained in another is caught
        # too; patch lists are short, so O(n^2) is fine.
        ranges = [(entry["file_offset"], entry["file_offset"] + len(pb), id(entry))
                  for entry, pb, perr in computed if pb is not None]
        overlapping = set()
        for i, a in enumerate(ranges):
            for b in ranges[i + 1:]:
                if a[0] < b[1] and b[0] < a[1]:
                    overlapping.add(a[2])
                    overlapping.add(b[2])

        buf = bytearray(original_content)
        records = []
        failed = False
        for entry, patch_bytes, perr in computed:
            if perr is not None:
                records.append(self._patch_record(entry, "failed", perr))
                failed = True
                continue
            if id(entry) in overlapping:
                off = entry["file_offset"]
                records.append(self._patch_record(
                    entry, "failed",
                    f"write range {off:#x}..{off + len(patch_bytes):#x} "
                    "overlaps another patch to this file"))
                failed = True
                continue
            # Bounds-check the write against the actual buffer before touching
            # it. bytearray slice-assignment silently misplaces bytes when the
            # start is past the end (appends) or negative (writes from the far
            # end), so an offset beyond the real window — e.g. a short read
            # because the guest file was smaller than declared, or a negative
            # offset — would corrupt the file instead of failing. In the normal
            # windowed case pos is in [0, len) by construction, so this never
            # false-trips; it only fires on those degenerate reads.
            pos = entry["file_offset"] - base_offset
            if pos < 0 or pos + len(patch_bytes) > len(original_content):
                off = entry["file_offset"]
                records.append(self._patch_record(
                    entry, "failed",
                    f"offset {off:#x} (window position {pos}) is outside the "
                    f"{len(original_content)}-byte target window — bad offset "
                    "or the file is shorter than the patch expects"))
                failed = True
                continue
            status, detail = self._verify_entry(
                original_content, entry, patch_bytes, base_offset)
            if status == "applied":
                buf[pos:pos + len(patch_bytes)] = patch_bytes
            elif status == "failed":
                failed = True
            records.append(self._patch_record(entry, status, detail))

        new_content = None if failed else bytes(buf)
        return new_content, records, failed

    def _patch_window(self, action: Dict) -> Tuple[int, int]:
        """Compute the ``(base_offset, length)`` byte window that covers every
        edit of one binary_patch action, so only that range is transferred
        to/from the guest instead of the whole file. The window spans from the
        lowest edit offset to the furthest byte any edit reads (``expect``) or
        writes (patch). Raises ValueError on a malformed edit (bad bytes,
        missing offset, both/neither hex_bytes+asm) so the run fails before
        boot rather than aborting mid-build.
        """
        entries, err = self._normalize_patch_entries(action)
        if err:
            raise ValueError(err)
        lo = hi = None
        for entry in entries:
            patch_bytes, perr = self._entry_patch_bytes(entry)
            if perr is not None:
                raise ValueError(
                    f"binary_patch at offset {entry.get('file_offset')}: {perr}")
            off = entry["file_offset"]
            span = len(patch_bytes)
            if entry.get("expect"):
                try:
                    span = max(span, len(self._parse_hex(entry["expect"])))
                except ValueError as e:
                    raise ValueError(
                        f"binary_patch at offset {off:#x}: invalid expect "
                        f"{entry['expect']!r}: {e}")
            lo = off if lo is None else min(lo, off)
            hi = off + span if hi is None else max(hi, off + span)
        return lo, hi - lo

    @staticmethod
    def _window_exceeds_size(base_off: int, win_len: int,
                             size: Optional[int]) -> bool:
        """True only when the size is known (not None) and the patch window
        runs past the end of the file. Unknown size -> never flagged (skip)."""
        return size is not None and base_off + win_len > size

    def _check_patch_within_file(self, file_path: str, base_off: int,
                                 win_len: int) -> None:
        """Fail before boot if a patch window falls past the end of its target
        file, when the size can be determined from the static filesystem.

        Uses the ``static_fs`` view, which composes the base rootfs with
        config operations (``host_file``/``inline_file``) and resolves symlinks;
        ``binary_patch`` is passed through as an in-place edit so we read the
        underlying file's size. If the size can't be determined (target not in
        the rootfs, static_fs unavailable), the check is skipped rather than
        failing — this catches out-of-bounds offsets without false positives,
        and is complementary to per-edit ``expect`` verification.
        """
        try:
            size = plugins.static_fs.get_size(file_path, transparent={"binary_patch"})
        except Exception as e:
            self.logger.debug(
                f"binary_patch: size check skipped for {file_path}: {e}")
            return
        if self._window_exceeds_size(base_off, win_len, size):
            raise ValueError(
                f"binary_patch {file_path}: patch window "
                f"{base_off:#x}..{base_off + win_len:#x} exceeds file size "
                f"{size} bytes — wrong offset or wrong target file?")

    def _gen_asm_patch_bytes(self, asm_code: str, user_mode: Optional[str]) -> Optional[bytes]:
        """Assembles assembly code into bytes using Keystone."""
        if keystone is None:
            self.logger.error(
                "Cannot assemble code because keystone-engine is not installed.")
            return None

        arch_map = {"armel": keystone.KS_ARCH_ARM, "aarch64": keystone.KS_ARCH_ARM64,
                    "mipsel": keystone.KS_ARCH_MIPS, "mipseb": keystone.KS_ARCH_MIPS,
                    "x86_64": keystone.KS_ARCH_X86, "intel64": keystone.KS_ARCH_X86}
        mode_map = {"aarch64": keystone.KS_MODE_LITTLE_ENDIAN, "mipsel": keystone.KS_MODE_MIPS32 | keystone.KS_MODE_LITTLE_ENDIAN,
                    "mipseb": keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN,
                    "x86_64": keystone.KS_MODE_64, "intel64": keystone.KS_MODE_64}

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

        records = []
        for i, (guest_path, action) in enumerate(self.patch_queue):
            shared_file_name = f"patch_{i}"
            host_side_path = Path(staged_dir) / shared_file_name

            self.logger.debug(
                f"Patching guest file '{guest_path}' via staged file '{host_side_path}'")

            try:
                # original_content is only the window that was staged
                # (hyp_file_op --range); base_offset rebases absolute edit
                # offsets onto it.
                window = host_side_path.read_bytes()
                base_offset = self._patch_base_offset.get(i, 0)
                new_content, recs, failed = self._apply_binary_patch(
                    window, action, base_offset)
            except Exception as e:
                self.logger.error(
                    f"Error during file patch of {host_side_path}: {e}", exc_info=True)
                new_content, recs, failed = None, [{"result": "failed",
                                                    "detail": str(e)}], True

            for r in recs:
                r = {"file": guest_path, **r}
                records.append(r)
                offset = r.get("file_offset", "?")
                provenance = "".join(f" [{k}={r[k]}]"
                                     for k in ("tag", "why") if k in r)
                detail = r.get("detail")
                line = (f"binary_patch {guest_path} @ {offset}{provenance}: "
                        f"{r['result']}" + (f" ({detail})" if detail else ""))
                if r["result"] == "failed":
                    self.logger.error(line)
                elif detail:
                    self.logger.warning(line)
                else:
                    self.logger.info(line)

            # Only persist the patched file when every edit succeeded; on
            # failure we abort so the guest never copies back a half-patched
            # file. Returning -1 propagates through send_portalcall's exit code
            # to run_or_report, which halts the image build.
            if failed:
                self._write_patch_report(records)
                self.logger.error(
                    f"Aborting: binary patch of '{guest_path}' failed.")
                return -1
            if new_content is not None:
                host_side_path.write_bytes(new_content)

        self._write_patch_report(records)
        self.logger.info("Batch patching completed successfully.")
        return 0

    def _write_patch_report(self, records):
        """Record patch provenance (offset, tag, why, result) in the run output."""
        outdir = self.get_arg("outdir")
        if not outdir or not records:
            return
        try:
            with open(Path(outdir) / "binary_patches.yaml", "w") as f:
                yaml.dump(records, f, sort_keys=False)
        except Exception as e:
            self.logger.error(f"Could not write binary_patches.yaml: {e}")

    @plugins.portalcall.portalcall(GEN_LIVE_IMAGE_ACTION_FINISHED)
    def _on_live_image_finished(self):
        self.fs_generated = True
        for cb in self._init_callbacks:
            cb_to_call = resolve_bound_method_from_class(cb)
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

    def _get_boot_env_script_bytes(self):
        """Render penguin's internal boot env (the blob bucket of
        partition_boot_env) as a sourceable `export K=V` snippet. Generated
        once on first request -- conf["env"] is finalized by the time the guest
        boots and asks for it -- and cached so getsize/get agree on length."""
        if getattr(self, "_boot_env_script_bytes", None) is None:
            _cmdline_env, blob_env = partition_boot_env(self.config.get("env", {}))
            self._boot_env_script_bytes = render_env_blob(blob_env).encode()
        return self._boot_env_script_bytes

    @plugins.portalcall.portalcall(MAGIC_GET)
    def portalcall_get(self, path_ptr, offset, chunk_size, buffer_ptr):
        path = yield from plugins.mem.read_str(path_ptr)
        self.logger.debug(
            f"portalcall_get: path={path}, offset={offset}, chunk_size={chunk_size}, buffer_ptr={buffer_ptr}")
        # On-demand generation for virtual (never-staged) files.
        if path in ("gen_live_image.sh", BOOT_ENV_FILENAME):
            if path == BOOT_ENV_FILENAME:
                script_bytes = self._get_boot_env_script_bytes()
            else:
                script_bytes = self._get_gen_live_image_script_bytes()
            script_len = len(script_bytes)
            if offset >= script_len:
                self.logger.debug(
                    f"portalcall_get: offset {offset} >= script_len {script_len}, returning 0 bytes")
                return 0
            end = min(offset + chunk_size, script_len)
            data = script_bytes[offset:end]
            self.logger.debug(
                f"portalcall_get: {path}, writing {len(data)} bytes")
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
        if path == BOOT_ENV_FILENAME:
            return len(self._get_boot_env_script_bytes())
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
