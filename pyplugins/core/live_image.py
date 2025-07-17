from penguin import Plugin, plugins
from penguin.defaults import static_dir
from os import makedirs, chmod
from os.path import join
import shutil
import os
import keystone

GEN_LIVE_IMAGE_ACTION_MAGIC = 0xf113c0df


class LiveImage(Plugin):
    def __init__(self) -> None:
        self.panda.hypercall(GEN_LIVE_IMAGE_ACTION_MAGIC)(self._live_image_action)
        self.config = self.get_arg("conf")
        self.shared_dir = self.get_arg("shared_dir")
        self.host_files_dir = join(self.shared_dir, "host_files")
        makedirs(self.host_files_dir, exist_ok=True)

        self.file_counter = 0
        self.busybox = "/igloo/utils/busybox"
        self.proj_dir = self.get_arg("proj_dir")
        self.guest_shared_dir = "/igloo/shared/host_files"
        
        arch = self.config["core"]["arch"]
        self.arch_dir = arch
        if arch == "intel64":
            self.arch_dir = "x86_64"
        elif arch == "powerpc64el":
            self.arch_dir = "powerpc64"
        self.utils_dir = f"{static_dir}/{self.arch_dir}/"
        self.copy_util("send_hypercall_raw")
    
    def ensure_init(self):
        pass
    
    def copy_util(self, util_name):
        """
        Copy a utility file from the static directory to the guest's host_files directory.
        """
        util_path = join(self.utils_dir, util_name)
        if not os.path.exists(util_path):
            print(f"[LiveImage] ERROR: Utility {util_name} does not exist at {util_path}")
            return ""
        return self.copy_host_file_to_guest(util_path)

    def copy_host_file_to_guest(self, host_path):
        if not os.path.isabs(host_path):
            proj_dir = self.get_arg("proj_dir")
            host_path = os.path.join(proj_dir, host_path)
        dst = os.path.join(self.host_files_dir, os.path.basename(host_path))
        try:
            shutil.copyfile(host_path, dst)
            chmod(dst, 0o755)  # Make it executable
            return dst
        except Exception as e:
            print(f"[LiveImage] ERROR: Failed to copy host file {host_path} to {dst}: {e}")
            return ""
    
    def _get_parse_action(self):
        # Sort files by the length of their path to ensure directories are created first
        # But we'll handle 'move_from' types first - we need to move these out *before* we
        # replace them (i.e., /bin/sh goes into /igloo/utils/sh.orig and then we replace /bin/sh)
        files = dict(self.config.get("static_files", {}))

        # First we'll make any requested directories (which rm -rf anything that exists)
        mkdirs = {k: v for k, v in files.items() if v["type"] == "dir"}
        sorted_mkdirs = sorted(mkdirs.items(), key=lambda x: len(x[0]))
        for file_path, file in sorted_mkdirs:
            files.pop(file_path, None)  # Remove from files after yielding
            yield (file_path, dict(file))
        
        # Next, we'll do any move_from operations
        sorted_move_from_files = sorted(
            {k: v for k, v in files.items() if v["type"] == "move_from"},
            key=lambda x: len(files[x[0]])
        )
        for file_path, file in sorted_move_from_files:
            files.pop(file_path, None)
            yield (file_path, dict(file))

        # Now we'll do everything, except symlinks
        sorted_files = {
            k: v
            for k, v in files.items()
            if v["type"] not in ["move_from", "dir", "symlink", "shim"]
        }
        sorted_files = sorted(sorted_files.items(), key=lambda x: len(x[0]))
        for file_path, file in sorted_files:
            files.pop(file_path, None)
            yield (file_path, dict(file))

        # Create symlinks after everything else because guestfs requires destination to exist
        # move_from_files = {k: v for k, v in files.items() if v["type"] == "symlink"}
        move_from_files = {
            k: v for k, v in files.items() if v["type"] in ["symlink", "shim"]
        }
        sorted_move_from_files = sorted(
            move_from_files.items(), key=lambda x: len(files[x[0]]["target"])
        )
        for file_path, file in sorted_move_from_files:
            files.pop(file_path, None)
            yield (file_path, file)
        
        assert len(files) == 0, f"Unhandled files remaining: {files.keys()}"
    
    def octal_mode(self, mode):
        return oct(mode)[2:] if isinstance(mode, int) else str(mode)
    
    def parent_dir(self, path):
        d = os.path.dirname(path)
        return d if d and d != '/' else None
    
    def gen_asm_patch_bytes(self, action, asm):
        arch = self.config["core"]["arch"]
        arch_map = {
            "armel": getattr(keystone, "KS_ARCH_ARM"),
            "aarch64": getattr(keystone, "KS_ARCH_ARM64"),
            "mipsel": getattr(keystone, "KS_ARCH_MIPS"),
            "mipseb": getattr(keystone, "KS_ARCH_MIPS"),
            "mips64el": getattr(keystone, "KS_ARCH_MIPS"),
            "mips64eb": getattr(keystone, "KS_ARCH_MIPS"),
            "intel64": getattr(keystone, "KS_ARCH_X86"),
        }
        mode_map = {
            "aarch64": getattr(keystone, "KS_MODE_LITTLE_ENDIAN") | getattr(keystone, "KS_MODE_64"),
            "mipsel": getattr(keystone, "KS_MODE_MIPS32") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN"),
            "mipseb": getattr(keystone, "KS_MODE_MIPS32") | getattr(keystone, "KS_MODE_BIG_ENDIAN"),
            "mips64el": getattr(keystone, "KS_MODE_MIPS64") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN"),
            "mips64eb": getattr(keystone, "KS_MODE_MIPS64") | getattr(keystone, "KS_MODE_BIG_ENDIAN"),
            "intel64": getattr(keystone, "KS_MODE_64"),
        }
        ks_arch = arch_map.get(arch)
        if ks_arch is None:
            self.logger.error(f"Unsupported arch: {arch}")
            return None
        if arch == "armel":
            user_mode = action.get("mode", "arm")
            if user_mode == "thumb":
                ks_mode = getattr(keystone, "KS_MODE_THUMB") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN")
            else:
                ks_mode = getattr(keystone, "KS_MODE_ARM") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN")
        else:
            ks_mode = mode_map.get(arch)
            if ks_mode is None:
                self.logger.error(f"Unsupported mode for arch: {arch}")
                return None
        ks = keystone.Ks(ks_arch, ks_mode)
        encoding, _ = ks.asm(asm)
        patch_bytes = bytes(encoding)
        return patch_bytes

    def get_unique_shared_name(self, src):
        unique_name = f"{self.file_counter}_" + os.path.basename(src)
        self.file_counter += 1
        return unique_name

    def with_mkdir(self, cmd, dir_path):
        if dir_path and dir_path not in self.made_dirs:
            self.made_dirs.add(dir_path)
            return f"{self.busybox} mkdir -p '{dir_path}' && {cmd}"
        return cmd

    def copy_host_to_shared(self, src):
        if not os.path.isabs(src):
            src = os.path.join(self.proj_dir, src)
        unique_name = self.get_unique_shared_name(src)
        shared_dst = os.path.join(self.host_files_dir, unique_name)
        guest_shared_dst = os.path.join(self.guest_shared_dir, unique_name)
        if not os.path.exists(shared_dst):
            try:
                shutil.copyfile(src, shared_dst)
                self.logger.debug(f"Copied file {src} to {shared_dst}")
            except Exception as e:
                self.logger.error(f"Failed to copy file {src} to {shared_dst}: {e}")
                return None
        return guest_shared_dst
    
    def handle_generic_file(self, file_path, guest_shared_dst, mode=None):
        dir_path = self.parent_dir(file_path)
        mode_cmd = ""
        if mode:
            mode_str = self.octal_mode(mode)
            mode_cmd = f" && {self.busybox} chmod {mode_str} '{file_path}'"
        cmd = f"{self.busybox} cp '{guest_shared_dst}' '{file_path}' {mode_cmd}"
        cmd = self.with_mkdir(cmd, dir_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_host_file(self, file_path, action):
        src = action.get("host_path")
        if src and "*" in src:
            import glob
            src_glob = src if os.path.isabs(src) else os.path.join(self.proj_dir, src)
            matches = glob.glob(src_glob)
            for match in matches:
                target_path = os.path.join(os.path.dirname(file_path), os.path.basename(match))
                if target_path == "/igloo/utils/busybox":
                    continue
                guest_shared_dst = self.copy_host_to_shared(match)
                if not guest_shared_dst:
                    continue
                mode = action.get("mode", 0o777)
                yield from self.handle_generic_file(target_path, guest_shared_dst, mode)
            return
        guest_shared_dst = self.copy_host_to_shared(src)
        if not guest_shared_dst:
            return
        mode = action.get("mode", 0o777)
        yield from self.handle_generic_file(file_path, guest_shared_dst, mode)

    def handle_inline_file(self, file_path, action):
        contents = action.get("contents")
        unique_name = self.get_unique_shared_name(file_path)
        shared_dst = os.path.join(self.host_files_dir, unique_name)
        guest_shared_dst = os.path.join(self.guest_shared_dir, unique_name)
        if contents is not None:
            try:
                with open(shared_dst, "wb") as f:
                    f.write(contents if isinstance(contents, bytes) else contents.encode())
                self.logger.debug(f"Wrote inline file {shared_dst}")
            except Exception as e:
                self.logger.error(f"Failed to write inline file {shared_dst}: {e}")
                return
        yield from self.handle_generic_file(file_path, guest_shared_dst, action.get("mode", 0o777))

    def handle_binary_patch(self, file_path, action):
        info = plugins.staticfs.lookup(file_path)
        if not info:
            self.logger.error(f"File {file_path} not found in static_fs")
            return
        file_offset = action.get("file_offset", 0)
        hex_bytes = action.get("hex_bytes", "")
        asm = action.get("asm", None)
        if bool(hex_bytes) == bool(asm):
            self.logger.error("Exactly one of 'hex_bytes' or 'asm' must be specified for binary_patch")
            return
        if asm:
            patch_bytes = self.gen_asm_patch_bytes(action, asm)
        else:
            patch_bytes = bytes.fromhex(hex_bytes.replace(" ", ""))
        if patch_bytes is None:
            return
        unique_name = self.get_unique_shared_name(file_path)
        with open(unique_name, "wb") as out_file:
            with plugins.staticfs.open(info) as in_file:
                out_file.write(in_file.read(file_offset))
                out_file.write(patch_bytes)
                in_file.seek(file_offset + len(patch_bytes))
                out_file.write(in_file.read())
        yield from self.handle_generic_file(file_path, unique_name, action.get("mode", 0o777))

    def handle_copytar(self, file_path, action):
        tar_src = action.get("host_path")
        guest_tar = self.copy_host_to_shared(tar_src)
        if not guest_tar:
            return
        dir_path = self.parent_dir(file_path)
        cmd = f"{self.busybox} tar -xf '{guest_tar}' -C '{file_path}'"
        cmd = self.with_mkdir(cmd, dir_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_dir(self, file_path, action):
        mode_str = self.octal_mode(action.get("mode", 0o777))
        cmd = f"{self.busybox} chmod {mode_str} '{file_path}'"
        cmd = self.with_mkdir(cmd, file_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_symlink(self, file_path, action):
        target = action.get("target", "")
        dir_path = self.parent_dir(file_path)
        cmd = f"{self.busybox} ln -sf '{target}' '{file_path}'"
        cmd = self.with_mkdir(cmd, dir_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_dev(self, file_path, action):
        devtype = action.get("devtype", "")
        major = action.get("major", 0)
        minor = action.get("minor", 0)
        dir_path = self.parent_dir(file_path)
        cmd = f"{self.busybox} mknod '{file_path}' {'c' if devtype == 'char' else 'b'} {major} {minor} && {self.busybox} chmod 777 '{file_path}'"
        cmd = self.with_mkdir(cmd, dir_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_move(self, file_path, action):
        from_path = action.get("from", "")
        dir_path = self.parent_dir(file_path)
        mode_str = self.octal_mode(action.get("mode", 0o777))
        cmd = f"{self.busybox} mv '{from_path}' '{file_path}' && {self.busybox} chmod {mode_str} '{file_path}'"
        cmd = self.with_mkdir(cmd, dir_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_shim(self, file_path, action):
        target = action.get("target", "")
        orig_path = f"/igloo/utils/{os.path.basename(file_path)}.orig"
        dir_path = self.parent_dir(orig_path)
        cmd = f"{self.busybox} mv '{file_path}' '{orig_path}' && {self.busybox} ln -sf '{target}' '{file_path}' && {self.busybox} chmod 777 '{file_path}'"
        cmd = self.with_mkdir(cmd, dir_path)
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def handle_delete(self, file_path, action):
        cmd = f"{self.busybox} rm -rf '{file_path}'"
        self.logger.debug(f"CMD: {cmd}")
        yield cmd

    def build_shell_commands(self):
        self.made_dirs = set()
        handlers = {
            "host_file": self.handle_host_file,
            "inline_file": self.handle_inline_file,
            "binary_patch": self.handle_binary_patch,
            "copytar": self.handle_copytar,
            "dir": self.handle_dir,
            "symlink": self.handle_symlink,
            "dev": self.handle_dev,
            "move": self.handle_move,
            "shim": self.handle_shim,
            "delete": self.handle_delete,
        }
        for file_path, action in self._get_parse_action():
            if file_path.startswith("/dev/") or file_path == "/dev":
                self.logger.warning("/dev/ must be populated dynamically in config.pseudofiles - ignoring request to modify %s", file_path)
                continue
            t = action.get("type")
            if file_path == "/igloo/utils/busybox":
                continue
            handler = handlers.get(t)
            if handler:
               yield from handler(file_path, action)
            else:
                self.logger.error(f"Unhandled action type '{t}' for file {file_path}")

    def _live_image_action(self, cpu):
        if not hasattr(self, "script_written"):
            # Write all commands to a script in the shared dir
            script_path = os.path.join(self.host_files_dir, "gen_live_image.sh")
            with open(script_path, "w") as f:
                f.write(f"#!/igloo/utils/busybox sh\n")
                for cmd in self.build_shell_commands():
                    f.write(cmd + "\n")
            os.chmod(script_path, 0o755)
            self.script_written = True
            self.panda.arch.set_retval(cpu, 0, convention="syscall")