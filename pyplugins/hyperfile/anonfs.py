from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop
from typing import Generator
from hyperfile.models.base import VFSFile, SocketFile


class AnonFS(Plugin):
    def __init__(self):
        # We maintain a strong reference to the dynamically created models
        # so the C FFI trampolines aren't garbage collected while the
        # guest kernel holds the live file descriptors.
        self.dynamic_files = {}
        self.next_dynamic_id = 1

    def register_dynamic_file(self, file_model) -> int:
        """Stores the model to keep FFI pointers alive in memory."""
        fid = self.next_dynamic_id
        self.next_dynamic_id += 1
        self.dynamic_files[fid] = file_model
        return fid

    def _make_fops_struct(self, vfs_file: VFSFile):
        """
        Build an igloo_dev_ops struct with FFI trampolines for VFS methods.
        """
        kffi = plugins.kffi
        method_names = [
            "open", "read", "read_iter", "write", "write_iter", "lseek",
            "release", "poll", "ioctl", "compat_ioctl", "mmap", "get_unmapped_area",
            "flush", "fsync", "fasync", "lock"
        ]

        # We use igloo_dev_ops as our generic VFS struct transporter
        ops_type = kffi.ffi.get_type("igloo_dev_ops")

        init_data = {}
        for name in method_names:
            # Leverage BaseFile's native overridden detection
            if getattr(vfs_file, "_is_overridden", lambda x: False)(name):
                fn = getattr(vfs_file, name)
                op_signature = None
                if ops_type and name in ops_type.members:
                    member_type = ops_type.members[name].type_info

                    # Unwrap the function pointer layer for kffi
                    if member_type and member_type.get("kind") == "pointer":
                        op_signature = member_type.get("subtype")
                    else:
                        op_signature = member_type

                init_data[name] = yield from kffi.callback(fn, func_type=op_signature)

        return kffi.new("igloo_dev_ops", init_data)

    def _make_proto_ops_struct(self, sock_file: SocketFile):
        """
        Build an igloo_proto_ops struct with FFI trampolines for Socket methods.
        """
        kffi = plugins.kffi
        method_names = ["bind", "connect", "sendmsg", "recvmsg", "release"]

        ops_type = kffi.ffi.get_type("igloo_proto_ops")

        init_data = {}
        for name in method_names:
            # Leverage BaseFile's native overridden detection
            if getattr(sock_file, "_is_overridden", lambda x: False)(name):
                fn = getattr(sock_file, name)
                op_signature = None
                if ops_type and name in ops_type.members:
                    member_type = ops_type.members[name].type_info

                    if member_type and member_type.get("kind") == "pointer":
                        op_signature = member_type.get("subtype")
                    else:
                        op_signature = member_type

                init_data[name] = yield from kffi.callback(fn, func_type=op_signature)

        return kffi.new("igloo_proto_ops", init_data)

    def register_anon_file(self, vfs_file: VFSFile, name: str = "[igloo_anon]") -> Generator[int, None, int]:
        """
        Injects a generic VFS anonymous inode into the guest process table.
        Returns the raw integer File Descriptor.
        """
        # Register locally instead of using the pseudofile tracker
        hf_id = self.register_dynamic_file(vfs_file)

        fops = yield from self._make_fops_struct(vfs_file)
        kffi = plugins.kffi

        init_data = {
            "name": name.encode("latin-1", errors="ignore"),
            "hf_id": hf_id,
            "ops": fops
        }

        req = kffi.new("struct portal_anonfs_create_req", init_data)
        req_bytes = bytes(req)

        # Assuming you added HYPER_OP_ANONFS_CREATE_FILE to hyper.consts.HYPER_OP
        fd = yield PortalCmd(hop.HYPER_OP_ANONFS_CREATE_FILE, 0, len(req_bytes), None, req_bytes)

        if fd is None or fd < 0:
            self.logger.error(
                f"Kernel rejected anon file creation for '{name}', code: {fd}")
            return -1

        self.logger.debug(f"Injected anon file '{name}' at FD {fd}")
        return fd

    def register_socket(self, sock_file: SocketFile) -> Generator[int, None, int]:
        """
        Injects a true kernel socket object into the guest process table.
        Returns the raw integer File Descriptor.
        """
        # Register locally instead of using the pseudofile tracker
        hf_id = self.register_dynamic_file(sock_file)

        pops = yield from self._make_proto_ops_struct(sock_file)
        kffi = plugins.kffi

        init_data = {
            "hf_id": hf_id,
            "family": getattr(sock_file, "DOMAIN", 0),
            "type": getattr(sock_file, "TYPE", 0),
            "protocol": getattr(sock_file, "PROTOCOL", 0),
            "ops": pops
        }

        req = kffi.new("struct portal_sockfs_create_req", init_data)
        req_bytes = bytes(req)

        # Assuming you added HYPER_OP_SOCKFS_CREATE_SOCKET to hyper.consts.HYPER_OP
        fd = yield PortalCmd(hop.HYPER_OP_SOCKFS_CREATE_SOCKET, 0, len(req_bytes), None, req_bytes)

        if fd is None or fd < 0:
            self.logger.error(f"Kernel rejected socket creation, code: {fd}")
            return -1

        self.logger.debug(f"Injected true socket at FD {fd}")
        return fd
