import os
import re
from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop

class MTD(Plugin):
    def __init__(self):
        self.config = self.get_arg("devices") or {}
        self.internal_devices = self._validate_and_build(self.config)
        
        # Registry for open file handles: { mtd_id: file_object }
        self._handles = {}
        
        # Registry to keep CFFI callbacks alive (prevent Garbage Collection)
        self._c_callbacks = [] 
        self._cb_ptrs = {} # { 'read': int_addr, ... }
        
        if self.internal_devices:
            plugins.portal.register_interrupt_handler(
                "mtd", self._mtd_interrupt_handler)
            plugins.portal.queue_interrupt("mtd")

    # -------------------------------------------------------------------------
    # Guest -> Host Callbacks
    # -------------------------------------------------------------------------

    def _mtd_read(self, mtd_id, offset, length, buf_ptr):
        """Called by Guest Kernel to read data from Host file."""
        f = self._handles.get(mtd_id)
        if not f:
            return -19 # -ENODEV
            
        try:
            f.seek(offset)
            data = f.read(length)
            read_len = len(data)
            
            # Copy data from Python bytes -> Guest Memory Pointer
            plugins.kffi.memmove(buf_ptr, data, read_len)
            
            # If we hit EOF, pad the rest with 0xFF (Simulate Erased Flash)
            if read_len < length:
                pad_len = length - read_len
                pad_ptr = buf_ptr + read_len
                pad = b'\xff' * pad_len
                plugins.kffi.memmove(pad_ptr, pad, pad_len)
                
            return 0 # Success
        except Exception as e:
            self.logger.error(f"MTD Read Error (ID {mtd_id}): {e}")
            return -5 # -EIO

    def _mtd_write(self, mtd_id, offset, length, buf_ptr):
        """Called by Guest Kernel to write data to Host file."""
        f = self._handles.get(mtd_id)
        if not f:
            return -19
            
        try:
            # Read data from Guest Memory Pointer -> Python bytes
            # kffi.buffer creates a view, [:] copies it to bytes
            data = plugins.kffi.buffer(buf_ptr, length)[:]
            
            f.seek(offset)
            f.write(data)
            return 0
        except Exception as e:
            self.logger.error(f"MTD Write Error (ID {mtd_id}): {e}")
            return -5

    def _mtd_erase(self, mtd_id, offset, length):
        """Called by Guest Kernel to erase a block."""
        f = self._handles.get(mtd_id)
        if not f:
            return -19

        try:
            # Simulate erase by writing 0xFFs to the file
            f.seek(offset)
            f.write(b'\xff' * length)
            return 0
        except Exception as e:
            self.logger.error(f"MTD Erase Error (ID {mtd_id}): {e}")
            return -5

    # -------------------------------------------------------------------------
    # Initialization Logic
    # -------------------------------------------------------------------------

    def _mtd_interrupt_handler(self):
        return self._setup_hardware()

    def _setup_hardware(self):
        self.logger.info("Initializing MTD Subsystem...")

        # 1. Initialize Callbacks
        # We must create these once and store references, otherwise CFFI
        # destroys the callback stub and the kernel crashes on invocation.
        kffi = plugins.kffi
        cb_read  = yield from kffi.callback(self._mtd_read)
        cb_write = yield from kffi.callback(self._mtd_write)
        cb_erase = yield from kffi.callback(self._mtd_erase)
        
        self._c_callbacks = [cb_read, cb_write, cb_erase]
        
        # Cache the integer addresses to pass to the struct
        self._cb_ptrs = {
            'read': cb_read,
            'write': cb_write,
            'erase': cb_erase
        }

        # 2. Scorched Earth (Nuke existing MTDs)
        yield from self._cmd_nuke()

        # 3. Create Devices
        for dev in self.internal_devices:
            yield from self._cmd_create(dev)

        self.logger.info(f"MTD Subsystem Ready. {len(self.internal_devices)} devices created.")

    def _cmd_nuke(self):
        kffi = plugins.kffi
        req = kffi.new("struct portal_mtd_nuke_req")
        req.max_scan_index = 64
        req_bytes = req.to_bytes()
        
        result = yield PortalCmd(hop.HYPER_OP_MTD_NUKE, 0, len(req_bytes), None, req_bytes)
        
        if result is None:
            self.logger.error("MTD Nuke command failed (IPC error)")
        else:
            self.logger.info(f"MTD Nuke complete. Removed {result} devices.")

    def _cmd_create(self, dev):
        kffi = plugins.kffi
        req = kffi.new("struct portal_mtd_create_req")

        # --- 1. Basic Metadata ---
        label_bytes = dev['name'].encode('utf-8')[:63]
        for i, b in enumerate(label_bytes): req.label[i] = b
            
        req.total_size = dev['total_size']
        req.erase_size = dev['geometry']['erase_size']
        req.write_size = dev['geometry']['write_size']
        req.oob_size   = dev['geometry']['oob_size']
        req.is_nand    = 1 if dev['geometry']['type'] == 'nand' else 0
        
        # --- 2. Mode Selection ---
        f_handle = None
        
        if dev['model'] == 'zeros':
            req.mode = 0 # RAM Mode
            req.cb_read_ptr = 0
            req.cb_write_ptr = 0
            req.cb_erase_ptr = 0
            # Callbacks are ignored in this mode
        else:
            req.mode = 1 # Callback Mode
            req.cb_read_ptr  = self._cb_ptrs['read']
            req.cb_write_ptr = self._cb_ptrs['write']
            req.cb_erase_ptr = self._cb_ptrs['erase']
            
            # Prepare file handle
            try:
                # Open with rb+ for Read/Write, rb for Read-Only
                mode_str = "rb" if dev.get('mode') == 'ro' else "rb+"
                f_handle = open(dev['backing_path'], mode_str)
            except Exception as e:
                self.logger.error(f"Failed to open backing file {dev['backing_path']}: {e}")
                return # Skip this device

        # --- 3. Send Command ---
        req_bytes = req.to_bytes()
        
        result_id = yield PortalCmd(hop.HYPER_OP_MTD_CREATE, 0, len(req_bytes), None, req_bytes)

        if result_id is None or result_id < 0:
            self.logger.error(f"Failed to create MTD device '{dev['name']}'")
            if f_handle: f_handle.close()
        else:
            self.logger.info(f"Created MTD device '{dev['name']}' as mtd{result_id}")
            # Map the returned ID to the file handle for the callbacks to use
            if f_handle:
                self._handles[result_id] = f_handle

    # --- Utility Methods ---

    def _parse_size(self, size_input):
        if isinstance(size_input, int): return size_input
        units = {"k": 1024, "m": 1024**2, "g": 1024**3}
        match = re.match(r"(\d+)([kmgKMG]?)", str(size_input))
        if not match: raise ValueError(f"Invalid size format: {size_input}")
        number, unit = match.groups()
        return int(number) * units.get(unit.lower(), 1)

    def _get_personality_defaults(self, p_type):
        if p_type == "nand":
            return {"type": "nand", "erase_size": 131072, "write_size": 2048, "oob_size": 64}
        elif p_type == "nor":
            return {"type": "nor", "erase_size": 65536, "write_size": 1, "oob_size": 0}
        return {}

    def _validate_and_build(self, raw_devices):
        device_list = []
        used_ids = set()
        
        # --- Pass 1: Reserve Explicit IDs ---
        for name, dev in raw_devices.items():
            if "id" in dev:
                did = int(dev["id"])
                if did in used_ids:
                    raise ValueError(f"Duplicate device ID explicitly defined: {did} (device: '{name}')")
                used_ids.add(did)

        # --- Pass 2: Assign Missing IDs Alphabetically ---
        resolved_configs = []
        next_candidate_id = 0
        
        for name in sorted(raw_devices.keys()):
            dev = raw_devices[name]
            
            if "id" in dev:
                final_id = int(dev["id"])
            else:
                while next_candidate_id in used_ids:
                    next_candidate_id += 1
                final_id = next_candidate_id
                used_ids.add(final_id)
            
            resolved_configs.append((name, final_id, dev))

        # --- Pass 3: Build Device Nodes ---
        for name, dev_id, dev in resolved_configs:
            
            model = dev.get("model")
            final_size = 0
            backing_path = None

            if model == "backing_file":
                backing_path = dev.get("backing_file")
                if not backing_path:
                    raise ValueError(f"Device '{name}' (backing_file) missing 'backing_file' path")
                
                backing_path = os.path.abspath(os.path.expanduser(backing_path))
                if not os.path.exists(backing_path):
                    raise FileNotFoundError(f"File not found: {backing_path}")
                
                final_size = os.path.getsize(backing_path)
            
            elif model == "zeros":
                if "size" in dev:
                    final_size = self._parse_size(dev["size"])
                else:
                    # Pick a reasonable default based on the intended technology
                    # NAND defaults to 256MB, NOR defaults to 16MB
                    p_type_guess = dev.get("personality", {}).get("type", "nand")
                    if p_type_guess == "nor":
                        final_size = 16 * 1024 * 1024 # 16MB
                    else:
                        final_size = 256 * 1024 * 1024 # 256MB
            
            else:
                raise ValueError(f"Unknown model type '{model}' for device '{name}'")

            # Personality & Geometry
            raw_pers = dev.get("personality", {})
            p_type = raw_pers.get("type", "nand")
            personality = self._get_personality_defaults(p_type)
            
            if "erase_size" in raw_pers:
                personality["erase_size"] = self._parse_size(raw_pers["erase_size"])
            if "write_size" in raw_pers:
                personality["write_size"] = self._parse_size(raw_pers["write_size"])
            if "oob_size" in raw_pers:
                personality["oob_size"] = int(raw_pers["oob_size"])

            device_list.append({
                "name": name,
                "id": dev_id,
                "model": model,
                "mode": dev.get("mode", "rw"),
                "total_size": final_size,
                "backing_path": backing_path,
                "geometry": personality
            })

        device_list.sort(key=lambda x: x["id"])
        
        return device_list