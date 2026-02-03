from typing import Union
from penguin import plugins
from wrappers.ptregs_wrap import PtRegsWrapper
import os

class ReadBufWrapper:
    '''
    The Logic Mixin: Consumes 'buffer' to set up the buffer.
    '''
    def __init__(self, *, buffer: Union[bytes, str] = None, cycle: bool = False, **kwargs):
        self._cycle = cycle
        if buffer is not None:
            self._data = buffer
        else:
            # If buffer is None, default to empty bytes instead of raising an exception immediately,
            # unless you strictly require it. This handles cases where a mixin chain might 
            # initialize it differently, or if we want a safe default.
            # However, based on your request for "const_buf", we'll initialize it safely.
            self._data = b"" 
            
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        """
        Reads data once, respecting offset and size.
        Returns 0 if offset is beyond the data.
        """
        if isinstance(self._data, bytes):
            data_bytes = self._data
        else:
            data_bytes = self._data.encode("utf-8")
        data_len = len(data_bytes)
        offset = yield from plugins.mem.read_int(loff)

        # Check for cycling
        cycle = getattr(self, "_cycle", False)

        if size <= 0 or offset < 0 or (not cycle and offset >= data_len):
            ptregs.set_retval(0)
            return

        if not cycle:
            chunk = min(size, data_len - offset)
            yield from plugins.mem.write_bytes(user_buf, data_bytes[offset:offset + chunk])
            yield from plugins.mem.write_int(loff, offset + chunk)
            ptregs.set_retval(chunk)
        else:
            # Cycle: repeat buffer forever, write the requested size in one go
            if data_len == 0:
                ptregs.set_retval(0)
                return
            pos = offset % data_len
            # Build the output by repeating the buffer as needed
            full_repeats = (size + data_len - 1 - pos) // data_len
            end_pos = (pos + size) % data_len
            if end_pos > pos:
                chunk = data_bytes[pos:end_pos]
            else:
                chunk = data_bytes[pos:] + data_bytes * (full_repeats - 1) + data_bytes[:end_pos]
            chunk = chunk[:size]  # Ensure exact size
            yield from plugins.mem.write_bytes(user_buf, chunk)
            yield from plugins.mem.write_int(loff, offset + size)
            ptregs.set_retval(size)


class ReadConstBuf(ReadBufWrapper):
    '''
    The Translator: Takes 'buffer' or 'const_buf'
    '''
    def __init__(self, *, const_buf: str = None, buffer: str = None, **kwargs):
        self.cycle = False
        # Support both argument names
        buf = const_buf if const_buf is not None else buffer
        super().__init__(buffer=buf, **kwargs)


class ReadEmpty(ReadBufWrapper):
    '''
    The Preset: Hardcodes the data.
    '''
    def __init__(self, **kwargs):
        # Just inject the hardcoded value
        super().__init__(buffer="", **kwargs)

class ReadZero(ReadBufWrapper):
    '''
    The Preset: Hardcodes the data.
    '''
    def __init__(self, **kwargs):
        # Just inject the hardcoded value
        super().__init__(buffer="0", **kwargs)

class ReadDefault:
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        ptregs.set_retval(-22)

class ReadFromFile:
    '''
    The Loader: Takes 'read_filepath' or 'filename', loads it.
    '''
    def __init__(self, *, read_filepath: str = None, filename: str = None, **kwargs):
        self.filename = read_filepath if read_filepath is not None else filename
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        offset = yield from plugins.mem.read_int(loff)
        fname = self.filename
        if fname is None:
            ptregs.set_retval(0)
            return
        if not os.path.isabs(fname):
            # Paths are relative to cwd or caller will resolve relative path
            fpath = fname
        else:
            fpath = fname
        try:
            with open(fpath, "rb") as f:
                f.seek(offset)
                chunk = f.read(size)
        except Exception:
            chunk = b""
        yield from plugins.mem.write_bytes(user_buf, chunk)
        yield from plugins.mem.write_int(loff, offset + len(chunk))
        ptregs.set_retval(len(chunk))

class ReadConstMap(ReadBufWrapper):
    '''
    Reads a sparse map of offsets to values, with optional padding and size.
    '''
    def __init__(self, *, vals=None, pad: Union[str, int, bytes]=b"\x00", size: int=0x10000, **kwargs):
        self.vals = vals or {}
        # Normalize pad to bytes
        if isinstance(pad, str):
            self.pad = pad.encode()
        elif isinstance(pad, int):
            self.pad = bytes([pad])
        else:
            self.pad = pad
        self.size = size
        # Render the buffer once at init
        data = self._render_file()
        super().__init__(buffer=data, **kwargs)

    def _render_file(self):
        # sort vals dict by key, lowest to highest
        vals = {
            k: v for k, v in sorted(self.vals.items(), key=lambda item: item[0])
        }
        data = b""
        for off, val in vals.items():
            # Accept str, bytes, list[int], or list[str]
            if isinstance(val, str):
                val = val.encode()
            elif isinstance(val, list):
                if not len(val):
                    continue
                first_val = val[0]
                if isinstance(first_val, int):
                    val = bytes(val)
                elif isinstance(first_val, str):
                    val = b"\x00".join([x.encode() for x in val])
                else:
                    raise ValueError("const_map: list values must be int or str")
            elif isinstance(val, bytes):
                pass
            else:
                raise ValueError("const_map: vals must be str, bytes, or list")
            # Pad before this value, then add the value
            data += self.pad * (off - len(data)) + val
        # Pad up to size
        assert len(data) <= self.size, f"Data is too long: {len(data)} > size {self.size}"
        data += self.pad * (self.size - len(data))
        return data

class ReadConstMapFile(ReadConstMap):
    '''
    Like ReadConstMap, but persists the buffer to a file and reads from it.
    '''
    def __init__(self, *, filename, vals=None, pad: Union[str, int, bytes]=b"\x00", size: int=0x10000, **kwargs):
        self.filename = filename
        self.vals = vals or {}
        # Normalize pad to bytes
        if isinstance(pad, str):
            self.pad = pad.encode()
        elif isinstance(pad, int):
            self.pad = bytes([pad])
        else:
            self.pad = pad
        self.size = size
        # Create file if it doesn't exist
        if not os.path.isabs(self.filename):
            # Assume cwd or caller will resolve relative path
            fpath = self.filename
        else:
            fpath = self.filename
        if not os.path.isfile(fpath):
            data = self._render_file()
            with open(fpath, "wb") as f:
                f.write(data)
        super().__init__(vals=vals, pad=pad, size=size, **kwargs)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        offset = yield from plugins.mem.read_int(loff)
        # Read from file
        with open(self.filename, "rb") as f:
            f.seek(offset)
            chunk = f.read(size)
        yield from plugins.mem.write_bytes(user_buf, chunk)
        yield from plugins.mem.write_int(loff, offset + len(chunk))
        ptregs.set_retval(len(chunk))

class ReadCycle(ReadBufWrapper):
    '''
    Like ReadBufWrapper, but cycles the buffer forever.
    '''
    def __init__(self, *, buffer: Union[bytes, str] = None, **kwargs):
        super().__init__(buffer=buffer, cycle=True, **kwargs)

class ReadZeroCycle(ReadCycle):
    '''
    Cycles "0" forever.
    '''
    def __init__(self, **kwargs):
        super().__init__(buffer="0", **kwargs)

class ReadOneCycle(ReadCycle):
    '''
    Cycles "1" forever.
    '''
    def __init__(self, **kwargs):
        super().__init__(buffer="1", **kwargs)

class ReadConstBufCycle(ReadCycle):
    '''
    Cycles a constant buffer forever.
    '''
    def __init__(self, *, buffer: str = None, **kwargs):
        super().__init__(buffer=buffer, **kwargs)

class ReadExternalVFS:
    """
    Modern Adapter: Calls a plugin function with the standard VFS signature.
    func(ptregs, file, user_buf, size, loff) -> Generator
    """
    def __init__(self, *, read_plugin: str = None, read_function: str = "read", **kwargs):
        self._func = getattr(getattr(plugins, read_plugin), read_function)
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        yield from self._func(ptregs, file, user_buf, size, loff)

class ReadExternalLegacy:
    """
    Legacy Adapter: Adapts the old synchronous/complex return signature to VFS.
    func(self, filename, user_buf, size, offset, details=kwargs) -> (data, retval)
    """
    def __init__(self, *, read_plugin: str = None, read_function: str = "read", **kwargs):
        self._func = getattr(getattr(plugins, read_plugin), read_function)
        self._legacy_kwargs = kwargs.copy() # Capture extra args for 'details'
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        offset = yield from plugins.mem.read_int(loff)
        
        # Call the legacy function
        # Note: We pass 'self' as the first arg because legacy plugins expected the file instance
        # self.full_path comes from BaseFile via composition
        filename = getattr(self, "full_path", "unknown")
        
        val = yield from self._func(self, filename, user_buf, size, offset, details=self._legacy_kwargs)

        # Handle the polymorphic return types of the old system
        retval = 0
        write_data = b""

        if isinstance(val, tuple) and len(val) == 2:
            write_data, retval = val
        elif isinstance(val, int):
            retval = val
        elif isinstance(val, (bytes, str)):
            write_data = val
            retval = len(val)
        
        if write_data:
            if isinstance(write_data, str):
                write_data = write_data.encode("utf-8")
            yield from plugins.mem.write_bytes(user_buf, write_data)
            yield from plugins.mem.write_int(loff, offset + len(write_data))
        
        ptregs.set_retval(retval)