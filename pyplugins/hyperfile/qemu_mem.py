from dataclasses import dataclass
from typing import Callable, Optional

from penguin import Plugin


PAGE_SIZE = 4096
DEFAULT_MMAP_BASE = 0xfe000000
DEFAULT_MMAP_SIZE = 16 * 1024 * 1024


@dataclass
class Allocation:
    name: str
    offset: int
    size: int
    storage: bytearray
    read_cb: Optional[Callable]
    write_cb: Optional[Callable]


def _parse_int(value, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        suffixes = {
            "k": 1024,
            "kb": 1024,
            "m": 1024 * 1024,
            "mb": 1024 * 1024,
            "g": 1024 * 1024 * 1024,
            "gb": 1024 * 1024 * 1024,
        }
        lowered = text.lower()
        for suffix, scale in suffixes.items():
            if lowered.endswith(suffix):
                return int(text[:-len(suffix)], 0) * scale
        return int(text, 0)
    raise ValueError(f"Unsupported integer value {value!r}")


def _align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _guest_byteorder(plugin) -> str:
    conf = getattr(getattr(plugin, "plugins", None), "args", {}).get("conf", {})
    arch = str(conf.get("core", {}).get("arch", "")).lower()
    if arch.endswith("eb") or arch.startswith(("powerpc", "ppc")):
        return "big"
    if arch:
        return "little"
    return getattr(plugin.panda, "endianness", "little")


class QemuMem(Plugin):
    """
    Native QEMU MMIO aperture used as a backing store for guest mmap() users.
    """

    def __init__(self):
        if not hasattr(self.panda, "set_after_guest_init_callback"):
            raise RuntimeError(
                "qemu_mem requires a QEMU compatibility backend with "
                "set_after_guest_init_callback; update the Penguin QEMU "
                "compat layer or disable native mmap users."
            )
        if not hasattr(self.panda, "ffi") or not hasattr(self.panda, "lib"):
            raise RuntimeError(
                "qemu_mem requires Penguin's QEMU CFFI backend; it cannot run "
                "on a PANDA-only backend."
            )
        if not hasattr(self.panda.lib, "penguin_qemu_add_mmio_region"):
            raise RuntimeError(
                "qemu_mem requires QEMU to export "
                "penguin_qemu_add_mmio_region; rebuild/install Penguin's "
                "QEMU package before enabling native mmap."
            )

        self.base = _parse_int(self.get_arg("mmap_base"), DEFAULT_MMAP_BASE)
        self.size = _parse_int(self.get_arg("mmap_size"), DEFAULT_MMAP_SIZE)
        self.alignment = _parse_int(self.get_arg("mmap_alignment"), PAGE_SIZE)
        self.byteorder = _guest_byteorder(self)
        if self.base % PAGE_SIZE:
            raise ValueError(
                f"qemu_mem mmap_base must be page aligned: 0x{self.base:x}"
            )
        if self.alignment <= 0 or self.alignment % PAGE_SIZE:
            raise ValueError(
                "qemu_mem mmap_alignment must be a positive page-aligned size: "
                f"{self.alignment}"
            )
        if self.size <= 0 or self.size % PAGE_SIZE:
            raise ValueError(
                "qemu_mem mmap_size must be a positive page-aligned size: "
                f"{self.size}"
            )

        self._used = 0
        self._allocations: list[Allocation] = []
        self._installed = False
        ffi = self.panda.ffi
        self._read_cb = ffi.callback(
            "uint64_t(uint64_t, unsigned, void *)"
        )(self._read)
        self._write_cb = ffi.callback(
            "void(uint64_t, uint64_t, unsigned, void *)"
        )(self._write)
        self.panda.set_after_guest_init_callback(self._after_guest_init)

    def allocate_region(
        self,
        name: str,
        size: int,
        read_cb=None,
        write_cb=None,
        initial=None,
    ) -> int:
        size = _align_up(max(int(size), 1), self.alignment)
        offset = _align_up(self._used, self.alignment)
        end = offset + size
        if end > self.size:
            raise RuntimeError(
                f"qemu_mem mmap aperture exhausted allocating {name!r}: "
                f"requested={size} used={self._used} limit={self.size}. "
                "Increase the aperture, for example:\n"
                "plugins:\n"
                "  qemu_mem:\n"
                "    mmap_size: 64M"
            )

        storage = bytearray(size)
        if initial:
            initial_bytes = bytes(initial)
            storage[:min(len(initial_bytes), size)] = initial_bytes[:size]

        self._used = end
        alloc = Allocation(name, offset, size, storage, read_cb, write_cb)
        self._allocations.append(alloc)
        self.logger.debug(
            "Allocated mmap region %s at 0x%x size=0x%x",
            name,
            self.base + offset,
            size,
        )
        return self.base + offset

    def allocate_file(self, file_model) -> int:
        if getattr(file_model, "_qemu_mem_phys_addr", 0):
            return file_model._qemu_mem_phys_addr

        size = int(getattr(file_model, "SIZE", 0) or PAGE_SIZE)
        initial = self._initial_data(file_model, size)
        name = getattr(
            file_model,
            "full_path",
            getattr(file_model, "PATH", "mmap"),
        )
        addr = self.allocate_region(
            name,
            size,
            read_cb=lambda offset, length: self._file_read(
                file_model,
                offset,
                length,
            ),
            write_cb=lambda offset, data: self._file_write(
                file_model,
                offset,
                data,
            ),
            initial=initial,
        )
        file_model._qemu_mem_phys_addr = addr
        file_model._qemu_mem_storage = self._allocation_for_addr(addr).storage
        return addr

    def _after_guest_init(self, _machine, _opaque):
        name = self.panda.ffi.new("char[]", b"penguin-mmap-aperture")
        ret = self.panda.lib.penguin_qemu_add_mmio_region(
            self.base,
            self.size,
            name,
            self._read_cb,
            self._write_cb,
            self.panda.ffi.NULL,
        )
        if ret != 0:
            self.logger.error(
                "Failed to install qemu_mem aperture at 0x%x size=0x%x",
                self.base,
                self.size,
            )
            return 1
        self._installed = True
        self.logger.info(
            "Installed qemu_mem mmap aperture at 0x%x size=0x%x",
            self.base,
            self.size,
        )
        return 0

    def _allocation_for_addr(self, addr: int) -> Allocation:
        relative = addr - self.base
        for alloc in self._allocations:
            if alloc.offset <= relative < alloc.offset + alloc.size:
                return alloc
        raise KeyError(f"No qemu_mem allocation owns address 0x{addr:x}")

    def _allocation_for_offset(self, offset: int) -> tuple[Allocation, int]:
        for alloc in self._allocations:
            if alloc.offset <= offset < alloc.offset + alloc.size:
                return alloc, offset - alloc.offset
        raise KeyError(
            f"No qemu_mem allocation owns aperture offset 0x{offset:x}"
        )

    def _read(self, addr, size, _opaque):
        try:
            alloc, file_offset = self._allocation_for_offset(int(addr))
            read_len = min(int(size), alloc.size - file_offset)
            if alloc.read_cb:
                data = alloc.read_cb(file_offset, read_len)
            else:
                data = bytes(
                    alloc.storage[file_offset:file_offset + read_len]
                )
            data = bytes(data or b"")[:read_len]
            if len(data) < read_len:
                data += b"\x00" * (read_len - len(data))
            self.logger.debug(
                "mmap read %s offset=0x%x size=%d",
                alloc.name,
                file_offset,
                read_len,
            )
            return int.from_bytes(
                data.ljust(int(size), b"\x00")[:int(size)],
                self.byteorder,
            )
        except Exception as exc:
            self.logger.error(
                "qemu_mem mmap read failed at offset 0x%x: %s",
                int(addr),
                exc,
            )
            return 0

    def _write(self, addr, data, size, _opaque):
        try:
            alloc, file_offset = self._allocation_for_offset(int(addr))
            write_len = min(int(size), alloc.size - file_offset)
            payload = int(data).to_bytes(int(size), self.byteorder)[:write_len]
            alloc.storage[file_offset:file_offset + write_len] = payload
            if alloc.write_cb:
                alloc.write_cb(file_offset, payload)
            self.logger.debug(
                "mmap write %s offset=0x%x size=%d",
                alloc.name,
                file_offset,
                write_len,
            )
        except Exception as exc:
            self.logger.error(
                "qemu_mem mmap write failed at offset 0x%x: %s",
                int(addr),
                exc,
            )

    def _initial_data(self, file_model, size: int) -> bytes:
        if hasattr(file_model, "_data"):
            data = file_model._data
            if isinstance(data, str):
                data = data.encode("utf-8")
            return bytes(data)[:size]
        if hasattr(file_model, "written_data"):
            return bytes(file_model.written_data)[:size]
        if hasattr(file_model, "data"):
            return bytes(file_model.data)[:size]
        return b""

    def _file_read(self, file_model, offset: int, length: int) -> bytes:
        storage = getattr(file_model, "_qemu_mem_storage")
        return bytes(storage[offset:offset + length])

    def _file_write(self, file_model, offset: int, data: bytes) -> None:
        storage = getattr(file_model, "_qemu_mem_storage")
        end = offset + len(data)
        storage[offset:end] = data
        if hasattr(file_model, "_data"):
            current_len = len(getattr(file_model, "_data", b""))
            file_model._data = bytes(storage[:max(current_len, end)])
            file_model.SIZE = max(
                getattr(file_model, "SIZE", 0),
                len(file_model._data),
            )
        if hasattr(file_model, "written_data"):
            previous = file_model.written_data[:offset]
            if len(previous) < offset:
                previous += b"\x00" * (offset - len(previous))
            file_model.written_data = (
                previous + data + file_model.written_data[end:]
            )
        if (
            hasattr(file_model, "data")
            and isinstance(file_model.data, bytearray)
        ):
            file_model.data[offset:end] = data
