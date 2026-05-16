from typing import Callable
from penguin import getColoredLogger


class QemuMemoryManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(QemuMemoryManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, panda=None):
        if hasattr(self, "_initialized"):
            return
        if panda is None:
            raise ValueError("QemuMemoryManager requires a panda instance")

        self.panda = panda
        self.ffi = panda.ffi
        self.libpanda = panda.libpanda
        self.logger = getColoredLogger("penguin.qemu_mem")

        # Symbols are now expected to be natively extracted by libpanda-ng.
        # We only add minimal fallback definitions if they are absolutely missing.
        self._ensure_minimal_cdefs()

        self.next_phys_addr = 0xFE000000
        self.regions = {}  # name -> state
        self.pending_allocations = []  # list of names to allocate

        # Register the after_machine_init callback to perform allocations
        @self.ffi.callback("void(struct CPUState *)")
        def _after_machine_init_cb(cpu):
            self._do_pending_allocations()

        self._machine_init_cb_anchor = _after_machine_init_cb
        self.panda.register_callback(
            self.panda.callback.after_machine_init,
            _after_machine_init_cb,
            "qemu_mem_allocator"
        )

        # Fallback callback (one-shot per registration)
        @self.ffi.callback("void(struct CPUState *, struct TranslationBlock *)")
        def _fallback_cb(cpu, tb):
            if self.pending_allocations:
                self._do_pending_allocations()

        self._fallback_cb_anchor = _fallback_cb
        self.panda.register_callback(
            self.panda.callback.before_block_exec,
            _fallback_cb,
            "qemu_mem_fallback_allocator"
        )

        self._initialized = True

    def _ensure_minimal_cdefs(self):
        """
        Registers minimal C definitions if missing from extracted types.
        """
        needed = ["MemoryRegion", "MemoryRegionOps", "hwaddr"]
        missing = []
        for t in needed:
            try:
                self.ffi.typeof(t)
            except self.ffi.error:
                missing.append(t)

        if not missing:
            return

        self.logger.debug(f"Adding missing QEMU types to FFI: {missing}")
        try:
            self.ffi.cdef("""
                typedef uint64_t hwaddr;
                typedef uint32_t MemTxResult;
                typedef uint64_t MemTxAttrs;
                
                typedef struct MemoryRegion MemoryRegion;

                typedef struct MemoryRegionOps {
                    uint64_t (*read)(void *opaque, hwaddr addr, unsigned size);
                    void (*write)(void *opaque, hwaddr addr, uint64_t data, unsigned size);
                    MemTxResult (*read_with_attrs)(void *opaque, hwaddr addr, uint64_t *data, unsigned size, MemTxAttrs attrs);
                    MemTxResult (*write_with_attrs)(void *opaque, hwaddr addr, uint64_t data, unsigned size, MemTxAttrs attrs);
                    int endianness;
                    struct {
                        unsigned min_access_size;
                        unsigned max_access_size;
                        bool unaligned;
                        bool (*accepts)(void *opaque, hwaddr addr, unsigned size, bool is_write, MemTxAttrs attrs);
                    } valid;
                    struct {
                        unsigned min_access_size;
                        unsigned max_access_size;
                        bool unaligned;
                    } impl;
                } MemoryRegionOps;

                void memory_region_init_io(MemoryRegion *mr, void *owner, const MemoryRegionOps *ops,
                                           void *opaque, const char *name, uint64_t size);
                void memory_region_add_subregion(MemoryRegion *mr, hwaddr offset, MemoryRegion *subregion);
                MemoryRegion *get_system_memory(void);

                void bql_lock_impl(const char *file, int line);
                void bql_unlock(void);
                bool bql_locked(void);
            """)
        except Exception:
            pass

    def _do_pending_allocations(self, cpu=None, tb=None):
        """
        Performs QEMU allocations.
        """
        if not self.pending_allocations:
            return

        # Attempt to acquire BQL. Symbols should be in libpanda or global.
        locked_here = False
        try:
            # Check multiple potential providers for BQL
            providers = [self.libpanda]
            try:
                providers.append(self.ffi.dlopen(None))
            except Exception:
                pass
                
            for lib in providers:
                try:
                    if hasattr(lib, "bql_locked") and not lib.bql_locked():
                        lib.bql_lock_impl(b"qemu_mem.py", 0)
                        locked_here = True
                        break
                except Exception:
                    continue
        except Exception as e:
            self.logger.debug(f"BQL orchestration error: {e}")

        try:
            while self.pending_allocations:
                name = self.pending_allocations.pop(0)
                state = self.regions[name]
                
                self.logger.info(f"Mapping native QEMU region '{name}' at 0x{state['phys_addr']:x}")

                try:
                    self.libpanda.memory_region_init_io(
                        state["mr_cdata"], self.ffi.NULL, state["ops_cdata"],
                        self.ffi.NULL, state["name_bytes"], state["size"]
                    )

                    sys_mem = self.libpanda.get_system_memory()
                    self.libpanda.memory_region_add_subregion(sys_mem, state["phys_addr"], state["mr_cdata"])
                    self.logger.info(f"Successfully mapped native QEMU region '{name}'")
                except Exception as e:
                    self.logger.error(f"Failed to allocate region '{name}': {e}")
        finally:
            if locked_here:
                try:
                    # Use same provider to unlock
                    for lib in providers:
                        try:
                            if hasattr(lib, "bql_unlock"):
                                lib.bql_unlock()
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

    def allocate_region(self, name: str, size: int,
                        read_cb: Callable, write_cb: Callable) -> int:
        """
        Registers a QEMU MemoryRegion to be allocated.
        Allocation is deferred until a safe point where BQL is held.
        """
        if name in self.regions:
            return self.regions[name]["phys_addr"]

        phys_addr = self.next_phys_addr
        self.next_phys_addr += size
        self.next_phys_addr = (self.next_phys_addr + 0xFFF) & ~0xFFF

        self.logger.info(
            f"Queuing native QEMU MemoryRegion '{name}' for allocation at "
            f"phys 0x{phys_addr:x} (size 0x{size:x})"
        )

        # 1. Wrap Python callbacks
        @self.ffi.callback("uint64_t(void *, hwaddr, unsigned)")
        def qemu_read(opaque, addr, size):
            try:
                return read_cb(int(addr), int(size))
            except Exception as e:
                self.logger.error(f"Error in QEMU mmap read callback: {e}")
                return 0

        @self.ffi.callback("void(void *, hwaddr, uint64_t, unsigned)")
        def qemu_write(opaque, addr, data, size):
            try:
                write_cb(int(addr), int(data), int(size))
            except Exception as e:
                self.logger.error(f"Error in QEMU mmap write callback: {e}")

        ops = self.ffi.new("MemoryRegionOps *")
        ops.read = qemu_read
        ops.write = qemu_write
        try:
            ops.endianness = self.libpanda.DEVICE_NATIVE_ENDIAN
        except AttributeError:
            ops.endianness = 0
        ops.impl.min_access_size = 1
        ops.impl.max_access_size = 8
        ops.valid.min_access_size = 1
        ops.valid.max_access_size = 8

        mr_buf = self.ffi.new("char[4096]")
        mr = self.ffi.cast("MemoryRegion *", mr_buf)

        state = {
            "phys_addr": phys_addr,
            "size": size,
            "name_bytes": name.encode('latin-1'),
            "callbacks": (qemu_read, qemu_write),
            "ops_cdata": ops,
            "mr_buf": mr_buf,
            "mr_cdata": mr
        }
        self.regions[name] = state
        self.pending_allocations.append(name)

        return phys_addr


# Global instance pointer, initialized by IGLOOPluginManager
manager: QemuMemoryManager = None
