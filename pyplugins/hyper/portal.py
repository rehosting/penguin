"""
# Portal Plugin

This module implements the Portal plugin for the Penguin hypervisor environment. It provides a mechanism for plugins to communicate with the hypervisor and each other using memory-mapped regions and hypercalls. The Portal plugin manages command and data transfer, interrupt handling, and memory region state for efficient and flexible plugin communication.

## Usage

The Portal plugin is loaded by the Penguin framework and is not intended for direct invocation. It provides an API for other plugins to register interrupt handlers, queue interrupts, and send/receive commands via the portal mechanism.

### Example

```python
# Register an interrupt handler
portal.register_interrupt_handler("my_plugin", my_handler_fn)

# Queue an interrupt for a plugin
portal.queue_interrupt("my_plugin")
```

## Classes

- `PortalCmd`: Encapsulates a command to be sent through the portal mechanism.
- `Portal`: Main plugin class for handling portal communication and interrupts.

## Key Features

- Memory-mapped command and data transfer
- Plugin interrupt registration and handling
- Command construction and parsing utilities

"""

from penguin import plugins, Plugin
from collections.abc import Iterator
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import HYPER_OP as hop
from typing import Union, Callable, Optional, Any
import time
import struct
import functools

CURRENT_PID_NUM = 0xffffffff

kffi = plugins.kffi


class PortalCmd:
    """
    Encapsulates a command to be sent through the portal mechanism.

    This class centralizes the logic for constructing portal commands and
    reduces complexity in the _handle_output_cmd method.

    Attributes:
        op (int): Operation code from HYPER_OP constants.
        addr (int): Address field value.
        size (int): Size field value.
        pid (int): Process ID or CURRENT_PID_NUM for current process.
        data (Optional[bytes]): Optional data payload for the command.
    """

    def __init__(
        self,
        op: Union[int, str],
        addr: int = 0,
        size: int = 0,
        pid: Optional[int] = None,
        data: Optional[bytes] = None
    ) -> None:
        """
        Initialize a portal command.

        **Parameters:**
        - `op` (int | str): Operation code from HYPER_OP constants.
        - `addr` (int): Address field value.
        - `size` (int): Size field value.
        - `pid` (Optional[int]): Process ID or None for current process.
        - `data` (Optional[bytes]): Optional data payload for the command.

        **Returns:** None
        """
        op_num = None
        if isinstance(op, str):
            op_num = getattr(hop, f"HYPER_OP_{op.upper()}", None)
            if op is None:
                op_num = getattr(hop, op.upper(), None)
                if op_num is None:
                    raise ValueError(f"Invalid operation name: {op}")
        elif isinstance(op, int):
            op_num = op
        else:
            raise TypeError(f"Operation must be int or str, got {type(op)}")
        self.op = op_num or 0
        self.addr = addr or 0
        self.size = size if size is not None else (len(data) if data else 0)
        self.pid = pid or CURRENT_PID_NUM
        self.data = data

    @classmethod
    def none(cls) -> "PortalCmd":
        """
        Create a command representing no operation.

        **Returns:**
        - `PortalCmd`: A command with HYPER_OP_NONE operation.
        """
        return cls(hop.HYPER_OP_NONE, 0, 0, None, None)
    

class Portal(Plugin):
    """
    Portal is a plugin that manages communication and interrupts between plugins and the hypervisor.

    It provides methods for registering interrupt handlers, queuing interrupts, and reading/writing
    commands and data to memory-mapped regions.

    Attributes:
        outdir (str): Output directory for plugin data.
        endian_format (str): Endianness format character for struct operations.
        portal_interrupt (Optional[int]): Address of the portal interrupt.
        _interrupt_handlers (dict): Mapping of plugin names to their interrupt handler functions.
        _pending_interrupts (set): Set of plugin names with pending interrupts.
        regions_size (int): Size of the memory region.
    """

    def __init__(self) -> None:
        """
        Initialize the Portal plugin.

        - Sets up the output directory.
        - Registers memory region and portal interrupt handlers.
        - Initializes internal state for interrupt handling.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")
        # if self.get_arg_bool("verbose"):
            # self.logger.setLevel("DEBUG")
        # Set endianness format character for struct operations
        self.endian_format = '<' if self.panda.endianness == 'little' else '>'
        self.portal_interrupt = None
        # Generic interrupts mechanism
        self._interrupt_handlers = {}  # plugin_name -> handler_function
        self._pending_interrupts = set()  # Set of plugin names with pending work
        self.panda.hypercall(iconsts.IGLOO_HYPER_REGISTER_MEM_REGION)(
            self._register_cpu_memregion)
        self.panda.hypercall(iconsts.IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT)(
            self._register_portal_interrupt)
        # Don't wrap _portal_interrupt - it's not a generator function
        self.panda.hypercall(iconsts.IGLOO_HYPER_PORTAL_INTERRUPT)(
            self.wrap(self._portal_interrupt))

    def _register_portal_interrupt(self, cpu: Any) -> None:
        """
        Register the portal interrupt address for the current CPU.

        **Parameters:**
        - `cpu` (Any): CPU object.

        **Returns:** None
        """
        self.portal_interrupt = self.panda.arch.get_arg(
            cpu, 1, convention="syscall")
        assert self.panda.arch.get_arg(
            cpu, 2, convention="syscall") == 0

    def _portal_interrupt(self, cpu: Any) -> Iterator:
        """
        Handle portal interrupts and process pending items from registered plugins.

        **Parameters:**
        - `cpu` (Any): CPU object.

        **Yields:** None
        """
        # Process one item from each plugin that has pending interrupts
        interrupts = self._pending_interrupts.copy()
        self._pending_interrupts.clear()
        self._portal_clear_interrupt()
        for plugin_name in list(interrupts):
            if plugin_name in self._interrupt_handlers:
                handler_fn = self._interrupt_handlers[plugin_name]
                self.logger.debug(f"Processing interrupt for {plugin_name}")
                # Call handler function without any arguments
                # Plugin is responsible for tracking its own pending work
                yield from handler_fn()

    def register_interrupt_handler(self, plugin_name: str, handler_fn: Callable[[], Iterator]) -> None:
        """
        Register a plugin to handle portal interrupts.

        **Parameters:**
        - `plugin_name` (str): Name of the plugin.
        - `handler_fn` (Callable[[], Iterator]): Function to handle interrupts for this plugin.
          Must be a generator function that can be used with yield from.

        **Returns:** None
        """
        self.logger.debug(f"Registering interrupt handler for {plugin_name}")
        # The handler function should be a wrapped generator
        self._interrupt_handlers[plugin_name] = handler_fn
        if plugin_name in self._pending_interrupts:
            self.logger.debug(
                f"Plugin {plugin_name} already had pending interrupts")

    def queue_interrupt(self, plugin_name: str) -> bool:
        """
        Queue an interrupt for a plugin.

        **Parameters:**
        - `plugin_name` (str): Name of the plugin.

        **Returns:**
        - `bool`: True if queued successfully, False otherwise.
        """
        if plugin_name not in self._interrupt_handlers:
            self.logger.error(
                f"No interrupt handler registered for {plugin_name}")
            return False

        # Add plugin to pending set
        self._pending_interrupts.add(plugin_name)

        # Trigger an interrupt to process the item
        self._portal_set_interrupt()
        return True

    def _cleanup_all_interrupts(self) -> None:
        """
        Clean up all registered interrupt handlers and pending interrupts.

        **Returns:** None
        """
        self._interrupt_handlers = {}
        self._pending_interrupts = set()

    def _portal_set_interrupt_value(self, value: int) -> None:
        """
        Set the portal interrupt value in memory.

        **Parameters:**
        - `value` (int): Value to write to the portal interrupt address.

        **Returns:** None
        """
        if self.portal_interrupt:
            buf = struct.pack(f"{self.endian_format}Q", value)
            self.panda.virtual_memory_write(
                self.panda.get_cpu(), self.portal_interrupt, buf)

    def _portal_set_interrupt(self) -> None:
        """
        Set the portal interrupt to signal an event.

        **Returns:** None
        """
        self._portal_set_interrupt_value(1)

    def _portal_clear_interrupt(self) -> None:
        """
        Clear the portal interrupt.

        **Returns:** None
        """
        self._portal_set_interrupt_value(0)

    '''
    Our memregion is the first available memregion OR the one that is owned by us

    This can return none
    '''

    def _read_memregion_state(self, cpum: tuple) -> tuple:
        """
        Read the state of the memory region.

        **Parameters:**
        - `cpum` (tuple): Tuple of (cpu, cpu_memregion).

        **Returns:**
        - `(op, addr, size)`: Tuple of operation, address, and size.
        """
        cpu, cpu_memregion = cpum
        memr = kffi.read_type_panda(cpu, cpu_memregion, "region_header")
        self.logger.debug(
            f"Reading memregion state: op={memr.op}, addr={memr.addr:#x}, size={memr.size}")
        return memr.op, memr.addr, memr.size

    def _read_memregion_data(self, cpum: tuple, size: int) -> Optional[bytes]:
        """
        Read data from the memory region.

        **Parameters:**
        - `cpum` (tuple): Tuple of (cpu, cpu_memregion).
        - `size` (int): Number of bytes to read.

        **Returns:**
        - `Optional[bytes]`: Data read from the memory region, or None on error.
        """
        cpu, cpu_memregion = cpum
        if size > self.regions_size:
            self.logger.error(
                f"Size {size} exceeds chunk size {self.regions_size}")
            size = self.regions_size
        try:
            mem = self.panda.virtual_memory_read(
                cpu, cpu_memregion+kffi.sizeof("region_header"), size)
            return mem
        except ValueError as e:
            self.logger.error(f"Failed to read memory: {e}")

    def _write_memregion_state(
        self, cpum: tuple, op: int, addr: int, size: int, pid: Optional[int] = None
    ) -> None:
        """
        Write the state to the memory region.

        **Parameters:**
        - `cpum` (tuple): Tuple of (cpu, cpu_memregion).
        - `op` (int): Operation code.
        - `addr` (int): Address value.
        - `size` (int): Size value.
        - `pid` (Optional[int]): Process ID.

        **Returns:** None
        """
        cpu, cpu_memregion = cpum
        if size > self.regions_size:
            self.logger.error(
                f"Size {size} exceeds chunk size {self.regions_size}")
            size = self.regions_size
        if size < 0:
            self.logger.error(f"Size {size} is negative")
            size = 0
        if addr < 0:
            self.logger.debug(
                f"Address {addr} is negative. Converting to unsigned")
            mask = 0xFFFFFFFFFFFFFFFF if self.panda.bits == 64 else 0xFFFFFFFF
            addr = addr & mask

        self.logger.debug(
            f"Writing memregion state:  op={op}, addr={addr:#x}, size={size}")

        pid = pid or CURRENT_PID_NUM

        # mem = struct.pack("<QQQQ", op, addr, size, pid)
        mem = kffi.new("region_header")
        mem.op = op
        mem.addr = addr
        mem.size = size
        mem.pid = pid

        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion, mem.to_bytes())
        except ValueError as e:
            self.logger.error(f"Failed to write memregion state: {e}")

    def _write_memregion_data(self, cpum: tuple, data: bytes) -> None:
        """
        Write data to the memory region.

        **Parameters:**
        - `cpum` (tuple): Tuple of (cpu, cpu_memregion).
        - `data` (bytes): Data to write.

        **Returns:** None
        """
        cpu, cpu_memregion = cpum
        if len(data) > self.regions_size:
            self.logger.error(
                f"Data length {len(data)} exceeds chunk size {self.regions_size}")
            data = data[:self.regions_size]
        try:
            self.panda.virtual_memory_write(
                cpu, cpu_memregion+kffi.sizeof("region_header"), data)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion data: {e}")

    def _handle_input_state(self, cpum: tuple) -> Optional[tuple]:
        """
        Handle the input state from the memory region and process the operation.

        **Parameters:**
        - `cpum` (tuple): Tuple of (cpu, cpu_memregion).

        **Returns:**
        - `Optional[tuple]`: Operation and associated data, or None.
        """
        in_op = None
        op, addr, size = self._read_memregion_state(cpum)
        if op == hop.HYPER_OP_NONE:
            pass
        elif op & hop.HYPER_RESP_NONE == 0:
            self.logger.error(f"Invalid operation OP in return {op:#x}")
        elif op < hop.HYPER_RESP_NONE or op > hop.HYPER_RESP_MAX:
            self.logger.error(f"Invalid operation: {op:#x}")
        elif op == hop.HYPER_RESP_READ_OK:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpum, size)
            in_op = (op, data)
        elif op == hop.HYPER_RESP_READ_FAIL:
            self.logger.debug("Failed to read memory")
        elif op == hop.HYPER_RESP_READ_PARTIAL:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpum, size)
            in_op = (op, data)
        elif op == hop.HYPER_RESP_WRITE_OK:
            pass
        elif op == hop.HYPER_RESP_WRITE_FAIL:
            self.logger.debug("Failed to write memory")
            pass
        elif op == hop.HYPER_RESP_READ_NUM:
            in_op = (op, size)
        elif op == hop.HYPER_RESP_NONE:
            pass
        else:
            self.logger.error(f"Unknown operation: {op:#x}")
        return in_op
    
    def _write_portalcmd(self, cpum: tuple, cmd: PortalCmd) -> None:
        """
        Write a PortalCmd to the memory region.

        **Parameters:**
        - `cpum` (tuple): Tuple of (cpu, cpu_memregion).
        - `cmd` (PortalCmd): PortalCmd instance to write.

        **Returns:** None
        """
        self._write_memregion_state(cpum, cmd.op, cmd.addr, cmd.size, cmd.pid)
        if cmd.data:
            self._write_memregion_data(cpum, cmd.data)

    def wrap(self, f: Callable) -> Callable:
        """
        Wrap a function to manage portal command iteration and state.

        **Parameters:**
        - `f` (Callable): Function to wrap.

        **Returns:**
        - `Callable`: Wrapped function.
        """
        iterators = {}
        iteration_time = {}

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            cpu = self.panda.get_cpu()
            cpu_memregion = self.panda.arch.get_arg(cpu, 3, convention="syscall")
            cpum = cpu, cpu_memregion
            fn_return = None
            
            if cpu_memregion not in iterators or iterators[cpu_memregion] is None:
                self.logger.debug("Creating new iterator")
                # Revert to calling the original function f with self_
                fn_ret = f(*args, **kwargs)

                if not isinstance(fn_ret, Iterator):
                    return fn_ret

                iterators[cpu_memregion] = fn_ret
                iteration_time[cpu_memregion] = time.time()
                in_op = None
            else:
                in_op = self._handle_input_state(cpum)

            try:
                if not in_op:
                    cmd = next(iterators[cpu_memregion])
                elif in_op[0] == hop.HYPER_RESP_READ_OK:
                    cmd = iterators[cpu_memregion].send(in_op[1])
                elif in_op[0] == hop.HYPER_RESP_READ_NUM:
                    cmd = iterators[cpu_memregion].send(in_op[1])
                elif in_op[0] == hop.HYPER_RESP_READ_PARTIAL:
                    cmd = iterators[cpu_memregion].send(in_op[1])
                else:
                    iterators[cpu_memregion] = None
                    raise Exception(f"Invalid state cmd is {in_op}")
            except StopIteration as e:
                del iterators[cpu_memregion]
                # The function has completed, and we need to return the value
                fn_return = e.value
                cmd = PortalCmd.none()
            except Exception as e:
                self.logger.error(f"Error in portal iterator: {e}")
                cmd = e

            if type(cmd).__name__ == "PortalCmd":
                self._write_portalcmd(cpum, cmd)
            elif isinstance(cmd, Exception):
                self._write_portalcmd(cpum, PortalCmd.none())
                raise cmd
            elif cmd is not None:
                breakpoint()
                self.logger.error(f"Invalid return to portal: {type(cmd)} {cmd}")
            return fn_return
        return wrapper

    def _register_cpu_memregion(self, cpu: Any) -> None:
        """
        Register the memory region size for the current CPU.

        **Parameters:**
        - `cpu` (Any): CPU object.

        **Returns:** None
        """
        self.regions_size = self.panda.arch.get_arg(
            cpu, 1, convention="syscall")

    def uninit(self) -> None:
        """
        Clean up all interrupt handlers and pending interrupts on plugin unload.

        **Returns:** None
        """
        self._cleanup_all_interrupts()
