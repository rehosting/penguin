"""
# SendHypercall Plugin (`send_hypercall.py`) for Penguin

This module provides the `SendHypercall` plugin for the Penguin framework, enabling the registration and handling of custom hypercalls from the guest OS. It allows plugins to subscribe to specific hypercall events, receive arguments from the guest, process them, and return results back to the guest memory. The plugin is designed for extensibility and safe event-driven communication between guest and host.

## Features

- Register and handle custom hypercall events from the guest.
- Safely read arguments and write results to guest memory.
- Supports both string and bytes output.
- Handles architecture-specific pointer sizes and endianness.
- Provides error handling and logging for robust operation.

## Example Usage

```python
from penguin import plugins

def my_hypercall_handler(arg1, arg2):
    # Process arguments and return (retval, output)
    return 0, f"Received: {arg1}, {arg2}"

# Direct registration
plugins.send_hypercall.subscribe("mycmd", my_hypercall_handler)

# --- Decorator usage ---
@plugins.send_hypercall.subscribe("mycmd2")
def my_hypercall_handler2(arg1):
    # Process arguments and return (retval, output)
    return 0, f"Handled by decorator: {arg1}"

# You can also use a bound method as a decorator:
class MyPlugin:
    @plugins.send_hypercall.subscribe("mycmd3")
    def my_method(self, arg):
        return 0, f"Handled in class: {arg}"
```
"""

import struct
from penguin import Plugin, plugins
from typing import Callable, Union, Tuple, Dict, Any


class SendHypercall(Plugin):
    """
    ## SendHypercall Plugin

    Handles registration and processing of custom hypercall events from the guest OS.

    ### Attributes
    - `outdir` (`str`): Output directory for plugin data.
    - `registered_events` (`Dict[str, Callable[..., Tuple[int, Union[str, bytes]]]]`): Registered event handlers.
    """

    def __init__(self) -> None:
        """
        ### Initialize the SendHypercall plugin

        Sets up logging, event registration, and subscribes to the igloo_send_hypercall event.
        """
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("penguin_verbose"):
            self.logger.setLevel("DEBUG")
        self.registered_events: Dict[str, Callable[...,
                                                   Tuple[int, Union[str, bytes]]]] = {}
        plugins.subscribe(
            plugins.Events, "igloo_send_hypercall", self.on_send_hypercall)

    def subscribe(self, event: str,
                  callback: Callable[..., Tuple[int, Union[str, bytes]]] = None):
        """
        ### Register a callback for a specific hypercall event

        Can be used as a decorator or called directly.

        **Args:**
        - `event` (`str`): Event name to subscribe to.
        - `callback` (`Callable[..., Tuple[int, Union[str, bytes]]]`, optional): Callback function that processes the event.

        **Raises:**
        - `ValueError`: If already subscribed to the event.

        **Returns:**
        - If used as a decorator, returns the decorator function.
        - If called directly, returns `None`.
        """
        if callback is None:
            def decorator(cb):
                # Handle bound methods as in plugin_manager
                if event in self.registered_events:
                    raise ValueError(f"Already subscribed to event {event}")
                self.registered_events[event] = cb
                return cb
            return decorator

        # Handle bound methods as in plugin_manager
        if event in self.registered_events:
            raise ValueError(f"Already subscribed to event {event}")
        self.registered_events[event] = callback

    def on_send_hypercall(self, cpu: Any, buf_addr: int,
                          buf_num_ptrs: int) -> None:
        """
        ### Handle an incoming hypercall from the guest

        Reads arguments from guest memory, dispatches to the registered handler, and writes the result back.

        **Args:**
        - `cpu` (`Any`): CPU context from PANDA.
        - `buf_addr` (`int`): Address of the pointer array in guest memory.
        - `buf_num_ptrs` (`int`): Number of pointers in the array.

        **Returns:**
        - `None`
        """
        arch_bytes = self.panda.bits // 8

        # Read list of pointers
        buf_size = buf_num_ptrs * arch_bytes
        buf = self.panda.virtual_memory_read(
            cpu, buf_addr, buf_size, fmt="bytearray")

        # Unpack list of pointers
        word_char = "I" if arch_bytes == 4 else "Q"
        endianness = ">" if self.panda.arch_name in ["mips", "mips64"] else "<"
        ptrs = struct.unpack_from(
            f"{endianness}{buf_num_ptrs}{word_char}", buf)
        str_ptrs, out_addr = ptrs[:-1], ptrs[-1]

        # Read command and arg strings
        try:
            strs = [self.panda.read_str(cpu, ptr) for ptr in str_ptrs]
        except ValueError:
            self.logger.error("Failed to read guest memory. Skipping")
            return
        cmd, args = strs[0], strs[1:]

        # Simulate command
        cb = self.registered_events.get(cmd)
        if cb is None:
            self.logger.error(f"Unregistered send_hypercall command {cmd}")
            return

        # If cb is an unbound method, try to resolve the class and bind it
        if hasattr(cb, "__qualname__") and "." in cb.__qualname__ and not hasattr(
                cb, "__self__"):
            class_name = cb.__qualname__.split(".")[0]
            # Try to get the class instance from plugins singleton
            instance = getattr(plugins, class_name, None)
            if instance and hasattr(instance, cb.__name__):
                cb = getattr(instance, cb.__name__)

        try:
            ret_val, out = cb(*args)
        except Exception as e:
            self.logger.error(f"Exception while processing {cmd}:")
            self.logger.exception(e)
            return

        # Send output to guest
        out_bytes = out if isinstance(out, bytes) else out.encode()
        self.panda.virtual_memory_write(cpu, out_addr, out_bytes)
        self.panda.arch.set_retval(cpu, ret_val)
