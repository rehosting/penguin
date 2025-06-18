import struct
from penguin import Plugin, plugins
from typing import Callable, Union, Tuple


class SendHypercall(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        self.registered_events = {}
        plugins.subscribe(
            plugins.Events, "igloo_send_hypercall", self.on_send_hypercall)

    def subscribe(self, event, callback: Callable[..., Tuple[int, Union[str, bytes]]]):
        if event in self.registered_events:
            raise ValueError(f"Already subscribed to event {event}")
        self.registered_events[event] = callback

    def on_send_hypercall(self, cpu, buf_addr: int, buf_num_ptrs: int):
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
        if cmd not in self.registered_events:
            self.logger.error(f"Unregistered send_hypercall command {cmd}")
        try:
            ret_val, out = self.registered_events[cmd](*args)
        except Exception as e:
            self.logger.error(f"Exception while processing {cmd}:")
            self.logger.exception(e)
            return

        # Send output to guest
        # assert len(out_str) < 0x1000
        out_bytes = out if isinstance(out, bytes) else out.encode()
        self.panda.virtual_memory_write(cpu, out_addr, out_bytes)
        self.panda.arch.set_retval(cpu, ret_val)
