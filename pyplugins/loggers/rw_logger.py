"""
# Read/Write Logger Plugin

This plugin records read and write system call events to the penguin database. It hooks into the system call
return events for `read` and `write`, extracts relevant details such as file descriptor, buffer content, and
process name, and stores them as `Read` and `Write` events in the database.

## Purpose

- Monitors file descriptor read and write operations in the guest.
- Records buffer contents, file descriptor names, and process names for each event.
- Enables later analysis of file I/O activity and data flow.

## Usage

Simply add this plugin by name to your config.

The plugin extracts relevant fields and stores them in the database using the `Read` and `Write` event types.
"""

from penguin import plugins, Plugin
from events.types import Read, Write


class RWLog(Plugin):
    """
    Plugin for logging read and write system call events to the database.

    Hooks into system call return events and records them as `Read` and `Write` events.
    """

    def __init__(self) -> None:
        """
        Initialize the RWLog plugin.

        - Sets up the output directory and database reference.
        - Registers hooks for `on_sys_write_return` and `on_sys_read_return` syscalls.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB

    @plugins.syscalls.syscall("on_sys_write_return")
    def write(self, regs, proto, syscall, fd, buf, count) -> None:
        """
        Callback for handling write syscall return events.

        **Parameters:**
        - `regs`: CPU registers at the time of the syscall.
        - `proto`: Protocol or plugin-specific context.
        - `syscall`: Syscall number or identifier.
        - `fd`: File descriptor being written to.
        - `buf`: Buffer address containing data written.
        - `count`: Number of bytes written.

        Reads the buffer content, resolves the file descriptor name and process name,
        and records the event in the database as a `Write` event.

        **Returns:** None
        """
        rv = syscall.retval
        s = yield from plugins.mem.read_bytes(buf, size=rv)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = (yield from plugins.portal.get_fd_name(fd)) or "?"
        args = yield from plugins.portal.get_args()
        if args:
            procname = args[0]
        else:
            procname = "[???]"
        self.DB.add_event(
            Write(
                procname=procname,
                fd=signed_fd,
                fname=fname,
                buffer=s,
            )
        )

    @plugins.syscalls.syscall("on_sys_read_return")
    def read(self, regs, proto, syscall, fd, buf, count) -> None:
        """
        Callback for handling read syscall return events.

        **Parameters:**
        - `proto`: Protocol or plugin-specific context.
        - `syscall`: Syscall number or identifier.
        - `fd`: File descriptor being read from.
        - `buf`: Buffer address containing data read.
        - `count`: Number of bytes read.

        Reads the buffer content, resolves the file descriptor name and process name,
        and records the event in the database as a `Read` event.

        **Returns:** None
        """
        rv = syscall.retval
        if rv < 0:
            rv = count
        s = yield from plugins.mem.read_bytes(buf, rv)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = (yield from plugins.portal.get_fd_name(fd)) or "?"
        # Get name of FD, if it's valid
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        args = yield from plugins.osi.get_args()
        if args:
            procname = args[0]
        else:
            procname = "[???]"
        self.DB.add_event(
            Read(
                procname=procname,
                fd=signed_fd,
                fname=fname,
                buffer=s,
            )
        )
