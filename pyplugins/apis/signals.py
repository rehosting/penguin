"""
Signals Plugin (signals.py) for Penguin
=======================================

This module provides the Signals plugin for the Penguin framework, enabling the triggering of core dumps, crash snapshots, and custom signals in the guest OS via the hypervisor portal. It is useful for debugging, analysis, and automation of guest process state.

Features
--------

- Trigger a full snapshot and core dump in the guest.
- Send SIGABRT or custom signals to the current process in the guest.
- Coroutine-based API for integration with other Penguin plugins.

Example Usage
-------------

.. code-block:: python

    from penguin import plugins

    # Trigger a full snapshot and core dump
    pid = yield from plugins.signals.crash_snapshot()

    # Send SIGABRT to the current process
    pid = yield from plugins.signals.self_abort()

    # Send a custom signal
    pid = yield from plugins.signals.self_signal("SIGTERM")
"""

from penguin import Plugin
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from typing import Optional, Generator, Any


# Values taken from man signal(7)
#
# Alpha/SPARC and PA-RISC have their own cases for signal numbers,
# so those need to be added to this table if PENGUIUN ever supports those.
SIGNAL_NAMES = dict(
    SIGHUP=dict(default=1, mips=1),
    SIGINT=dict(default=2, mips=2),
    SIGQUIT=dict(default=3, mips=3),
    SIGILL=dict(default=4, mips=4),
    SIGTRAP=dict(default=5, mips=5),
    SIGABRT=dict(default=6, mips=6),
    SIGIOT=dict(default=6, mips=6),
    SIGBUS=dict(default=7, mips=10),
    SIGEMT=dict(mips=7),
    SIGFPE=dict(default=8, mips=8),
    SIGKILL=dict(default=9, mips=9),
    SIGUSR1=dict(default=10, mips=16),
    SIGSEGV=dict(default=11, mips=11),
    SIGUSR2=dict(default=12, mips=17),
    SIGPIPE=dict(default=13, mips=13),
    SIGALRM=dict(default=14, mips=14),
    SIGTERM=dict(default=15, mips=15),
    SIGSTKFLT=dict(default=16),
    SIGCHLD=dict(default=17, mips=18),
    SIGCLD=dict(mips=18),
    SIGCONT=dict(default=18, mips=25),
    SIGSTOP=dict(default=19, mips=23),
    SIGTSTP=dict(default=20, mips=24),
    SIGTTIN=dict(default=21, mips=26),
    SIGTTOU=dict(default=22, mips=27),
    SIGURG=dict(default=23, mips=21),
    SIGXCPU=dict(default=24, mips=30),
    SIGXFSZ=dict(default=25, mips=31),
    SIGVTALRM=dict(default=26, mips=28),
    SIGPROF=dict(default=27, mips=29),
    SIGWINCH=dict(default=28, mips=20),
    SIGIO=dict(default=29, mips=22),
    SIGPOLL=dict(default=29, mips=22),
    SIGPWR=dict(default=30, mips=19),
    SIGSYS=dict(default=31, mips=12),
    SIGUNUSED=dict(default=31),
)


class Signals(Plugin):
    """
    Signals Plugin
    ==============

    Provides methods to trigger core dumps, crash snapshots, and send signals to guest processes via the hypervisor portal.
    """

    def dump(self, mode: int = 0,
             signal: int = 0) -> Generator[Any, None, Optional[int]]:
        """
        Trigger a core dump or signal in the guest.

        Parameters
        ----------
        mode : int, optional
            Dump mode (0=full snapshot and coredump, 1=self abort, 2=custom signal). Default is 0.
        signal : int, optional
            Signal number to send (only used with mode=2). Default is 0.

        Returns
        -------
        Optional[int]
            PID of the process that received the signal, or error code, or None on failure.
        """
        # mode in lowest 8 bits, signal in next 8 bits
        dump_addr = ((signal & 0xFF) << 8) | (mode & 0xFF)
        response = yield PortalCmd(hop.HYPER_OP_DUMP, dump_addr, 0)
        if response is None:
            self.logger.error("Failed to execute dump operation")
            return None
        return response

    def crash_snapshot(self) -> Generator[Any, None, Optional[int]]:
        """
        Create a snapshot and core dump in the guest (default dump mode).

        Returns
        -------
        Optional[int]
            PID of the process that received the signal, or error code, or None on failure.
        """
        return (yield from self.dump(mode=0))

    def self_abort(self) -> Generator[Any, None, Optional[int]]:
        """
        Send SIGABRT to the current process in the guest.

        Returns
        -------
        Optional[int]
            PID of the process that received SIGABRT, or error code, or None on failure.
        """
        return (yield from self.dump(mode=1))

    def signal_name_to_num(self, name: str) -> Optional[int]:
        arch = self.get_arg("conf")["core"]["arch"]
        arch_case = "mips" if "mips" in arch else "default"
        try:
            return SIGNAL_NAMES[name][arch_case]
        except KeyError:
            return None

    def self_signal(self, signal: int | str) -> Generator[Any, None, Optional[int]]:
        """
        Send a custom signal to the current process in the guest.

        Parameters
        ----------
        signal : int
            Signal number (1-31) or name to send.

        Returns
        -------
        Optional[int]
            PID of the process that received the signal, or error code, or None on failure.

        Raises
        ------
        ValueError
            If the signal number is not between 1 and 31 or the signal name is unrecognized.
        """
        if isinstance(signal, str):
            signal = self.signal_name_to_num(signal)
            if signal is None:
                raise ValueError("Signal name not recognized.")
        if not 1 <= signal <= 31:
            raise ValueError(
                f"Invalid signal number: {signal}. Must be between 1 and 31.")
        return (yield from self.dump(mode=2, signal=signal))
