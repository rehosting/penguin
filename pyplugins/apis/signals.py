from penguin import Plugin 
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd


class Signals(Plugin):
    def dump(self, mode=0, signal=0):
        """
        Trigger a core dump in the guest.

        Args:
            mode (int): Dump mode (0=full snapshot and coredump, 1=self abort, 2=custom signal)
            signal (int): Signal number to send (only used with mode=2)

        Returns:
            int: PID of the process that received the signal, or error code
        """
        # mode in lowest 8 bits, signal in next 8 bits
        dump_addr = ((signal & 0xFF) << 8) | (mode & 0xFF)
        response = yield PortalCmd(hop.HYPER_OP_DUMP, dump_addr, 0)
        if response is None:
            self.logger.error("Failed to execute dump operation")
            return None
        return response

    def crash_snapshot(self):
        """
        Create a snapshot and core dump in the guest (default dump mode).

        Returns:
            int: PID of the process that received the signal, or error code
        """
        return (yield from self.dump(mode=0))

    def self_abort(self):
        """
        Send SIGABRT to the current process in the guest.

        Returns:
            int: PID of the process that received SIGABRT, or error code
        """
        return (yield from self.dump(mode=1))

    def self_signal(self, signal):
        """
        Send a custom signal to the current process in the guest.

        Args:
            signal (int): Signal number to send (1-31)

        Returns:
            int: PID of the process that received the signal, or error code
        """
        if not 1 <= signal <= 31:
            raise ValueError(
                f"Invalid signal number: {signal}. Must be between 1 and 31.")
        return (yield from self.dump(mode=2, signal=signal))