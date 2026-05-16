from os.path import join

from penguin import Plugin


class SignalInterceptionTest(Plugin):
    """
    Test plugin that drops SIGILL and advances past the x86 UD2 instruction.
    """

    def __init__(self):
        super().__init__()
        self.outfile = join(self.args.outdir, "signal_interception_test.txt")

        self.logger.info("Queueing SIGILL hook via signal_interception_test plugin...")
        self.plugins.subscribe(self.plugins.signal_monitor, "signal_deliver", self.on_signal_deliver)
        if self.plugins.signal_monitor.register_hook(sig=4):
            self.report("SIGILL hook registration queued.")
            self.logger.info("SIGILL hook registration queued and subscribed successfully.")
        else:
            self.report("Failed to queue SIGILL hook registration.")
            self.logger.error("Failed to queue SIGILL hook registration.")

    def report(self, line):
        with open(self.outfile, "a") as f:
            f.write(f"{line}\n")

    def on_signal_deliver(self, cpu, event):
        """
        Callback triggered when a signal is delivered in the guest.
        """
        if event.sig != 4:
            return

        self.logger.info(
            f"Intercepted SIGILL for process '{event.comm}' (PID {event.pid}) at PC 0x{event.pc:x}")

        self.logger.info("Signal dropped.")
        self.report("Signal dropped.")
        event.drop = True

        if event.regs:
            try:
                new_pc = event.regs.get_pc() + 2
                event.regs.set_pc(new_pc)
                self.logger.info(f"Advanced PC to 0x{new_pc:x} to bypass instruction.")
                self.report(f"Advanced PC to 0x{new_pc:x}.")
            except Exception as e:
                self.logger.error(f"Failed to advance PC during signal bypass: {e}")
                self.report(f"Failed to advance PC: {e}")
