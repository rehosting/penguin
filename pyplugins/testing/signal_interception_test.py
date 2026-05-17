from os.path import join

from penguin import Plugin


class SignalInterceptionTest(Plugin):
    """
    Test plugin that drops SIGHUP deliveries.
    """

    def __init__(self):
        super().__init__()
        self.outfile = join(self.args.outdir, "signal_interception_test.txt")

        self.logger.info("Queueing SIGHUP hook via signal_interception_test plugin...")
        self.plugins.subscribe(self.plugins.signal_monitor, "signal_deliver", self.on_signal_deliver)
        if self.plugins.signal_monitor.register_hook(sig=1):
            self.report("SIGHUP hook registration queued.")
            self.logger.info("SIGHUP hook registration queued and subscribed successfully.")
        else:
            self.report("Failed to queue SIGHUP hook registration.")
            self.logger.error("Failed to queue SIGHUP hook registration.")

    def report(self, line):
        with open(self.outfile, "a") as f:
            f.write(f"{line}\n")

    def on_signal_deliver(self, cpu, event):
        """
        Callback triggered when a signal is delivered in the guest.
        """
        if event.sig != 1:
            return

        self.logger.info(
            f"Intercepted SIGHUP for process '{event.comm}' (PID {event.pid})")

        self.logger.info("Signal dropped.")
        self.report("Signal dropped.")
        event.drop = True
