from pandare import PyPlugin
import time
import threading

BB_MAX=1000000 # Halt after a fixed number of blocks (1M)
TIMEOUT=60*20 # 20 minute max - normal end should be from zap of BB count

class Shutdown(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.bb_count = 0

        if BB_MAX is not None:
            @panda.cb_before_block_translate
            def shutdown_bbt(cpu, pc):
                self.bb_count += 1

                if self.bb_count > BB_MAX:
                    self.panda.end_analysis()
                    with open(self.outdir + "/shutdown.log", "w") as f:
                        f.write(f"Shutting down from shutdown.py after {self.bb_count} BBs\n")

        if TIMEOUT is not None:
            # Start a thread that waits for TIMEOUT seconds and then shuts down
            self.thread = threading.Thread(target=self.run, args=(panda,))
            self.thread.daemon = True
            self.thread.start()

    def run(self, panda):
        time.sleep(TIMEOUT)
        panda.end_analysis()
        with open(self.outdir + "/shutdown.log", "w") as f:
            f.write(f"Shutting down from shutdown.py after timeout\n")