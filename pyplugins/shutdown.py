from pandare import PyPlugin
import time
import threading

#BB_MAX=1000000 # Halt after a fixed number of blocks (1M)
#TIMEOUT=60*20 # 20 minute max - normal end should be from zap of BB count

#BB_MAX=1000000 # 1M
#UNIQUE=0 # Non-unique
BB_MAX=200000 # 100k DEBUG
UNIQUE=1 # 100k DEBUG
TIMEOUT=240*1/2 # XXX DEBUG 0.5x for testing?

class Shutdown(PyPlugin):
    def __init__(self, panda):
        # XXX don't pass TIMEOUT to timeout plugin, the C shutdown breaks pypanda uninit
        panda.load_plugin("timeout", {"bb_limit": BB_MAX, 'unique_bbs': UNIQUE})

        # Create a thread that sleeps until TIMEOUT, then shuts down the VM
        self.shutdown_event = threading.Event()
        self.shutdown_thread = threading.Thread(target=self.shutdown_after_timeout, args=(panda, TIMEOUT, self.shutdown_event))
        self.shutdown_thread.start()
    
    def shutdown_after_timeout(self, panda, timeout, shutdown_event):
        wait_time = 0
        while wait_time < timeout:
            # Check if the event is set
            if shutdown_event.is_set():
                print("Shutdown thread: Guest shutdown detected, exiting thread.")
                return

            # Sleep briefly
            time.sleep(1)
            wait_time += 1

        print(f"Shutdown thread: execution timed out after {timeout}s - shutting down guest")
        panda.end_analysis()

    def uninit(self):
        self.shutdown_event.set()
