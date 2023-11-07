from pandare import PyPlugin
import time
import threading

TIMEOUT=60*10 # 10m

class Shutdown(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        log_path = self.outdir + "/shutdown.csv"

        # XXX the timeout plugin can't trigger our pyplugin end-of-analysis
        # logic so we've hacked that up and disabled it.
        # Instead, all the plugin does is to write down the number of 
        # executed blocks at log_path
        panda.load_plugin("timeout", {
                #"bb_limit": BB_MAX,
                #'unique_bbs': UNIQUE,
                "log": log_path
                })

        # Create a thread that sleeps until TIMEOUT, then shuts down the VM
        self.shutdown_event = threading.Event()
        self.shutdown_thread = threading.Thread(
                target=self.shutdown_after_timeout,
                args=(panda, TIMEOUT, self.shutdown_event))
        self.shutdown_thread.start()
    
    def shutdown_after_timeout(self, panda, timeout, shutdown_event):
        wait_time = 0
        while wait_time < timeout:
            # Check if the event is set
            if shutdown_event.is_set():
                try:
                    print("Shutdown thread: Guest shutdown detected, exiting thread.")
                except OSError:
                    pass # Can't print but it's not important
                return

            # Sleep briefly
            time.sleep(1)
            wait_time += 1

        try:
            print(f"Shutdown thread: execution timed out after {timeout}s - shutting down guest")
        except OSError:
            # During shutdown, stdout might be closed!
            pass

        panda.end_analysis()

    def uninit(self):
        self.shutdown_event.set()
