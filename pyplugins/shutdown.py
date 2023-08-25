from pandare import PyPlugin
import time
import threading

#BB_MAX=1000000 # Halt after a fixed number of blocks (1M)
#TIMEOUT=60*20 # 20 minute max - normal end should be from zap of BB count

#BB_MAX=1000000 # 1M
#UNIQUE=0 # Non-unique
BB_MAX=200000 # 100k DEBUG
UNIQUE=1 # 100k DEBUG
TIMEOUT=120

class Shutdown(PyPlugin):
    def __init__(self, panda):
        # XXX don't pass TIMEOUT to timeout plugin, the C shutdown breaks pypanda uninit
        panda.load_plugin("timeout", {"bb_limit": BB_MAX, 'unique_bbs': UNIQUE})

        # Create a thread that sleeps until TIMEOUT, then shuts down the VM
        self.shutdown_thread = threading.Thread(target=self.shutdown_after_timeout, args=(panda, TIMEOUT))
        self.shutdown_thread.start()
    
    def shutdown_after_timeout(self, panda, timeout):
        time.sleep(timeout)
        panda.end_analysis()