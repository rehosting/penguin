from pandare import PyPlugin
import time
import threading

TIMEOUT=60*5

class Shutdown(PyPlugin):
    def __init__(self, panda):
        # Start a thread
        self.thread = threading.Thread(target=self.run, args=(panda,))
        self.thread.daemon = True
        self.thread.start()

    def run(self, panda):
        time.sleep(TIMEOUT)
        panda.end_analysis()
