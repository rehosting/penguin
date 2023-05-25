from threading import Lock
from pandare import PyPlugin

class Introspect(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.zaps = {} # host_port: zap
        self.requests = {} # host_port: request
        self._lock = Lock()

        @panda.ppp("syscalls2", "on_sys_openat_enter")
        def intro_openat(cpu, pc, fd, path, flags, mode):
            if not self.has_lock():
                return
            self.counter += 1

        @panda.ppp("syscalls2", "on_sys_open_enter")
        def intro_open(cpu, pc, path, flags, mode):
            if not self.has_lock():
                return
            self.counter += 1

    @PyPlugin.ppp_export
    def set_zap(self, port, zap):
        self.zaps[port] = zap

    @PyPlugin.ppp_export
    def __enter__(self):
        self.lock()

    @PyPlugin.ppp_export
    def __exit__(self, exc_type, exc_value, traceback):
        self.unlock()

    @PyPlugin.ppp_export
    def lock(self):
        self._lock.acquire()

    @PyPlugin.ppp_export
    def unlock(self):
        assert(self._lock.locked())
        self._lock.release()

    @PyPlugin.ppp_export
    def has_lock(self):
        return self._lock.locked()

    @PyPlugin.ppp_export
    def start_request(self, port, url, method, headers, body):
        #assert(self._lock.locked())
        self.counter = 0
        #print(f"Introspect: start_request: {url}, {method}, {headers}")
        # TODO: store details of pending request

    @PyPlugin.ppp_export
    def end_request(self, port):
        #assert(self._lock.locked())
        #print(f"Introspect: end_request")
        # TODO: disable introspection, analyze results
        print(f"At end of request we have saw {self.counter} file opens")

    # TODO: register various syscall handlers to analyze behavior during requests