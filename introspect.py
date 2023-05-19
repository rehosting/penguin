from threading import Lock
from pandare import PyPlugin

class Introspect(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.zaps = {} # host_port: zap
        self.requests = {} # host_port: request
        self.lock = Lock()

    @PyPlugin.ppp_export
    def set_zap(self, port, zap):
        self.zaps[port] = zap

    @PyPlugin.ppp_export
    def __enter__(self):
        self.lock.acquire()

    @PyPlugin.ppp_export
    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()

    @PyPlugin.ppp_export
    def start_request(self, port, url, method, headers, body):
        assert(self.lock.locked())
        print(f"Introspect: start_request: {url}, {method}, {headers}")
        # TODO: store details of pending request

    @PyPlugin.ppp_export
    def end_request(self, port):
        assert(self.lock.locked())
        print(f"Introspect: end_request")
        # TODO: disable introspection, analyze results

    # TODO: register various syscall handlers to analyze behavior during requests