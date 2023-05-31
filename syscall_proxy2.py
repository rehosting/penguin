import threading
import socket
from time import sleep
from contextlib import closing

from pandare import PyPlugin

from twisted.web import proxy, http
from twisted.internet import defer
from twisted.python import log
from twisted.internet import reactor
from queue import Queue


# Need to run outside main thread
reactor._handleSignals = lambda: None

class QueuedReverseProxyRequest(proxy.ReverseProxyRequest):
    def process(self):
        # This is where you add the request to the queue instead of processing it immediately
        self.channel.factory.queue.put(self)
        #self.channel.factory.processNextRequest() # Hmm? Infinite loop?

class QueuedReverseProxy(proxy.ReverseProxy):
    requestFactory = QueuedReverseProxyRequest

class QueuedReverseProxyResource(proxy.ReverseProxyResource):
    def getChild(self, path, request):
        return QueuedReverseProxy(self.host, self.port, path)

class QueuedReverseProxyHTTPChannel(proxy.ProxyClientFactory):
    requestFactory = QueuedReverseProxy

class QueuedReverseProxyHTTPFactory(http.HTTPFactory):
    protocol = QueuedReverseProxy

    def __init__(self, panda, addr, port, reactor):
        http.HTTPFactory.__init__(self)
        self.addr = addr
        self.port = port
        self.reactor = reactor
        self.queue = Queue()  # This is where we'll store the requests
        self.processing = False
        self.panda = panda

    def startFactory(self):
        http.HTTPFactory.startFactory(self)
        self.processNextRequest()

    def processNextRequest(self):
        if self.processing or self.queue.empty():
            return
        self.processing = True
        request = self.queue.get()
        print("PROCESS:", request)
        
        # Call Introspect.start_request before forwarding request to upstream server
        self.panda.pyplugins.ppp.Introspect.start_request(request)
        
        # Use callLater to prevent blocking
        d = defer.Deferred()
        self.reactor.callLater(0, d.callback, request)
        d.addCallback(lambda _: super(QueuedReverseProxyRequest, request).process())
        d.addBoth(self.requestFinished)

    def requestFinished(self, result):
        self.processing = False
        print("FINISHED:", result)
        
        # Call Introspect.end_request after response from upstream server is received
        self.panda.pyplugins.ppp.Introspect.end_request(result)
        
        self.processNextRequest()
        return result

def run_proxy(panda, local_host, port, upstream_host, upstream_port):
    site = QueuedReverseProxyHTTPFactory(panda, upstream_host, upstream_port, reactor)
    reactor.listenTCP(port, site)
    reactor.run()


class SyscallProxy2(PyPlugin):
    def __init__(self, panda):

        self.ppp_cb_boilerplate('on_pbind')

        self.panda = panda
        self.port_map = {} # listen port -> (guest port, VPN host port)

        # Register sp_on_bind to trigger when we see a target service bind to aport
        self.ppp.VsockVPN.ppp_reg_cb('on_bind', self.sp_on_bind)

    @staticmethod
    def find_free_port():
        '''
        https://stackoverflow.com/a/45690594
        '''
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('localhost', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def start_proxy_server(self, listen_port, target_port, guest_procname, guest_ip, guest_port):
        print(f'Starting server on port {listen_port}, forwarding to port {target_port}')
        t = threading.Thread(target=run_proxy, args=(self.panda, 'localhost', listen_port, 'localhost', target_port))
        t.daemon = True
        t.start()


    def sp_on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        if guest_port not in [80] or proto != 'tcp':
            return # Ignore

        # Pick an open port and start a proxy server
        port = self.find_free_port()
        self.port_map[port] = (guest_port, host_port)
        print(f"Syscall proxy listening on host port {port}, forwarding to host port on {host_port} which goes to {procname} in guest on {guest_ip}:{guest_port}")

        self.start_proxy_server(port, host_port, procname, guest_ip, guest_port)
        sleep(1) # Give the server a chance to start

        self.ppp_run_cb('on_pbind', proto, guest_ip, guest_port, port, procname)
