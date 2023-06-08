import threading
import socket
from time import sleep
from contextlib import closing

from pandare import PyPlugin

from twisted.web import proxy, server 
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectionDone, ConnectionLost

# Need to run outside main thread
reactor._handleSignals = lambda: None
class MyProxyClient(proxy.ProxyClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requestHeaders = []
        self.responseParts = []

    def handleHeader(self, key, value):
        self.requestHeaders.append((key, value))
        super().handleHeader(key, value)

    def handleResponseBegin(self):
        #print("MyProxyClient.handleResponseBegin")
        super().handleResponseBegin()

    def handleResponsePart(self, buffer):
        #print("MyProxyClient.handleResponsePart")
        self.responseParts.append(buffer)
        super().handleResponsePart(buffer)

    def handleResponseEnd(self):
        #print("MyProxyClient.handleResponseEnd", id(self))
        #print(f"Response Headers: {self.requestHeaders}")
        #print(f"Response Body: {repr(b''.join(self.responseParts).decode('utf-8', 'replace'))[:1000]}")
        try:
            super().handleResponseEnd()
        except RuntimeError as e:
            print("RuntimeError in handleResponseEnd:", e)

        if f := getattr(self.father, 'finish_deferred', None):
            if not self.father._disconnected:
                f.callback(self.father) # Signal that the response is processed
                self.father.finish_deferred = None


class MyProxyClientFactory(proxy.ProxyClientFactory):
    protocol = MyProxyClient

class MySingleRequestReverseProxy(proxy.ReverseProxyResource):
    proxyClientFactoryClass = MyProxyClientFactory

    def __init__(self, panda, outdir, listen_port, host, port, path, reactor=reactor):
        proxy.ReverseProxyResource.__init__(self, host, port, path, reactor=reactor)
        self.panda = panda
        self.listen_port = listen_port
        self.outdir = outdir

    def getChild(self, path, request):
        return MySingleRequestReverseProxy(
            self.panda, self.outdir, self.listen_port, self.host, self.port, self.path + b'/' + path)

    def before_request(self, request):
        request.finish_deferred = Deferred()

        # Append request to log
        with open(self.outdir + f"/syscall_proxy_{self.listen_port}.log", "ab") as f:
            # Write the FULL REQUEST to the text file
            f.write(f"{request.method} {request.uri} {request.clientproto}\n".encode('utf-8'))
            for k, v in request.requestHeaders.getAllRawHeaders():
                f.write(f"{k}: {v}\n".encode('utf-8'))
            f.write(b'\n')
            f.write(request.content.getvalue()+b'\n\n')

        self.panda.pyplugins.ppp.Introspect.start_request(request, self.listen_port)
        request.call_finish = True
        return request  # Return request to pass it to the next callback in the chain.

    def after_request(self, request):
        # XXX We want this to run after upstream finishes responding - is it running at the wrong time?
        self.panda.pyplugins.ppp.Introspect.end_request(request)

        # Write the FULL RESPONSE to the text file
        with open(self.outdir + f"/syscall_proxy_{self.listen_port}.log", "ab") as f:
            f.write(f"{request.code} {request.phrase}\n".encode('utf-8'))
            for k, v in request.responseHeaders.getAllRawHeaders():
                f.write(f"{k}: {v}\n".encode('utf-8'))
            f.write(b'\n')
            f.write(b''.join(request.responseParts)+b'\n\n')

        return server.NOT_DONE_YET  # Return NOT_DONE_YET to Twisted signaling that the response is not ready yet.

    def render(self, request):
        # Notify when connection lost
        def connectionLost(reason):
            request.call_finish = False
            reason.trap(ConnectionDone, ConnectionLost)
            print("Connection lost:", reason)

        request.notifyFinish().addErrback(connectionLost)

        #print(f"New incoming request:", request)
        d = Deferred()
        d.addCallback(self.before_request)  # 1) call Introspect.start_request(request)
        d.addCallback(lambda req: proxy.ReverseProxyResource.render(self, req))  # 2) Do the standard reverse proxy logic

        # Only call after_request if connection is still open
        d.addCallback(lambda _: request.finish_deferred if getattr(request, 'call_finish', False) else None) # Wait for the upstream response to be processed
        d.addCallback(self.after_request if getattr(request, 'call_finish', False) else lambda _: None) # 3) call Introspect.end_request(request)

        d.callback(request)  # Initiate the callback chain with the request as an argument.
        return server.NOT_DONE_YET
    
def run_proxy(panda, outdir, local_host, local_port, remote_host, remote_port):
    # Remost host is ignored, will always be localhost
    site = server.Site(MySingleRequestReverseProxy(panda, outdir, local_port, local_host, remote_port, b''))
    #site = MySite(MySingleRequestReverseProxy(panda, local_host, remote_port, b'', request_in_flight, rif_lock))
    reactor.listenTCP(local_port, site)
    reactor.run()

class SyscallProxy2(PyPlugin):
    def __init__(self, panda):

        self.ppp_cb_boilerplate('on_pbind')

        self.panda = panda
        self.port_map = {} # listen port -> (guest port, VPN host port)
        self.outdir = self.get_arg("outdir")

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
        t = threading.Thread(target=run_proxy, args=(self.panda, self.outdir, 'localhost', listen_port, 'localhost', target_port))
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
