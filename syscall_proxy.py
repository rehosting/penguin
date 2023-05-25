import urllib.parse
import asyncio
import threading
import socket
from pandare import PyPlugin
from contextlib import closing
from time import sleep
from urllib.parse import urlparse, urlunparse
from twisted.internet import reactor, protocol
reactor._handleSignals = lambda: None

'''
class ProxyClient(protocol.Protocol):
    def __init__(self, panda, local_host, local_port, target_host, target_port):
        self.panda = panda
        self.local_host = local_host
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port
        self.buffer = None
        #self.bad_host_header = f"Host: {local_host}:{local_port}".encode()
        #self.good_host_header = f"Host: {target_host}:{target_port}".encode()

    def connectionMade(self):
        self.transport.write(self.buffer)
        self.buffer = ''

    def dataReceived(self, data):
        print("Got back:", repr(data))
        self.server.transport.write(data)

        #self.panda.pyplugins.ppp.Introspect.end_request(self.target_port)
        #self.panda.pyplugins.ppp.Introspect.unlock()

    def connectionLost(self, reason):
        print("Client connection lost - TODO should we unlock?")
        self.server.transport.loseConnection()

class ProxyClientFactory(protocol.ClientFactory):
    def __init__(self, panda, server, local_host, local_port, target_host, target_port):
        self.panda = panda
        self.server = server
        self.local_host = local_host
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port

    def buildProtocol(self, addr):
        client = ProxyClient(self.panda, self.local_host, self.local_port, self.target_host, self.target_port)
        client.server = self.server
        client.buffer = self.server.buffer
        self.server.client = client
        return client

    def clientConnectionFailed(self, connector, reason):
        self.server.transport.loseConnection()

class ProxyServer(protocol.Protocol):
    def __init__(self, panda, local_host, local_port, target_host, target_port):
        self.panda = panda
        self.local_host = local_host
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port

    def dataReceived(self, data):
        if not hasattr(self, 'client'):
            print(f"\nProxy Server got data - let's grab Introspect lock: {data}")
            if self.panda.pyplugins.ppp.Introspect.has_lock():
                print("XXX WANT LOCK CAN'T GET RIGHT AWAY")

            self.panda.pyplugins.ppp.Introspect.lock()
            print("GOT LOCK")
            self.panda.pyplugins.ppp.Introspect.start_request(self.target_port, None, None, None, None)
            #data = data.replace(self.bad_host_header, self.good_host_header)
            self.buffer = data
            reactor.connectTCP(self.target_host, self.target_port, ProxyClientFactory(self.panda, self, self.local_host, self.local_port, self.target_host, self.target_port))
        else:
            self.client.transport.write(data)

    def connectionLost(self, reason):
        if hasattr(self, 'client'):
            if self.panda.pyplugins.ppp.Introspect.has_lock():
                print("\nProxy Server lost connection - let's release Introspect lock")
                self.panda.pyplugins.ppp.Introspect.end_request(self.target_port)
                self.panda.pyplugins.ppp.Introspect.unlock()
            self.client.transport.loseConnection()

class ProxyFactory(protocol.Factory):
    def __init__(self, panda, local_host, local_port, target_host, target_port):
        self.panda = panda
        self.local_host = local_host
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port

    def buildProtocol(self, addr):
        return ProxyServer(self.panda, self.local_host, self.local_port, self.target_host, self.target_port)

def run_proxy(panda, local_host, local_port, remote_host, remote_port):
    reactor.listenTCP(local_port, ProxyFactory(panda, local_host, local_port, remote_host, remote_port), interface=local_host)
    reactor.run()
'''

from twisted.internet import reactor
from twisted.web import http
from twisted.web.proxy import Proxy, ProxyRequest

class MyProxyRequest(ProxyRequest):
    ports = {b"http": 80, b"https": 443}

    def __init__(self, panda, remote_host, remote_port, *args, **kwargs):
        self.panda = panda
        self.remote_host = remote_host
        self.remote_port = remote_port
        super().__init__(*args, **kwargs)

    def process(self):
        parsed = urlparse(self.uri)
        host = self.remote_host
        port = self.remote_port
        rest = urlunparse((b"", b"") + parsed[2:])
        if not rest:
            rest = rest + b"/"
        class_ = self.protocols[b"http"]
        headers = self.getAllHeaders().copy()
        if b"host" not in headers:
            headers[b"host"] = host.encode("ascii")
        self.content.seek(0, 0)
        s = self.content.read()
        clientFactory = class_(self.method, rest, self.clientproto, headers, s, self)

        self.panda.pyplugins.ppp.Introspect.start_request(None, None, None, None, None)
        self.reactor.connectTCP(host, port, clientFactory)
        '''
        with self.panda.pyplugins.ppp.Introspect as introspection:
            introspection.start_request(None, None, None, None, None)
            self.reactor.connectTCP(host, port, clientFactory)
            introspection.end_request(None)
        '''

    def setHost(self, host, port, ssl=False):
        # Ignore 'host' and 'port' parameters and use fixed 'remote_host' and 'remote_port'
        self.host, self.port = self.remote_host, self.remote_port
        self.ssl = ssl

    def connectionLost(self, *args, **kwargs):
        self.panda.pyplugins.ppp.Introspect.finish_request(None)
        super().connectionLost(*args, **kwargs)
        
class MyProxy(Proxy):
    def __init__(self, panda, remote_host, remote_port, *args, **kwargs):
        self.panda = panda
        self.remote_host = remote_host
        self.remote_port = remote_port
        super().__init__(*args, **kwargs)

    def requestFactory(self, *args):
        # Pass 'remote_host' and 'remote_port' to 'MyProxyRequest'
        return MyProxyRequest(self.panda, self.remote_host, self.remote_port, *args)

class MyProxyFactory(http.HTTPFactory):
    def __init__(self, panda, remote_host, remote_port, *args, **kwargs):
        self.panda = panda
        self.remote_host = remote_host
        self.remote_port = remote_port
        super().__init__(*args, **kwargs)

    def buildProtocol(self, addr):
        # Pass 'remote_host' and 'remote_port' to 'MyProxy'
        return MyProxy(self.panda, self.remote_host, self.remote_port)

def run_proxy(panda, local_host, local_port, remote_host, remote_port):
    factory = MyProxyFactory(panda, remote_host, remote_port)
    reactor.listenTCP(local_port, factory)
    reactor.run()



class SyscallProxy(PyPlugin):
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