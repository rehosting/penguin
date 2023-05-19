import http.client
import http.server
import socketserver
import threading
import urllib.parse
import asyncio
import socket
from pandare import PyPlugin
from contextlib import closing

'''
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def __init__(self, *args, port, panda, **kwargs):
        self.panda = panda
        self.port = port
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.do_request('GET')

    def do_POST(self):
        self.do_request('POST')

    def do_request(self, method):
        url = urllib.parse.urlsplit(self.path)
        print(f'Received request: {url.path}')
        for header, value in self.headers.items():
            print(f'{header}: {value}')

        body = None
        if 'Content-Length' in self.headers:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)

        print(f"In do request for {method} with url {url}: get introspection lock")
        with self.panda.pyplugins.ppp.Introspect as introspection:
            print("\tGot lock!")

            introspection.start_request(self.port, url.path, method, self.headers, body)
            # Forward request and wait for response, with the lock
            conn = http.client.HTTPConnection('localhost', self.port)
            headers = {k: v for k, v in self.headers.items() if k not in ('Content-Length', 'Transfer-Encoding')}
            conn.request(method, url.path, headers=headers, body=body)
            response = conn.getresponse()

            print(f'Received response: {response.status} {response.reason}')
            for header, value in response.getheaders():
                print(f'{header}: {value}')

            self.send_response(response.status)
            for header, value in response.getheaders():
                if header.lower() not in ('content-length', 'transfer-encoding'):
                    self.send_header(header, value)
            self.end_headers()

            # Read and write in chunks
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)

            conn.close()
def make_handler(port, panda):
    def handler(*args, **kwargs):
        return MyHTTPRequestHandler(*args, port=port, panda=panda, **kwargs)
    return handler
'''


def handle_client(panda, client_socket, local_host, local_port, target_host, target_port):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((target_host, target_port))

    # Do initial recv before we have the lock
    client_data = client_socket.recv(4096)
    if len(client_data) == 0:
        # no more data, close both connections and break out of the loop
        client_socket.close()
        remote_socket.close()
        return

    bad_host_header = f"Host: {local_host}:{local_port}".encode()
    good_host_header = f"Host: {target_host}:{target_port}".encode()


    if len(client_data) > 0: # Don't take lock if no data
        with panda.pyplugins.ppp.Introspect as introspection:
            while len(client_data) > 0: # Could it be < 0 if error? Normal break is 0

                introspection.start_request(target_port, None, None, None, None)

                # 1) replace host with the guest port host? This gets funky with content length...
                #client_data = client_data.replace(bad_host_header, good_host_header)

                # 2) Try parsing the request?
                print(f"SENDING to {target_host}:{target_port}: {repr(client_data)}")

                # send data to remote host
                remote_socket.send(client_data)

                # receive back the response
                try:
                    remote_data = remote_socket.recv(4096)
                except ConnectionResetError:
                    print("Connection reset by peer")
                    break

                print("Got back:", repr(remote_data))

                # send the response to the local client
                client_socket.send(remote_data)

                # Get some more data
                client_data = client_socket.recv(4096)

            introspection.end_request(target_port)

    # All done
    client_socket.close()
    remote_socket.close()

def server_loop(panda, local_host, local_port, remote_host, remote_port, guest_procname, guest_ip, guest_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
        server.listen(5)
    except socket.error as e:
        print(f'Error binding or listening on socket: {e}')
        return

    print(f'Listening on {local_host}:{local_port} and proxying to {remote_host}:{remote_port} for {guest_procname} on {guest_ip}:{guest_port}')

    while True:
        client_socket, addr = server.accept()
        print(f'Accepted connection from {addr[0]}:{addr[1]}')
        handle_client(panda, client_socket, local_host, local_port, remote_host, remote_port)



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
        #handler = make_handler(target_port, self.panda)
        #server = ThreadedHTTPServer(('localhost', listen_port), handler)
        #t = threading.Thread(target=server.serve_forever)
        t = threading.Thread(target=server_loop, args=(self.panda, 'localhost', listen_port, 'localhost', target_port,
                                                       guest_procname, guest_ip, guest_port))
        t.daemon = True
        t.start()

        print(f'Starting server on port {listen_port}, forwarding to port {target_port}')


    def sp_on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        if guest_port not in [80] or proto != 'tcp':
            return # Ignore

        # Pick an open port and start a proxy server
        port = self.find_free_port()
        self.port_map[port] = (guest_port, host_port)
        self.start_proxy_server(port, host_port, procname, guest_ip, guest_port)

        print(f"Syscall proxy listening on host port {port}, forwarding to host port on {host_port} which goes to {procname} in guest on {guest_ip}:{guest_port}")
        self.ppp_run_cb('on_pbind', proto, guest_ip, guest_port, port, procname)