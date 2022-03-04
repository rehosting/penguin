import requests
import socket

class _Response(object):
    def __init__(self, data=None):
        self.status = None
        self.headers = {}
        self.reason = None
        self.pos = 0
        self.raw_data = None

        if data:
            self.from_data(data)

    def from_socket(self, s):
        # Consume response - try to find Content Length in a loop, then just read that size
        response = b""
        content_length = None
        header_length = 0
        while True:
            s.settimeout(5)
            chunk = s.recv(4096)
            if len(chunk) == 0:
                # No more data, but we didn't see the end of headers. Uh oh
                break
            response = response + chunk;

            if b"\r\n\r\n" in response:
                # Finished reading headers
                break


        # After headers - should have content length. Hopefully?
        if b"Content-Length: " in response:
            len_msg = response[response.index(b"Content-Length: ")+len("Content-Lenght: "):][:200]
            if b"\r\n" in len_msg:
                content_length = int(len_msg.split(b"\r\n")[0])
        else:
            print(f"WARNING: no content length in {response}")

        header_length = len(response.split(b"\r\n\r\n")[0])+4 # 4 is for the end

        expected_length = header_length + content_length

        if len(response) < expected_length:
            s.settimeout(10)
            remainder = s.recv(expected_length - len(response))
            response += remainder

        #print("RESP:", repr(response))

        self.from_data(response)

    def from_data(self, data):
        self.raw_data = data
        # parse payload
        headers, *body = data.split(b"\r\n\r\n") # body might contain the terminator - we'll fix it up later
        header_lines = headers.split(b"\r\n")

        proto = header_lines[0].split(b" ")[0]
        self.status = int(header_lines[0].split(b" ")[1])
        self.reason = header_lines[0].split(str(self.status).encode()+b" ")[1]

        for header_line in header_lines[1:]:
            key, value = header_line.split(b": ")
            self.headers[key] = value

        self.raw_data = b"\r\n\r\n".join(body)

    def read(self, size):
        data = self.raw_data[self.pos:self.pos+size]
        self.pos += size
        return data


class VMSockAdapter(requests.adapters.HTTPAdapter):
    '''
    Custom HTTPAdapter subclass for vm sock based connections.
    Initialize with CID, port as args. Example:
        s = requests.Session()
        vmsa = VMSockAdapter(4, 1000)
        s.mount('http://', vmsa)

    Then use the session object (s) e.g., s.get()
    '''
    def __init__(self, *args):
        self.cid, self.port = args

    def send(self, request, **kwargs):
        url = self.request_url(request, None)

        self.add_headers(request, stream=False, timeout=None,
                         verify=False, cert=None, proxies=None)

        byte_req =  f"{request.method} {url} HTTP/1.1\r\n".encode()

        # Not sure how to add host "correctly" but this works
        if 'host' not in request.headers:
            request.headers['host'] = 'localhost'

        for header, value in request.headers.items():
            byte_req += f"{header}: {value}\r\n".encode()

        byte_req += b"\r\n"
        if request.body:
            byte_req += request.body+"\r\n"

        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((self.cid, self.port))

        #s.setblocking(0)
        s.sendall(byte_req)

        resp = _Response()
        resp.from_socket(s)

        # Consume response, build a dict with 'status', 'headers', 'reason'
        return self.build_response(request, resp)

if __name__ == '__main__':
    # Need to set up a server on CID 4 vport 1000 for this test to work
    s = requests.Session()
    a = VMSockAdapter(4, 1001)
    s.mount('http://', a)

    resp = s.get("http://example.com")
