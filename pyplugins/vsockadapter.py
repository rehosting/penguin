# Adapter for python requests which supports virtio-vsock based communications

# The following was adapted from requests-unixsocket
# https://github.com/msabramo/requests-unixsocket/blob/master/requests_unixsocket/adapters.py

import socket
from requests.adapters import HTTPAdapter
from requests.compat import urlparse, unquote

import http.client as httplib
try:
    from requests.packages import urllib3
except ImportError:
    import urllib3

class VSockConnection(httplib.HTTPConnection, object):

    def __init__(self, cid, vport, timeout=60):
        """Create an HTTP connection to a unix domain socket
        :param cid: an integer for the vsock client identifier
        :param vport: an integer for the vsock port number
        """
        super(VSockConnection, self).__init__('localhost', timeout=timeout)
        self.cid = cid
        self.vport = vport
        self.timeout = timeout
        self.sock = None

    def __del__(self):  # base class does not have d'tor
        if self.sock:
            self.sock.close()

    def connect(self):
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.cid, self.vport))
        self.sock = sock


class VSockConnectionPool(urllib3.connectionpool.HTTPConnectionPool):

    def __init__(self, cid, port, timeout=60):
        super(VSockConnectionPool, self).__init__(
            'localhost', timeout=timeout)
        self.cid = int(cid)
        self.port = int(port)
        self.timeout = timeout

    def _new_conn(self):
        return VSockConnection(self.cid, self.port, self.timeout)

class VSockAdapter(HTTPAdapter):
    def __init__(self, cid, port, timeout=60, pool_connections=25, *args, **kwargs):
        super(VSockAdapter, self).__init__(*args, **kwargs)
        self.timeout = timeout
        self.pools = urllib3._collections.RecentlyUsedContainer(
            pool_connections, dispose_func=lambda p: p.close()
        )
        self.cid = cid
        self.port = port


    def get_connection(self, url, proxies=None):
        proxies = proxies or {}
        proxy = proxies.get(urlparse(url.lower()).scheme)

        if proxy:
            raise ValueError('%s does not support specifying proxies'
                             % self.__class__.__name__)

        with self.pools.lock:
            pool = self.pools.get(url)
            if pool:
                return pool

            pool = VSockConnectionPool(self.cid, self.port, self.timeout)
            self.pools[url] = pool

        return pool

    def request_url(self, request, proxies):
        return request.path_url

    def close(self):
        self.pools.clear()

if __name__ == '__main__':
    import requests

    # Need to set up an emulated guest listening on CID 4 vport 1007 for this test to work

    s = requests.Session()
    s.mount('http://', VSockAdapter(4, 1007))
    resp = s.get("http://localhost/index.html")
    print(resp.text)
