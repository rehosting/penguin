import os
from urllib.parse import urlparse

def make_abs(url, ref):
    '''
    REF is a relative/absolute path valid when at url
    Transform into an absolute path relative to the root of the domain
    e.g., if we're at http://foo.com/zoo and we see a ref to ./boo, we should
    return "/zoo/boo"

    Must Not include http://foo.com
    '''

    if ref is None:
        return url

    if ref.startswith("/"): # absolute url - easy mode
        abs_ref = ref[1:]
    elif "://" in ref: # External URL?
        return None
    else:
        # Relative path. if we have /foo/zoo.html we want to make the ref relative to /foo
        #                if we have /zoo.html we want to make the ref relative to /
        full = url + "/../" + ref
        base_url = "/".join(url.split("/")[:3])
        abs_ref = os.path.abspath(full.replace(base_url, ""))
        if abs_ref.startswith("/"):
            abs_ref = abs_ref[1:]

    abs_ref = abs_ref.replace("//", "/")
    return abs_ref

def make_rel(url):
    '''
    Given a url we just visited, turn it into a relative path on from the host:
    http://example.com:1234/asdf/basdf should turn into asdf/basdf
    '''
    path = urlparse(url).path
    while '//' in path:
        path = path.replace('//', '/')

    # Drop leading / in path
    while path.startswith("/"):
        path = path[1:]

    return path

def _strip_domain(url):
    '''
    Remove domain (doesn't handle http://user:pass@domain/)
    should handle http/https://domain:port/path
    '''
    #'http://asdf:port/"
    url = url.replace("http://", "").replace("https://", "")
    if '/' in url and url != '/':
        url = url[url.index('/')+1:]
    else:
        url = ''
    return url

def _strip_url(url):
    '''
    Remove any redundant properties from URLs

    Remove duplicate /s and anything after #

    Also remove anything after ? - TODO: get params might be part of form attack surface we want to fuzz
    so maybe we should add these to the fuzz queue
    '''

    if "://" in url:
        meth, body = url.split("://")
    else:
        meth = None
        body = url

    while "//" in body:
        body = body.replace("//", "/")

    if "#" in body:
        body = body.split("#")[0]

    if "?" in body:
        # TODO: maybe add to fuzz queue as a GET target?
        body = body.split("?")[0]

    if body.startswith("/"):
        body = body[1:]

    if meth:
        return meth + "://" + body
    return body

def _build_url(sock_family, sock_ip, sock_port, path):
    if sock_family == 10:
        sock_ip = f"[{sock_ip}]"

    if not sock_ip.endswith("/"):
        sock_ip += "/"

    url = sock_ip + path # Do we need proto?
    if sock_port == 443:
        url = "https://" + url
    else:
        url = "http://" + url
    return url

