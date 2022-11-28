import subprocess
from urllib.parse import urlparse

class FsHelper():
    '''
    Filesystem helpers for crawling when a tar-based FS is present.

    Given info about a syscall run for a given request, determine what other files might be reachable
    from similar requests.
    '''

    def __init__(self, image_tar=None):
        self.image_tar = image_tar
        self.seen_req_bases = set()

        if image_tar is not None:
            self.filesystem_contents = subprocess.check_output(f"tar -tf '{self.image_tar}'", shell=True)\
                .decode().splitlines()
            self.tarbase = subprocess.check_output(f"tar -tf '{self.image_tar}' | head -n1", shell=True)\
                .decode().strip()

    def check(self, request, target, syscall_name, pid, procname, file):
        '''
        A `syscall_name` syscall in `procname` (`pid`) acessed a `file` while we made `request to `target`.

        1) Examine the FS to identify sibling files we shuld also crawl
        2) Bug detection? (TODO)

        return a list of URLs to visit

        '''
        results = []

        # Ignore when our infrastructure is writing results. Note the dev filter could be too strong
        if file.startswith('/dev/') or file.startswith('/igloo/utils'):
            return []

        # check URL
        url  = urlparse(request.url)
        if fs_paths := self.resolve_fs(url.path, file):
            request_base, fs_base = fs_paths
            if request_base not in self.seen_req_bases:
                self.seen_req_bases.add(request_base)
                print(f"Requests to URL {request_base} might map to {fs_base} in guest fs")

            for subpath in self.find_fs_subpaths(fs_base):
                assert(subpath.startswith(fs_base)), f"Unexpected {subpath} for {fs_base}" # /var/www/dir/page.html
                subpath = subpath[len(fs_base):]  # if fs_base is /var/www/, dir/page.html
                if not subpath.startswith('/') and not request_base.endswith('/'):
                    subpath = '/' + subpath
                subpath = request_base + subpath
                results.append(subpath)

        # TODO: can we unify param checking with the request object instead of the URL?
        # check query
        for tok in url.query.split("&"):
            if "=" not in tok:
                if tok in file and len(tok) > 4:
                    print("QUERY MATCH:", tok)
            else:
                k, v = tok.split("=")
                if k in file and len(k) > 4:
                    print("QUERY KEY:", k)
                if v in file and len(v) > 4:
                    print("QUERY VAL:", v)

        # check params
        if request.method == 'POST':
            for p in request.params:
                print("POST has param", p) # TODO

        return results

    def find_fs_subpaths(self, path):
        '''
        Return files in the guest filesystem that start with the provided path.
        '''
        assert(hasattr(self, 'filesystem_contents'))
        # Tarbase is either / or ./ then path might be foo or /foo. Make sure we don't have .//foo
        if self.tarbase.endswith("/") and path.startswith("/"):
            path = self.tarbase + path[1:]
        elif not self.tarbase.endswith("/") and not path.startswith("/"):
            path = self.tarbase + "/" + path
        else:
            path = self.tarbase + path

        results = []
        for x in self.filesystem_contents:
            if x.startswith(path):
                if self.tarbase == './' and x.startswith('./'):
                    x = '/' + x[2:] # ./asdf -> /asdf
                results.append(x)
        return results

    """
    def analyze_fs(self, target, match_type, path, file):
        result = [] # [(path, new_url), ...]
        if match_type == "full_url_match":
            '''
            Imagine a get of /dir/file that opens /var/www/dir/file
            We calculate fs_base of /var/www. Then we ls /var/www/dir/file
            in the filesystem. Drop /var/www from each and those are the URLs to visit
            '''
            sysc_dir  = os.path.dirname(file)       # /var/www/dir
            files = self.find_fs_subpaths(sysc_dir) # /var/www/dir/other_file
            fs_base = file.replace(path, "")        # /var/www/

            for f in files:
                new_url = f.replace(fs_base, "")        # dir/other_file
                if f == "./":
                    continue
                if f.startswith("./"):
                    f = f[1:] # make ./foo /foo. It will become relative later?
                #print(f"Possible sibling. Browsing to {url.path} accessed {file}. So we should be able to hit {f} if we browse to {new_url}?")
                if not new_url.startswith("/"):
                    new_url = "/" + new_url
                result.append((path, new_url))
        else:
            raise ValueError(f"Unexpected match type: {match_type}")
        return result
    """

    @staticmethod
    def resolve_fs(url, fs_path):
        '''
        Given a path we browsed to and a file/folder accessed in the guest FS
        generate a list of (path, folder) mappings we should crawl.

        For example, if given '/web/file.html' and '/var/www/web', we should
        speculate that '/web/X' would go into '/var/www/X'. As such we'd return
        ('/web/', '/var/www/') and the caller can then examine /var/www to
        decide what subsequent requests to try.
        '''

        # No //s
        url = url.replace("//", "/")
        fs_path = fs_path.replace("//", "/")

        requested_dirs = url.split("/")
        fs_dirs = fs_path.split("/")

        # Reverse
        requested_dirs_t = requested_dirs[::-1]
        fs_dirs_t = fs_dirs[::-1]

        if requested_dirs_t[0] == '' and len(requested_dirs_t) > 1 and len(fs_dirs_t) > 1 and requested_dirs_t[1] != fs_dirs_t[1]:
            # Request was for some/directory/ make it for /some/directory
            return FsHelper.resolve_fs(url[:-1], fs_path)


        if requested_dirs_t[0] == fs_dirs_t[0]:
            # Filename matches, try to map paths
            for idx, x in enumerate(requested_dirs_t):
                if x != fs_dirs_t[idx]:
                    break

            return (('/'.join(requested_dirs_t[idx:][::-1])+'/',
                     '/'.join(fs_dirs_t[idx:][::-1]) + '/'))

        elif 'index.' in fs_dirs_t[0] and '.' not in (str(requested_dirs_t)):
            # It opened index.something, just add that to our path and recurse
            # e.g., if we see open of index.php while fetching /foo
            # rerun as if we got /foo/index.php and see if that resolves anything

            # XXX: If we request /foo.php and that goes and opens /var/www/index.php, we don't want
            # to then think /foo.php/* -> /var/www/*. To handle this we check of a '.' in any of
            # our requested path. It's not great.

            return FsHelper.resolve_fs(url + "/" + fs_dirs_t[0], fs_path)

        return None

if __name__ == '__main__':
    '''
    for url, fs in [ ('/web/file.html',      '/var/www/web/file.html'),
                     ('/index.html',         '/var/www/index.html'),
                     ('/',                   '/var/www/index.php'),
                     ('/',                   '/var/www/index.html'),
                     ('/data',               '/var/www/data/index.html'),
                     ('/p2/webroot2/d.html', '/altroot/f/d.html'),
                     ('/folder/',            'data/folder/'),
                     ('/foo/folder/',        'data/foo/folder/'),
                     ('/www/index.html/',    '/var/www/index.html'),
                     ]:

        print(url, fs)
        print(FsHelper.resolve_fs(url, fs))
    '''
    fsh = FsHelper("/home/andrew/git/igloo/results/FW/WNAP320 Firmware Version 2.0.3.zip/image.raw")
    #print(fsh.resolve_fs("/BackupConfig.php/", "/home/www/BackupConfig.php"))
    fsh.check("/BackupConfig.php/",
              None,
              'open',
              1,
              'init',
              '/home/www/index.php')
