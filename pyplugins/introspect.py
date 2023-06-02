import os
import tarfile
from threading import Lock
from pandare import PyPlugin

class TarDir:
    def __init__(self, tar_path):
        if not os.path.exists(tar_path):
            raise ValueError(f"No such file: {tar_path}")
        if not tarfile.is_tarfile(tar_path):
            raise ValueError(f"The file {tar_path} is not a tar archive")
        self.tar_path = tar_path

    def ls(self, path):
        with tarfile.open(self.tar_path) as tar:
            files_in_path = [member.name[1:] for member in tar.getmembers() # trim leading .
                             if member.isfile() and member.name.startswith(path) or member.name.startswith("." + path)]
        return files_in_path

class Introspect(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.zaps = {} # host_port: zap
        self.requests = {} # object -> details
        self._lock = Lock()

        self.mappings = {} # path -> all things we've seen with it
        self.hypotheses = {} # url -> set of guest dirs it may map to

        self.fs_path = self.get_arg("outdir") + "/../repack/fs.tar"
        assert(os.path.exists(self.fs_path))
        self.guest_fs = TarDir(self.fs_path)

        # Parse fs_path tar
        with tarfile.open(self.fs_path, "r") as tar:
            for f in tar:
                if f.isfile():
                    self.mappings[f.name] = set()

        panda.ppp("syscalls2", "on_sys_openat_enter")(self.intro_openat)
        panda.ppp("syscalls2", "on_sys_open_enter")(self.intro_open)
        panda.ppp("syscalls2", "on_sys_execve_enter")(self.intro_execve)
        panda.ppp("syscalls2", "on_sys_execveat_enter")(self.intro_execveat)

    def intro_execve(self, cpu, pc, fname_ptr, argv_ptr, envp):  
        # Log commands and arguments passed to execve
        try:
            fname = self.panda.read_str(cpu, fname_ptr)
            argv_buf = self.panda.virtual_memory_read(cpu, argv_ptr, 100, fmt='ptrlist')
        except ValueError: return
        argv = []
        for ptr in argv_buf:
            if ptr == 0: break
            try: argv.append(self.panda.read_str(cpu, ptr))
            except ValueError: argv.append("(error)")

        s = ' '.join([fname] + (argv[:1] if len(argv) else []))
        for k, v in self.requests.items():
            v['execs'].add(s)

    def intro_execveat(self, cpu, pc, dfd, fname_ptr, argv_ptr, envp, flags):
        # Log commands and arguments passed to execve
        try:
            fname = self.panda.read_str(cpu, fname_ptr)
            argv_buf = self.panda.virtual_memory_read(cpu, argv_ptr, 100, fmt='ptrlist')
        except ValueError: return
        argv = []
        for ptr in argv_buf:
            if ptr == 0: break
            try: argv.append(self.panda.read_str(cpu, ptr))
            except ValueError: argv.append("(error)")

        s = ' '.join([fname] + (argv[:1] if len(argv) else []))
        for k, v in self.requests.items():
            v['execs'].add(s)

    def intro_openat(self, cpu, pc, fd, path, flags, mode):
        try:
            p = self.panda.read_str(cpu, path)
        except ValueError:
            p = "error"

        for k, v in self.requests.items():
            v['files'].add(p)

    def intro_open(self, cpu, pc, path, flags, mode):
        try:
            p = self.panda.read_str(cpu, path)
        except ValueError:
            p = "error"

        for k, v in self.requests.items():
            v['files'].add(p)

    def print_mappings(self, path=None):
        mappings = self.mappings if path is None else {path: self.mappings[path]}

        for p, data in mappings.items():
            if len(data['files']) == 0 and len(data['execs']) == 0:
                continue
            print(f"TOTAL: {path}")

            if len(data['files']) != 0:
                print(f"\t{len(data['files'])} files: {data['files']}")

            if len(data['execs']) != 0:
                print(f"\t{len(data['execs'])} execs: {data['execs']}")

    def add_mappings(self, path, files, port, execs=None):
        # If the files or execs seem to be based on the path, store them!

        if path not in self.mappings:
            self.mappings[path] = {'files': set(), 'execs': set()}

        path_toks_r = [x for x in path.split('/')[::-1] if len(x)]

        # Now add potentially interesting files

        for f in list(files): # XX how is this changing?
            if f in self.mappings[path]['files']: # Already seen
                continue

            file_toks_r = [x for x in f.split('/')[::-1] if len(x)]

            is_interesting = False
            if path == '/':
                # Special case - all paths could be interesting
                is_interesting = True

                # Hypothesize path goes to each path we saw
                # TODO: if path is / and request is like /var/www/index.html we want the dirname of the path
                # Or it could be / -> /var/www/files/ in which case we do want the file. So if f is a dir, add that, if f is a file, add dirname(f)
                # For now just add both
                self.add_hypo(path, f, port)
                try:
                    self.add_hypo(path, os.path.dirname(f), port)
                except ValueError:
                    print("Error getting dirname of", f)

                return

            # How many tokens do they have in common?
            common = 0
            for i in range(min(len(path_toks_r), len(file_toks_r))):
                if path_toks_r[i] != file_toks_r[i]:
                    break
                common += 1

            if common > 1:
                is_interesting = True

            # Hypothesize mappings for each level of alignment
            for tok_id in range(0, common):
                request_url = '/' + '/'.join(path_toks_r[tok_id:][::-1])
                file_path = '/' + '/'.join(file_toks_r[tok_id:][::-1])
                self.add_hypo(request_url, file_path, port)
            self.mappings[path]['files'].add(f)

    def add_hypo(self, url, file_path, port):
        if port not in self.hypotheses:
            self.hypotheses[port] = {}

        if url not in self.hypotheses[port]:
            self.hypotheses[port][url] = set()

        if file_path not in self.hypotheses[port][url]:
            print(f"Save base request {url} => {file_path}")
            self.hypotheses[port][url].add(file_path)

            #print("NEW HYPO:", self.zaps[port], port, "request to", url, "goes to", file_path)
            try:
                for fname in self.guest_fs.ls(file_path):
                    rel_fname = fname.replace(file_path, "")

                    rel_fname = rel_fname.replace("//", "/")
                    if rel_fname.startswith("/") and url.endswith("/"):
                        rel_fname = rel_fname[1:]

                    url_hypo = url + rel_fname
                    if url_hypo.startswith("/"):
                        url_hypo = url_hypo[1:] # Trim leading /


                    if url_hypo not in self.hypotheses[port]:
                        self.hypotheses[port][url_hypo] = set()

                    if fname not in self.hypotheses[port][url_hypo]:
                        self.hypotheses[port][url_hypo].add(fname)
                        # First time seeing this file, so we should add it to the mappings and tell ZAP
                        self.zaps[port].add_url(url_hypo)


            except ValueError:
                print("\tNot a directory") # In this case it might be a file - can we look at the parent directory and propose other files?
                # Also what if we browse to foo/ and we see a request to foo/index.html or foo/main.html, then we should still handle it!

    @PyPlugin.ppp_export
    def set_zap(self, port, zap):
        self.zaps[port] = zap

    @PyPlugin.ppp_export
    def start_request(self, request, port):
        with self._lock:
            self.requests[id(request)] = {'request': request, 'port': port, 'files': set(), 'execs': set()}

    @PyPlugin.ppp_export
    def end_request(self, request):
        with self._lock:
            result = self.requests[id(request)]
            path = result['request'].path.decode()
            port = result['port']
            #print(f"Introspect: In processing {result['request']} we saw {len(result['files'])} files: {result['files']}")

            # Update mappings
            self.add_mappings(path, result['files'], port, result['execs'])
            # Print updated maps for this path
            #self.print_mappings(path)

            del self.requests[id(request)]

    # TODO: register various syscall handlers to analyze behavior during requests