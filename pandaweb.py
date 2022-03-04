#!/usr/bin/env python3

# XXX: For this script to work it must have internet access (i.e., don't run in VSockify bridge mode unless your netns has networking)

import re
import requests
import logging
from urllib.parse import unquote

from pandare import PyPlugin
from pandarepyplugins import CallTree

class PandaWeb(PyPlugin):
    def __init__(self, panda):
        self.panda = panda

        self.logger = logging.getLogger('PandaWeb')
        self.collab_url = self.get_arg("collab_url")
        if self.collab_url is None:
            self.collab_url = "burpcollaborator.net"
        self.matcher = re.compile(r".*?([a-z0-9]*.\." + self.collab_url +").*")

        panda.pyplugins.load(CallTree)
        self.ppp.CallTree.ppp_reg_cb('on_call', self.on_call)


        @panda.ppp("syscalls2", "on_sys_open_return")
        def open(cpu, pc, fname_ptr, flags, mode):
            fname = panda.read_str(cpu, fname_ptr)
            if self.collab_url in fname:
                self.report(cpu, "open filename", fname)

        @panda.ppp("syscalls2", "on_sys_openat_return")
        def openat(cpu, pc, fd, fname_ptr, flags):
            fname = panda.read_str(cpu, fname_ptr)
            if self.collab_url in fname:
                self.report(cpu, "openat filename", fname)

        @panda.ppp("syscalls2", "on_sys_creat_return")
        def creat(cpu, pc, fname_ptr, mode):
            fname = panda.read_str(cpu, fname_ptr)
            if self.collab_url in fname:
                self.report(cpu, "creat filename", fname)

        @panda.ppp("syscalls2", "on_sys_unlink_return")
        def unlink(cpu, pc, fname_ptr):
            fname = panda.read_str(cpu, fname_ptr)
            if self.collab_url in fname:
                self.report(cpu, "unlink filename", fname)

    def on_call(self, cpu, args):
        self.logger.info(f"Exec: {args}")
        s = ", ".join(args)
        for x in args:
            if 'burp' in x:
                self.logger.warning(f"MAYBE: {x} {self.collab_url}: {self.collab_url in x}")

            if self.collab_url in x:
                self.report(cpu, f"exec ({s})", x)
                break


    def report(self, cpu, msg, collab_str):
        # We saw a collaborator string in a notable place - report it
        self.logger.warning(f"REPORT {msg} to {collab_str}")

        # URL decode before matching (so we don't have to deal with %XX in regex
        collab_str = unquote(collab_str)

        m = self.matcher.match(collab_str)
        if not m:
            return

        url = "https://" + m.group(1) # match has no proto
        calltree = self.get_calltree(cpu)

        if not url.startswith("https://"):
            url = "https://" + url

        r = requests.post(url, data={"message": msg, "calltree": calltree})
        print(r.text)

    def get_calltree(self, cpu):
        # Print the calltree to the current process
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL: return
        procs = self.panda.get_processes_dict(cpu)
        chain = [{'name': self.panda.ffi.string(proc.name).decode('utf8', 'ignore'),
                  'pid': proc.pid, 'parent_pid': proc.ppid}]
        while chain[-1]['pid'] > 1 and chain[-1]['parent_pid'] in procs.keys():
            chain.append(procs[chain[-1]['parent_pid']])
        return " -> ".join(f"{item['name']} ({item['pid']})" for item in chain[::-1])

    def get_arg_list(self, cpu, argv_ptr):
        try:
            argv_buf = self.panda.virtual_memory_read(cpu, argv_ptr, 100, fmt='ptrlist')
        except ValueError:
            return []
        argv = []

        for ptr in argv_buf:
            if ptr == 0: break
            try:
                s = self.panda.read_str(cpu, ptr)
            except ValueError:
                s = "(error)"
            argv.append(s)
        return argv
