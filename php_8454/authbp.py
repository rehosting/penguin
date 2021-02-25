import logging
import random
import urllib3
import requests
from bs4 import BeautifulSoup
import coloredlogs

from StateTreeFilter import StateTreeFilter, StateAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
coloredlogs.DEFAULT_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
coloredlogs.install()

class Authbp():

    def __init__(self, panda, domain, mountpoint, auth_url="index.html", timeout=60):
        self.panda = panda
        self.domain = domain
        if not self.domain.endswith("/"):
            self.domain += "/"
        self.timeout = timeout

        self.s = StateTreeFilter('inactive', debug=True)
        local_log = logging.getLogger('panda.authbp')
        self.logger = StateAdapter(local_log, {'state': self.s})

        @self.panda.queue_blocking
        def driver():
            '''
            Make a request to auth page and print results. Hardcoded path + cookie for now
            '''
            burp0_url = self.domain+"authentication.cgi"
            burp0_cookies = {"uid": "57ZdZR2dOI"}
            burp0_headers = {"Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"}

            print("\nAttempting login with forced execution...")

            self.first_login = True

            for idx in range(100):
                self.pwd = f"PANDA__{idx}__PASS"
                burp0_data = {"id": "Admin", "password": self.pwd}

                p = panda.ffi.new("char[]", self.pwd.encode())
                self.panda.plugins['stringsearch'].add_string(p)

                if self.first_login:
                    self.s.change_state('active.collect')
                    self.auth_branches = set()
                else:
                    self.s.change_state('active.flip')

                r = requests.post(burp0_url, headers=burp0_headers,
                                    cookies=burp0_cookies, data=burp0_data)
                self.panda.plugins['forcedexec'].disable_forcedexec()

                self.s.change_state('inactive')
                print("Response:", r.text)

                # First attempt, initialize state
                if self.first_login:
                    self.first_login = False

                    # Create ordered + immutable list, set idx to flip
                    self.auth_flip_idx = 28 # XXX DEBUG
                    self.auth_branch_list = list(self.auth_branches)
                    self.logger.info(f"Found {len(self.auth_branches)} branches to force")

                else:
                    self.auth_flip_idx += 1
                    if self.auth_flip_idx >= len(self.auth_branches):
                        print("DONE")
                        self.panda.end_analysis()

            self.panda.end_analysis()

        self.panda.load_plugin("forcedexec", {"disabled": True})

        @self.panda.ppp("forcedexec", "on_branch")
        @self.s.state_filter("active.collect", default_ret=False)
        def branch_collect(cpu, tb, idx):
            if not self.panda.in_kernel(cpu) and tb.pc < 0x20000000:
                if self._active_proc_name(cpu).startswith('authentication'):
                    self.auth_branches.add(tb.pc) # Collecting
            return False

        @self.panda.ppp("forcedexec", "on_branch")
        @self.s.state_filter("active.flip", default_ret=False)
        def branch_flip(cpu, tb, idx):
            if not self.panda.in_kernel(cpu) and tb.pc < 0x20000000:
                if self._active_proc_name(cpu).startswith('authentication'):
                    if tb.pc == self.auth_branch_list[self.auth_flip_idx]:
                        print(f"Flip {self.auth_flip_idx} branch: 0x{tb.pc:x}")
                        return True
                    elif tb.pc not in self.auth_branches:
                        # Randomly flip
                        if bool(random.getrandbits(1)):
                            print(f"New PC: 0x{tb.pc:x} - flip")
                            return True
                        print(f"New PC: 0x{tb.pc:x} - noflip")


            return False

        @self.panda.ppp("stringsearch", "on_ssm")
        @self.s.state_filter("active")
        def string_hit(cpu, pc, addr, str_buf, strlen, is_write, in_mem):
            s = panda.ffi.string(str_buf)[:strlen].decode()
            name = self._active_proc_name(cpu)
            #if is_write:
            #    return

            if s == self.pwd:
                if is_write: return
                self.logger.info("[stringsearch] saw password")
                #self.panda.load_plugin('coverage', {'process_name': name, 'privilege': 'user'})

                p = self.panda.ffi.new("char[]", "ERR_TIMEOUT_OR_BADUID".encode())
                self.panda.plugins['stringsearch'].add_string(p)

                # Start considering branches to flip
                self.panda.plugins['forcedexec'].enable_forcedexec()

            elif s == "ERR_TIMEOUT_OR_BADUID":
                self.logger.info("[stringsearch] saw auth invalid")
                # Will double disable but should be ok?
                self.panda.plugins['forcedexec'].disable_forcedexec()


    # Helpers
    def _active_proc_name(self, cpu):
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL: return ""
        return self.panda.ffi.string(proc.name).decode("utf8", errors="ignore")

    def go(self):
        # Start emulation in main thread
        self.panda.enable_memcb()
        self.panda.run()
