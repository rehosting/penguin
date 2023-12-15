from pandare import PyPlugin
import logging
import re
import coloredlogs
logging.basicConfig(level=logging.DEBUG)
coloredlogs.DEFAULT_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
coloredlogs.install()

DEBUG_PATH = "/igloo/trace.php"
PREFIX = f" declare(ticks = 1); include_once('{DEBUG_PATH}'); ".encode()
START = b"<?"
START_RE = r"(<\?)".encode()
END = b"?>"

class PhpTrace(PyPlugin):
    '''
    Assuming guest filesystem has our debug script at DEBUG_PATH, inject the necessary
    changes into every .php file run by the guest (note, it's based off file extension)
    such that our debug script is run, writing trace info to /tmp/igloo_log.txt. We'll
    then capture that info and trigger a PPP-style callback on_php_coverage(file, line, code)
    '''
    def __init__(self, panda):
        self.logger = logging.getLogger("PhpTrace")
        self.logger.info("Loaded")
        if panda is None:
            return # Debugging
        self.panda  = panda
        self.ppp_cb_boilerplate('on_php_coverage')

        @panda.ppp("syscalls2", "on_sys_newfstat_return") # XXX inconsistent naming
        def post_fstat(cpu, pc, fd, buf):
            if not (fname := self.target_fd(cpu, fd, 'fstat')):
                return

            # In the `struct stat`, where is the field st_size?
            st_size_offset = 0x30 # X86_64 size, not sure about others. 0x30 for MIPSEB too? Hmm maybe not?
            try:
                old_size = int.from_bytes(panda.virtual_memory_read(cpu, buf+st_size_offset, 4), panda.endianness)
            except ValueError:
                self.logger.error("Unable to read original size in fstat")
                return
            new_size = old_size + len(PREFIX)
            self.logger.info(f"Fstat on {fname} original size was {old_size}, new size is {new_size}")
            panda.virtual_memory_write(cpu, buf+st_size_offset, int.to_bytes(new_size, 4, panda.endianness))

        @panda.ppp("syscalls2", "on_sys_read_enter")
        def pre_read(cpu, pc, fd, buf, count):
            if not self.target_fd(cpu, fd, 'read'):
                return
            # Need file descriptor consistency - if we're requesting a read of 100 bytes
            # But we're going to add an extra 10 bytes to it, we need to make the request
            # be for 90 bytes so the next read continues from the correct place.

            # This isn't going to work.
            if count < len(PREFIX):
                self.logger.error("Tiny read")
                return
            panda.arch.set_arg(cpu, 3, count-len(PREFIX), convention='syscall')



        @panda.ppp("syscalls2", "on_sys_read_return")
        def post_read(cpu, pc, fd, buf, count):
            if not self.target_fd(cpu, fd, 'read'):
                return

            actual_count = panda.arch.get_retval(cpu, convention='syscall') # Get actual size
            if actual_count <= 0:
                return
            try:
                read_buf = panda.virtual_memory_read(cpu, buf, actual_count) # Read original buffer
            except ValueError:
                self.logger.warning("Unable to read buffer after read. Ignoring")
                return

            if b'<?' not in read_buf:
                return

            at_max_len = (actual_count == count)
            new_buf = self.rewrite_target(read_buf, truncate=at_max_len)
            panda.virtual_memory_write(cpu, buf, new_buf)
            panda.arch.set_retval(cpu, len(new_buf), convention='syscall')

        @panda.ppp("syscalls2", "on_sys_mmap_return")
        def post_mmap(cpu, pc, addr, length, prot, flags, fd, offset):
            if not self.target_fd(cpu, fd, 'mmap'):
                return

            # REWRITE BUFFER!
            if length <= 0:
                return

            real_addr = panda.arch.get_retval(cpu, convention='syscall') # Note requested ADDR may be NULL
            try:
                mmap_buf = panda.virtual_memory_read(cpu, real_addr, length) # Read original buffer
            except ValueError:
                self.logger.warning(f"Unable to read MMAP'd buffer from FD at {real_addr:x}. Force guest to retry")
                panda.arch.set_retval(cpu, panda.to_unsigned_guest(-11), convention='syscall'), # EAGAIN
                return

            if b'<?php' not in mmap_buf:
                return

            new_buf = self.rewrite_target(mmap_buf)
            panda.virtual_memory_write(cpu, real_addr, new_buf)

        # Hook output
        @panda.ppp("syscalls2", "on_sys_write_return")
        def post_write(cpu, pc, fd, buf, count):
            if self.target_fd(cpu, fd, context='igloo_write'):
                count = self.panda.arch.get_retval(cpu, convention='syscall')
                buf = self.panda.virtual_memory_read(cpu, buf, count)
                file, line, *code = buf.split(b",")
                code = b",".join(code)
                self.ppp_run_cb('on_php_coverage', file.decode(), int(line), code.decode())

    def target_fd(self, cpu, fd, context=None):
        if fd == 0xffffffff:
            #self.logger.info(f"fd=-1 in {context}")
            return False
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL:
            self.logger.info(f"Unknown proc in {context}")
            return False
        fname_obj = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
        if fname_obj == self.panda.ffi.NULL:
            #self.logger.info(f"Bad filename in {self.panda.ffi.string(proc.name)} from proc {context}")
            return False
        fname = self.panda.ffi.string(fname_obj).decode()
        #self.logger.debug(f"Filename: {fname}")

        if context == 'igloo_write':
            if fname == '/tmp/igloo_log.txt':
                return True
            else:
                return False
        else:
            if not fname.endswith(".php"):
                return False
            if fname == DEBUG_PATH:
                return False # Don't instrument our debug script!

        self.logger.info(f"Found php file descriptor in proc {self.panda.ffi.string(proc.name)} with context {context}: {fname}")
        return fname

    def rewrite_target(self, contents, truncate=False):
        self.logger.info(f"Replacing string: {contents}")
        sections = [] # Tuples of (is_php, "contents", terminated)
        # e.g. "<?php echo 'hello'; ?> not-php"
        # should become (True, "<?php echo 'hello'; ?>" True), (False "not-php", True))

        if START not in contents:
            return contents

        last_start = False
        for idx, sect in enumerate(re.split(START_RE, contents)): #"pre-php", "~~<?php~~ asdf ?> not-php", "~~<?php~~ ..."
            start_tag = b''
            if sect == START:
                last_start = True
                continue
            if last_start:
                sect = START + sect
                last_start = False
            if sect.startswith(b"<?php"): #<?php
                start_tag=b'<?php'
                sect = sect[5:]
            elif sect.startswith(b"<?"):
                start_tag = b"<?"
                sect = sect[2:]

            if start_tag: # only if it's PHP
                if END in sect:
                    # Need to split on end delim to get post-php as HTML. Only split on the first one - XXX will break if php contains something like "?>"
                    start, end = sect.split(END, 1)
                    sections.append((start_tag, start, True))
                    sections.append((b'', end, False))
                    continue
                else:
                    # Unterminated PHP - must be last one
                    sections.append((start_tag, sect, False))
                    continue

            # Easy case: Unmixed: either pure php or nophp
            sections.append((start_tag, sect, False))

        output = b""
        first_php = True
        for (start_tag, text, terminated) in sections:
            if start_tag:
                if first_php:
                    first_php = False
                    text = PREFIX + text

                text = start_tag + text
                if terminated:
                    text += END
            output += text

        if truncate and len(output) > len(contents):
            output = output[:len(contents)]

        self.logger.info(f"New string is: {output}")
        return output

if __name__ == '__main__':

    tests = [#b'<?php\nhello world?>',
             #b'<? hello world ?>',
             #b'Testing. <?php echo "hi"; ?>',
             #b'Testing. <?php echo "hi"; ?> nonphp',
             b"""
             <?php
             echo "hi";
             """]
    for test in tests:
        p = PhpTrace(None)
        new = p.rewrite_target(test)
        print(test.decode())
        print("-----")
        print(new.decode())
        print("-----")
        print("-----")
        print("-----")
