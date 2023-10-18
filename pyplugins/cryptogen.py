from pandare import PyPlugin
from sys import stderr


class CryptoGen(PyPlugin):
    def __init__(self, panda):
        outdir = self.get_arg("outdir") # may be None
        self.log = open(outdir + "/cryptogen.log", "w")
        self.panda = panda
        panda.ppp("syscalls2", "on_sys_execve_enter")(self.crypto_execve)
        panda.ppp("syscalls2", "on_sys_execveat_enter")(self.crypto_execveat)

    def crypto_execve(self, cpu, pc, fname_ptr, argv_ptr, envp):  
        self.handle_crypto(cpu, fname_ptr, argv_ptr)
        

    def crypto_execveat(self, cpu, pc, dfd, fname_ptr, argv_ptr, envp, flags):
        self.handle_crypto(cpu, fname_ptr, argv_ptr)

    def handle_crypto(self, cpu, fname_ptr, argv_ptr):
        try:
            fname = self.panda.read_str(cpu, fname_ptr)
            argv_buf = self.panda.virtual_memory_read(cpu, argv_ptr, 100, fmt='ptrlist')
        except ValueError:
            return

        if "/" in fname:
            fname = fname.split("/")[-1]

        if fname not in ["openssl", "ssh-keygen"]:
            self.log.write(f"Ignoring: {fname}\n")
            return

        self.log.write(f"CRYPTO0: {fname}\n")

        argv = []
        for ptr in argv_buf:
            if ptr == 0: break
            try:
                argv.append(self.panda.read_str(cpu, ptr))
            except ValueError:
                argv.append("(error)")

        self.log.write(f"Detected non-deterministic crypto: {fname} {argv}\n")
        # TODO: if we get a supported openssl command, change execve to be a cp of target key to destination
        
        getattr(self, f"handle_{fname.replace('-','_')}")(cpu, argv)

    def handle_openssl(self, cpu, argv):
        # TODO: model openssl behavior. Open issue, how do we write to guest files?
        pass

    def handle_ssh_keygen(self, cpu, argv):
        # TODO: model ssh-keygen behavior. Open issue, how do we write to guest files?
        pass

    def uninit(self):
        if hasattr(self, 'log'):
            self.log.close()
            del self.log