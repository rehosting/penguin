from pandare import PyPlugin

class MemLoad(PyPlugin):
    def __init__(self, panda):
        #panda.load_plugin("memload")
        print("Load SSM")
        panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
        panda.load_plugin("stringsearch",
             args={"str": "PANDASTR",
                   "verbose": False})
        print("Loaded it")

        #target_cstr = panda.ffi.new("char[]", b"PANDASTR")
        #panda.plugins['stringsearch'].add_string(target_cstr)

        @panda.ppp("stringsearch", "on_ssm")
        def string_hit(cpu, pc, addr, str_buf, strlen, is_write, in_mem):
            if is_write:
                return
            
            if addr in [0xbeffff6b, 0xbeffff2e]:
                return # XXX WIP
            
            if pc == 0xc0303f30:
                return # XXX hack


            s = panda.ffi.string(str_buf)[:strlen].decode()
            cur_proc = panda.get_process_name(cpu)
            print(f"{cur_proc} matches {s} {hex(addr)} at {pc:x}")