
from typing import Any, Optional
from penguin import plugins, Plugin

RETRY: int = 0xDEADBEEF
NO_CHANGE: int = 0xABCDABCD

mem = plugins.mem
kffi = plugins.kffi


class KernelVersion2(Plugin):
    """
    Represents a Linux kernel version and supports comparison operations.

    **Attributes**
    - `outdir` (`Optional[str]`): Output directory.
    - `sysname` (`Optional[str]`): System name.
    - `nodename` (`Optional[str]`): Node name.
    - `release` (`Optional[str]`): Kernel release string.
    - `version` (`Optional[str]`): Kernel version string.
    - `machine` (`Optional[str]`): Machine architecture.
    - `domainname` (`Optional[str]`): Domain name.

    """

    outdir: Optional[str]
    sysname: Optional[str]
    nodename: Optional[str]
    release: Optional[str]
    version: Optional[str]
    machine: Optional[str]
    domainname: Optional[str]


    def __init__(self) -> None:
 
        self.outdir = self.get_arg("outdir")
        self.sysname = self.get_arg("sysname")
        self.nodename = self.get_arg("nodename")
        self.release = self.get_arg("release")
        self.version = self.get_arg("kversion")
        self.machine = self.get_arg("machine")
        self.domainname = self.get_arg("domainname")

    def create_string(self) -> str:
        """
        Construct a comma-separated string of uname fields.

        Returns:
            str: The constructed uname string, with 'none' for missing fields.
        """
        uname_str = ""

        uname_str += self.sysname + "," if self.sysname else "none,"
        uname_str += self.nodename + "," if self.nodename else "none,"
        uname_str += self.release + "," if self.release else "none,"
        uname_str += self.version + "," if self.version else "none,"
        uname_str += self.machine + "," if self.machine else "none,"
        uname_str += self.domainname + "," if self.domainname else "none,"


        return uname_str

    @plugins.syscalls.syscall(
    name_or_pattern="sys_newuname", 
    on_enter=False,
    on_return=True,)

    def change_newuname(self, pt_regs, proto, syscall, *args):
 
        new_uname = self.create_string()
        new_uname_list = new_uname.split(',')
        uname_fields = ["sysname", "nodename", "release", "version", "machine", "domainname"]
        new_uname_dir = dict(zip(uname_fields, new_uname_list))

        (struct_ptr) = args[0]

        new_utsname = yield from plugins.kffi.read_type(args[0], "struct new_utsname")
       # breakpoint()

        for uname_field, field_val in new_uname_dir.items():
            #print(uname_field)
            if field_val != 'none':
                char_list = [ord(c) for c in field_val]
                char_list.extend([0] * (65 - len(field_val)))
                #print(char_list)
            
                for i in range(65):
                    getattr(new_utsname, uname_field)[i] = char_list[i]

            else:
                continue
                
                
                
        final = new_utsname.to_bytes()
        #print(f"buffer length {len(final)}")

        yield from plugins.mem.write_bytes(struct_ptr, final)
        # data = yield from plugins.mem.read_bytes(struct_ptr, 390)
        # print(data)
        
        # breakpoint()
        pt_regs.set_retval(1)


 
                
                
                
