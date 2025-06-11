from events import Exec
from penguin import plugins, Plugin


def get_calltree(panda):
    # Print the calltree to the current process
    # 1) Get the current process
    cpu = panda.get_cpu()
    proc = panda.plugins["osi"].get_current_process(cpu)
    if proc == panda.ffi.NULL:
        print("Error determining current process")
        return

    # 2) Get a dict of all processes
    procs = panda.get_processes_dict(cpu)

    # 3) Construct a list of the current process and all its parents
    chain = [
        {
            "name": panda.ffi.string(proc.name).decode("utf8", "ignore"),
            "pid": proc.pid,
            "parent_pid": proc.ppid,
        }
    ]

    while chain[-1]["pid"] > 1 and chain[-1]["parent_pid"] in procs.keys():
        chain.append(procs[chain[-1]["parent_pid"]])

    # 4) Return a printable string representing the calltree
    return " -> ".join(f"{item['name']} ({item['pid']})" for item in chain[::-1])


class ExecLog(Plugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB

        panda.ppp("proc_start_linux", "on_rec_auxv")(self.rec_auxv)

    def rec_auxv(self, cpu, tb, av):
        args = " ".join(
            [
                self.panda.ffi.string(av.argv[i]).decode(errors="ignore")
                for i in range(av.argc)
            ]
        )
        envp = ", ".join(
            [
                self.panda.ffi.string(av.envp[i]).decode(errors="ignore")
                for i in range(av.envc)
            ]
        )
        self.DB.add_event(
            Exec(
                calltree=get_calltree(self.panda),
                argc=av.argc,
                argv=args,
                envp=envp,
                euid=av.euid,
                egid=av.egid,
            )
        )
