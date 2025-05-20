from pandare2 import PyPlugin
from penguin import plugins
from events.types import Exec


class ExecsLogger(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB
        plugins.subscribe(plugins.Events, "igloo_exec", self.on_igloo_exec)

    def on_igloo_exec(self, cpu, fname, argv, env, proc_name, proc_pid):
        # Add event to DB using the Exec type from events.types
        self.DB.add_event(
            Exec(
                procname=proc_name,
                pid=proc_pid,
                fname=fname,
                argv=' '.join(argv),
                env='\n'.join(env),
            )
        )
