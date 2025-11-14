import threading, queue
from IPython.terminal.embed import InteractiveShellEmbed
from IPython import get_ipython # needs to be in scope for register_line_magic to work
from IPython.core.magic import register_line_magic
from penguin import Plugin, plugins, yaml, getColoredLogger

class Repl(Plugin):

    def __init__(self,panda):
        self.panda = panda
        self.locals = {'plugins':plugins,'panda':panda}
        self.logger = getColoredLogger("plugins.repl")
        self.node = None
        self.thread = None   
    def update_locals(self,local):
        if local == None:
            return
        if self.locals == None:
            self.locals = local
            return
        for key in local.keys():
            self.locals[key] = local[key]
    def repl(self):
        """
        Generator-capable IPython REPL

        Call with `yield from repl()`.
        Use `%yield_from` and `%yield_` line commands in place of `yield from` and `yield`.
        """
        print("test")
        # Spawn REPL in separate thread
        command_queue = queue.Queue(maxsize=1)
        result_queue = queue.Queue(maxsize=1)
        t = threading.Thread(
            target=self.repl_thread,
            args=(command_queue, result_queue),
        )
        t.start()

        # Process commands from REPL and send back results
        while True:
            command, arg = command_queue.get()
            match command:
                case "exit":
                    break
                case "yield_from":
                    result = yield from arg
                    result_queue.put(result)
                case "yield_":
                    result = yield arg
                    result_queue.put(result)

        # Wait for thread to exit
        t.join()

    def repl_thread(self,command_queue, result_queue):
        """
        Function for running the IPython REPL in a separate thread.
        The command queue is for sending `yield` and `yield from` commands to the generator,
        and the result queue is for getting the results back.
        """



        ip = InteractiveShellEmbed().instance()
        def test_loop(gen):
            command_queue.put(("yield_from", gen))
            return result_queue.get()
        @register_line_magic
        def yield_from(line):
            """
            The command `%yield_from code()` in the repl is the same as `yield from code()` in regular Python
            """
            command_queue.put(("yield_from", line))
            return result_queue.get()

        @register_line_magic
        def yield_(line):
            """
            The command `%yield_ code()` in the repl is the same as `yield code()` in regular Python
            """
            command_queue.put(("yield_", line))
            return result_queue.get()

        # Actually start the REPL
        ip.mainloop()

        # Send a special exit command to make it easier to clean up
        command_queue.put(("exit", None))


