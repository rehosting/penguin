import threading
import queue
import os
from IPython.terminal.embed import InteractiveShellEmbed
from IPython.utils.path import ensure_dir_exists
from penguin import Plugin, plugins, getColoredLogger


class Repl(Plugin):

    def __init__(self, panda):
        self.panda = panda
        self.locals = {'plugins': plugins, 'panda': panda}
        self.logger = getColoredLogger("plugins.repl")
        self.proj_dir = self.get_arg("proj_dir")
        self.ipython_dir = os.path.join(self.proj_dir, ".ipython")
        ensure_dir_exists(self.ipython_dir)
        self.base_image = InteractiveShellEmbed(ipython_dir=self.ipython_dir)
        self.thread = None

    def repl(self):
        """
        Generator-capable IPython REPL

        Call with `yield from repl()`.
        Use `%yield_from` and `%yield_` line commands in place of `yield from` and `yield`.
        """
        local = self.base_image.get_local_scope(1)
        # Spawn REPL in separate thread
        command_queue = queue.Queue(maxsize=1)
        result_queue = queue.Queue(maxsize=1)
        self.thread = threading.Thread(
            target=self.repl_thread,
            args=(command_queue, result_queue, local),
        )
        self.thread.start()

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
        self.thread.join()

    def repl_thread(self, command_queue, result_queue, local):
        """
        Function for running the IPython REPL in a separate thread.
        The command queue is for sending `yield` and `yield from` commands to the generator,
        and the result queue is for getting the results back.
        """

        def y(gen):
            command_queue.put(("yield_from", gen))
            return result_queue.get()

        ip = self.base_image.instance()
        local['y'] = y
        local['plugins'] = plugins
        # Actually start the REPL
        ip.mainloop(local_ns=local)

        # Send a special exit command to make it easier to clean up
        command_queue.put(("exit", None))
