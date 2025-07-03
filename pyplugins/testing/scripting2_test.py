# Example scripting plugin for Penguin
# This script demonstrates how to use scripting plugins with the Penguin plugin manager.
# It uses the global 'plugins' object for API access and the injected 'logger' for logging.
# No class definition is needed; top-level code is executed at load time.
# The 'uninit' function will be called automatically when the plugin is unloaded.

# 'plugins' and 'logger' are injected automatically by the plugin manager.

getpid_ran = False


@plugins.syscalls.syscall("on_sys_getpid_enter")
def getpid_enter(*args):
    """
    This function is registered as a syscall callback for 'on_sys_getpid_enter'.
    It writes a message to a file the first time it is called.
    """
    global getpid_ran
    if getpid_ran:
        return
    logger.info("Received getpid_enter syscall")
    outdir = plugins.get_arg("outdir")
    with open(f"{outdir}/scripting2_test.txt", "w") as f:
        f.write("Hello from scripting2_test.py\n")
    getpid_ran = True


def uninit():
    """
    This function is called when the scripting plugin is unloaded.
    It appends a message to the output file, or writes a failure message if the syscall was never triggered.
    """
    logger.info("Got uninit() call")
    outdir = plugins.get_arg("outdir")
    if getpid_ran:
        with open(f"{outdir}/scripting2_test.txt", "a") as f:
            f.write("Unloading scripting2_test.py\n")
    else:
        with open(f"{outdir}/scripting2_test.txt", "w") as f:
            f.write("FAIL: scripting2_test.py was never run\n")
