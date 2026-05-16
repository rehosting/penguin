from penguin import plugins

# This is a ScriptingPlugin. The code runs at module load time.

def on_signal_deliver(cpu, event):
    """
    Callback triggered when a signal is delivered in the guest.
    """
    logger = plugins.logger # Get the logger passed to the script
    if event.sig != 4: # Only handle SIGILL
        return

    logger.info(f"Intercepted SIGILL for process '{event.comm}' (PID {event.pid}) at PC 0x{event.pc:x}")

    # Tell the guest driver to drop the signal
    logger.info("Signal dropped.")
    event.drop = True

    # Attempt to advance the program counter to skip the faulting instruction.
    if event.regs:
        try:
            new_pc = event.regs.get_pc() + 2 # A 'ud2' is 2 bytes on x86
            event.regs.set_pc(new_pc)
            logger.info(f"Advanced PC to 0x{new_pc:x} to bypass instruction.")
        except Exception as e:
            logger.error(f"Failed to advance PC during signal bypass: {e}")

def register_sigill_hook():
    """
    Coroutine to register the hook.
    """
    logger = plugins.logger
    logger.info("Registering SIGILL hook via signal_interception_test script...")
    # Register a hook specifically for SIGILL (signal 4)
    yield from plugins.signal_monitor.register_hook(sig=4)
    plugins.subscribe(plugins.signal_monitor, "signal_deliver", on_signal_deliver)
    logger.info("SIGILL hook registered and subscribed successfully.")

# Since this is a ScriptingPlugin, we are in a synchronous context.
# We need to schedule our async registration function to be run by PANDA's event loop.
plugins.panda.queue_async(register_sigill_hook())
