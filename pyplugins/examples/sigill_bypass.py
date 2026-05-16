"""
SIGILL Bypass Plugin (sigill_bypass.py)
=======================================

This module provides a specific example of using the Signal Monitor API to
intercept SIGILL (illegal instruction) signals and bypass them from the hypervisor.
It demonstrates how to monitor signals, analyze guest state, and modify it
to implement or skip instructions.

Usage
-----

This plugin is intended for research and as an example. It can be enabled
in the Penguin configuration to automatically bypass SIGILL signals.

.. code-block:: yaml

    plugins:
      sigill_bypass:
        enabled: true
"""

from penguin import plugins, Plugin
import capstone
from typing import Optional

class SigillBypass(Plugin):
    """
    SIGILL Bypass Plugin
    ====================
    Example plugin that intercepts SIGILL and advances the PC to skip the instruction.
    """

    def __init__(self):
        super().__init__()
        self.md = None
        self.arch_name = None

    def init(self):
        """
        Initialize the plugin and register for signal events.
        """
        # Register for signal delivery events from the SignalMonitor plugin
        plugins.subscribe(plugins.signal_monitor, "signal_deliver", self.on_signal)
        
        # Register a hook for SIGILL in the guest driver
        plugins.signal_monitor.register_hook(sig=4) # SIGILL is usually 4

    def _get_capstone(self, cpu):
        """
        Initialize Capstone disassembler for the current architecture.
        """
        if self.md:
            return self.md

        self.arch_name = self.get_arg("conf")["core"]["arch"]
        if "x86_64" in self.arch_name:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif "arm" in self.arch_name:
            self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif "mips" in self.arch_name:
            self.md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)
        
        return self.md

    def on_signal(self, cpu, event):
        """
        Callback triggered when a signal is delivered in the guest.
        """
        if event.sig != 4: # Only handle SIGILL
            return

        self.logger.info(f"Intercepted SIGILL for process '{event.comm}' (PID {event.pid}) at PC 0x{event.pc:x}")

        # Try to disassemble the instruction at the faulting address to determine its length
        md = self._get_capstone(cpu)
        if not md:
            self.logger.warning(f"No disassembler available for architecture: {self.arch_name}")
            return

        try:
            # Read enough bytes for the longest possible instruction
            code = plugins.mem.read_bytes_panda(cpu, event.pc, 15)
            insns = list(md.disasm(code, event.pc))
            
            if insns:
                insn = insns[0]
                self.logger.info(f"Faulting instruction: {insn.mnemonic} {insn.op_str} (length {insn.size})")

                # Example of "implementing" an instruction from the hypervisor
                if insn.mnemonic == "ud2": # x86 undefined instruction
                    self.logger.info("Found UD2! Emulating it as a success-reporting instruction.")
                    # We could modify registers here to simulate the instruction's effect
                    # e.g., event.regs.rax = 0x1337

                # Bypass: Advance the program counter to the next instruction
                new_pc = event.pc + insn.size
                self.logger.info(f"Bypassing: Advancing PC from 0x{event.pc:x} to 0x{new_pc:x}")
                event.regs.set_pc(new_pc)
                
                # Silence the signal: Tell the guest driver to drop the signal
                event.drop = True
                self.logger.info("Signal dropped.")
            else:
                self.logger.warning(f"Could not disassemble instruction at 0x{event.pc:x}")
        
        except Exception as e:
            self.logger.error(f"Error during SIGILL bypass: {e}")
