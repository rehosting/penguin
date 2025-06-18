"""
# Exec Logger Plugin

This plugin records process execution (exec) events to the penguin database. It subscribes to `exec_event`
events published by the `execs` plugin, extracts relevant execution details, and stores them as `Exec` events
in the database.

## Purpose

- Monitors process execution events in the guest.
- Records argument vectors, environment, and process credentials for each exec event.
- Enables later analysis of process launches and their context.

## Usage

This plugin is loaded automatically as part of the penguin plugin system. It requires the `execs` plugin
to be active, as it listens for `exec_event` events.

The plugin extracts relevant fields and stores them in the database using the `Exec` event type.
"""

from penguin import plugins, Plugin
from events.types import Exec

class ExecLog(Plugin):
    """
    # ExecLog Plugin

    Plugin for logging process execution (exec) events to the database.

    Subscribes to `exec_event` events from the `execs` plugin and records them as `Exec` events.
    """
    def __init__(self):
        """
        ## Initialize the ExecLog plugin

        Registers a subscription to the `exec_event` event published by the `execs` plugin.
        """
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB
        # Subscribe to exec_event published by execs plugin
        plugins.subscribe(self, "exec_event", self.on_exec_event)

    def on_exec_event(self, event):
        """
        ## Callback for handling `exec_event` events

        **Args:**
        - `event` (`dict` or `Wrapper`): The exec event data, either as a dictionary or a Wrapper object.

        Extracts argument count, argument vector, environment, and process credentials,
        then records the event in the database as an `Exec` event.
        """
        # event is a Wrapper, unwrap to dict
        data = event.unwrap() if hasattr(event, "unwrap") else event
        argc = str(len(data.get("argv", [])))
        argv_str = str(data.get("argv", []))
        envp_str = str(data.get("envp", {}))
        parent = data.get("parent", None)
        # Try to get euid/egid, fallback to -1 if not available
        if parent:
            euid = parent.euid
            egid = parent.egid
        else:
            euid = -1
            egid = -1
        
        self.DB.add_event(
            Exec(
                calltree="",
                argc=argc,
                argv=argv_str,
                envp=envp_str,
                euid=euid,
                egid=egid,
            )
        )
