"""
# Events API Plugin

This plugin provides a generic interface for handling hypercall-based events in the penguin system.
It maps event numbers (MAGIC values) to named events and their argument types, sets up hypercall handlers,
and allows other plugins to register callbacks for these events.

## Purpose

- Maps hypercall event numbers to named events and argument types.
- Sets up hypercall handlers that parse arguments and publish events.
- Allows plugins to register for named events and receive parsed arguments.

## Usage

This plugin is loaded automatically as part of the penguin plugin system. Other plugins can register
for named events (e.g., `igloo_open`, `igloo_string_cmp`) and receive callbacks with parsed arguments.

## Event Format

Each event is published with the parsed arguments as specified in the `EVENTS` mapping.

```python
EVENTS = {
    MAGIC_NUMBER: ('event_name', (arg_type1, arg_type2, ...)),
    ...
}
```

For example:

```python
0xB335A535: ('igloo_send_hypercall', (None, int, int)),
```

## Example

```python
from penguin import plugins

def on_open(cpu, filename, flags):
    print(f"Open: {filename} (flags={flags})")

plugins.subscribe(plugin_instance, "igloo_open", on_open)
```

"""

from penguin import plugins, Plugin
from hyper.consts import igloo_hypercall_constants as iconsts


EVENTS = {
    # MAGIC ->  (NAME,              (ARG1,...,ARGN))
    iconsts.IGLOO_OPEN:         ('igloo_open',            (str, int)),
    101:                ('igloo_string_cmp',      (str,)),
    102:                ('igloo_string_cmp',      (str,)),
    103:                ('igloo_getenv',          (str,)),
    104:                ('igloo_strstr',          (str, str)),
    iconsts.IGLOO_IOCTL_ENOTTY: ('igloo_ioctl',           (str, int)),
    107:                ('igloo_nvram_get_miss',  (str,)),
    108:                ('igloo_nvram_get_hit',   (str,)),
    109:                ('igloo_nvram_set',       (str, str)),
    110:                ('igloo_nvram_clear',     (str,)),
    iconsts.IGLOO_IPV4_SETUP:   ('igloo_ipv4_setup',      (str, int)),
    iconsts.IGLOO_IPV4_BIND:    ('igloo_ipv4_bind',       (int, bool)),
    iconsts.IGLOO_IPV6_SETUP:   ('igloo_ipv6_setup',      (str, int)),
    iconsts.IGLOO_IPV6_BIND:    ('igloo_ipv6_bind',       (int, bool)),
    iconsts.IGLOO_IPV4_RELEASE: ('igloo_ipv4_release',    (str, int)),
    iconsts.IGLOO_IPV6_RELEASE: ('igloo_ipv6_release',    (str, int)),
    iconsts.IGLOO_HYP_UNAME:    ('igloo_uname',           (int, int)),
    iconsts.IGLOO_HYP_ENOENT:   ('igloo_hyp_enoent',      (str,)),
    0xB335A535:         ('igloo_send_hypercall',  (None, int, int)),
    # crc32("busybox")
    0x8507FAE1: ('igloo_shell', (int, int, int)),
}


class Events(Plugin):
    """
    # Events Plugin

    Handles hypercall-based events and publishes them as named events for other plugins to subscribe to.

    ## Features

    - Registers all known event names for notification.
    - Sets up hypercall handlers for each event.
    - Publishes events with parsed arguments to subscribers.
    """

    def __init__(self):
        """
        ## Initialize the Events plugin

        Registers all known event names for notification and sets up callback storage.
        """
        # MAGIC -> [fn1, fn2, fn3,...]
        self.callbacks = {}

        for event_num, (name, args) in EVENTS.items():
            plugins.register(self, name, register_notify=self.register_notify)

    def _setup_hypercall_handler(self, magic, arg_types):
        """
        ## Set up a hypercall handler for a given magic number and argument types

        **Args:**
        - `magic` (`int`): The hypercall magic number.
        - `arg_types` (`tuple`): Tuple of argument types (int, str, bool, or None).

        The handler parses arguments from the CPU context and publishes the event.
        """
        @self.panda.hypercall(magic)
        def generic_hypercall(cpu):
            # argument parsing
            args = [cpu]
            for i, arg in enumerate(arg_types):
                argval = self.panda.arch.get_arg(
                    cpu, i + 1, convention="syscall")
                if arg is int:
                    args.append(argval)
                elif arg is str:
                    try:
                        s = self.panda.read_str(cpu, argval)
                    except ValueError:
                        self.logger.debug(
                            f"arg read fail: {magic} {argval:x} {i} {arg}"
                        )
                        self.panda.arch.set_retval(cpu, 1)
                        return
                    args.append(s)
                elif arg is bool:
                    args.append(argval != 0)
                elif arg is None:
                    # ignore this argument
                    pass
                else:
                    raise ValueError(f"Unknown argument type {arg}")
            plugins.publish(self, self.callbacks[magic], *args)

    def register_notify(self, name, callback):
        """
        ## Register a callback for an event

        **Args:**
        - `name` (`str`): The event name.
        - `callback` (`callable`): The callback function to register.

        Registers the callback for the specified event name.
        Raises a ValueError if the event name is not found.
        """
        for magic, (ename, arg_types) in EVENTS.items():
            if ename == name:
                if self.callbacks.get(magic, None) is None:
                    self._setup_hypercall_handler(magic, arg_types)
                    self.callbacks[magic] = []
                self.callbacks[magic] = name
                return
        raise ValueError(f"Events has no event {name}")
