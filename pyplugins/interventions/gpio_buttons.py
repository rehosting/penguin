"""Model board GPIO button inputs as released so firmware does not see a stuck
button (which asuswrt would treat as a held reset/WPS press).

asuswrt reads buttons (reset/wps/wl-toggle/...) via libshared ``get_gpio()``,
which does ``ioctl(/dev/gpio, 0xC018423E, struct[24])`` where::

    struct+8  = pin | 0x8000        (0x8000 = GPIO_ACTIVE_LOW flag)
    struct+12 = returned pin value  (filled by the driver)

``button_pressed()`` then reads that value: for an active-low button (reset/wps)
value 0 = pressed, non-zero = released; for active-high, non-zero = pressed.

With no real board GPIO, the ``/dev/gpio`` pseudofile ioctl leaves the value at
0, so every active-low button reads *pressed* -- the ASUS watchdog spams
"button RESET pressed" and can eventually trigger a factory reset. This plugin
intercepts the gpio-get ioctl and writes the released level into ``struct+12``
(1 for active-low, 0 for active-high), so all buttons read released.
"""
from penguin import Plugin, PluginArgs, plugins

BOARD_IOCTL_GET_GPIO = 0xC018423E   # _IOWR('B', 62, struct[24]) - libshared get_gpio
GPIO_ACTIVE_LOW = 0x8000            # flag OR'd into struct+8 by get_gpio
OFF_PINWORD = 8                     # struct offset: pin | flags (request)
OFF_VALUE = 12                      # struct offset: returned pin value


class gpio_buttons(Plugin):
    class Args(PluginArgs):
        pass

    def __init__(self):
        self.n = 0
        self.seen_pins = set()
        self.logger.setLevel("INFO")
        self.logger.info(
            f"gpio_buttons loaded (ioctl=0x{BOARD_IOCTL_GET_GPIO:08x}, "
            "buttons read as released)")

    @plugins.syscalls.syscall("on_sys_ioctl_return",
                              arg_filters=[None, BOARD_IOCTL_GET_GPIO, None])
    def _gpio_get(self, regs, proto, syscall, fd, request, arg):
        # arg is the 24-byte board_ioctl struct pointer (32-bit userland ptr,
        # but it is the syscall arg value directly -- no deref widening needed).
        pinword = (yield from plugins.mem.read_int(arg + OFF_PINWORD)) & 0xFFFFFFFF
        active_low = bool(pinword & GPIO_ACTIVE_LOW)
        pin = pinword & 0x7FFF
        # Released level: active-low inputs idle high (1), active-high idle low (0).
        released = 1 if active_low else 0
        yield from plugins.mem.write_int(arg + OFF_VALUE, released)
        syscall.retval = 0
        self.n += 1
        if pin not in self.seen_pins:
            self.seen_pins.add(pin)
            self.logger.info(
                f"gpio_get pin={pin} active_low={active_low} -> released="
                f"{released} (first sighting)")
