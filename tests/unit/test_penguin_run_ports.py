import os
import socket
import unittest
from contextlib import closing
from unittest.mock import patch

from penguin.penguin_run import find_free_port


def _reserve_port_with_free_successor():
    for base in range(30000, 65000):
        reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            reserved.bind(("0.0.0.0", base))
        except OSError:
            reserved.close()
            continue

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
            try:
                probe.bind(("0.0.0.0", base + 1))
            except OSError:
                reserved.close()
                continue
        return base, reserved

    raise RuntimeError("could not find a two-port free block for test")


class TestFindFreePort(unittest.TestCase):
    def test_compose_range_searches_within_reserved_block(self):
        base, reserved = _reserve_port_with_free_successor()
        self.addCleanup(reserved.close)
        env = {
            "PENGUIN_TELNET_PORT_BASE": str(base),
            "PENGUIN_TELNET_PORT_RANGE": "2",
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(find_free_port(), base + 1)

    def test_invalid_env_fails_clearly(self):
        with patch.dict(os.environ, {"PENGUIN_TELNET_PORT_BASE": "bad"}, clear=False):
            with self.assertRaisesRegex(ValueError, "PENGUIN_TELNET_PORT_BASE"):
                find_free_port()


if __name__ == "__main__":
    unittest.main()
