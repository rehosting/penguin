import socket
from os import environ as env
from os.path import join
from typing import Optional
import json


def in_container() -> bool:
    return env.get("PENGUIN_PROJECT_DIR", None) is not None


def send_command(data: dict = None, sock: Optional[str] = None) -> Optional[dict]:
    if sock is None:
        if in_container():
            sock = join(env["PENGUIN_PROJECT_DIR"],
                        "results", "latest", "penguin.sock")
        else:
            raise Exception("Socket path required")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.connect(sock)
        c.sendall(json.dumps(data).encode())
        c.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk

        if not data:
            return
        try:
            resp = json.loads(data.decode())
        except json.JSONDecodeError:
            print("Error decoding response:", data.decode())
            return
        return resp
