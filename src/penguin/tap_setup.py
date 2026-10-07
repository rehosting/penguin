"""Root-side network setup for the wrapper's --tap mode.

The wrapper runs this as root in the container (with CAP_NET_ADMIN, /dev/net/tun
and /dev/vhost-net) in front of the penguin command. It:

  1. creates a tap device owned by the run's user, so QEMU can attach to it
     without privileges (config: network.tap);
  2. gives the container end of the tap an address, which the guest uses as its
     gateway;
  3. forwards every new connection arriving on the container's own interface to
     the guest, so <container ip>:<port> reaches <guest ip>:<port>; traffic the
     container makes itself (e.g. the telnet console on localhost) is untouched;
  4. drops to the run's user and execs the command.
"""

import argparse
import os
import subprocess
import sys

TAP_IFNAME = "tap0"
TAP_HOST_ADDR = "10.10.10.1/24"
TAP_GUEST_IP = "10.10.10.10"
UPLINK = "eth0"


def run(*cmd: str) -> None:
    subprocess.run(cmd, check=True)


def setup_tap(ifname: str, uid: int, gid: int, host_addr: str) -> None:
    run("ip", "tuntap", "add", "dev", ifname, "mode", "tap",
        "user", str(uid), "group", str(gid))
    run("ip", "addr", "add", host_addr, "dev", ifname)
    run("ip", "link", "set", ifname, "up")


def forward_to_guest(uplink: str, guest_ip: str) -> None:
    # nat/PREROUTING only sees the first packet of a connection, so replies to
    # connections the container opens itself aren't redirected.
    run("iptables", "-t", "nat", "-A", "PREROUTING", "-i", uplink,
        "-j", "DNAT", "--to-destination", guest_ip)
    # Let the guest reach out through the container's address too.
    run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink,
        "-j", "MASQUERADE")


def drop_privileges(uid: int, gid: int, groups: list[int]) -> None:
    os.setgroups(groups)
    os.setgid(gid)
    # setuid away from root also clears the permitted/effective capabilities.
    os.setuid(uid)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--groups", default="",
                        help="comma-separated supplementary group ids for the run")
    parser.add_argument("--ifname", default=TAP_IFNAME)
    parser.add_argument("--host-addr", default=TAP_HOST_ADDR)
    parser.add_argument("--guest-ip", default=TAP_GUEST_IP)
    parser.add_argument("--uplink", default=UPLINK)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no command given")
    if os.geteuid() != 0:
        sys.exit("tap_setup: must run as root (the wrapper's --tap flag does this)")

    setup_tap(args.ifname, args.uid, args.gid, args.host_addr)
    if os.path.exists(f"/sys/class/net/{args.uplink}"):
        forward_to_guest(args.uplink, args.guest_ip)
        print(f"[tap] {args.ifname} {args.host_addr} up; connections to this "
              f"container's {args.uplink} address are forwarded to {args.guest_ip}",
              flush=True)
    else:
        print(f"[tap] {args.ifname} {args.host_addr} up; no {args.uplink} in the "
              f"container, so nothing is forwarded to {args.guest_ip}", flush=True)

    groups = [int(g) for g in args.groups.split(",") if g]
    drop_privileges(args.uid, args.gid, groups)
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
