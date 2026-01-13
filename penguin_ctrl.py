#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import os

def main():
    parser = argparse.ArgumentParser(
        description="Control Penguin DynEvents Plugin via Unix Socket",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Format Specifiers:
  Standard: %d, %u, %x, %p, %c, %s
  OS Info:  %fd (FD Name), %proc (Process Name)
  Memory:   %u8-%u64, %i8-%i64, %x8-%x64

Syntax:
  print ARGS...           (Prints arguments at entry)
  print ARGS... = RET...  (Captures arguments at entry, prints with return value at exit)

Examples:
  # Trace malloc args (Entry)
  penguin_ctrl.py uprobe --path /lib/libc.so.6 --symbol malloc --action "print %d"

  # Trace malloc args AND return value (Exit)
  penguin_ctrl.py uprobe --path /lib/libc.so.6 --symbol malloc --action "print %d = %p"
  
  # Syscall: Print args
  penguin_ctrl.py syscall --name sys_write --action "print %fd, %s, %d"
        """
    )
    parser.add_argument("--sock", default="results/latest/penguin_events.sock", help="Path to plugin socket")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    load = subparsers.add_parser("load", help="Load plugin")
    load.add_argument("name")

    def add_args(p, path=False):
        p.add_argument("--path", required=path)
        p.add_argument("--symbol", required=path)
        if not path: p.add_argument("--name", required=True)
        p.add_argument("--action", required=True)
        p.add_argument("--proc")
        p.add_argument("--pid", type=int)

    add_args(subparsers.add_parser("uprobe"), True)
    add_args(subparsers.add_parser("syscall"), False)

    subparsers.add_parser("list")
    dis = subparsers.add_parser("disable")
    dis.add_argument("id", type=int, nargs="?")

    args = parser.parse_args()
    
    cmd = {}
    if args.command == "load": cmd = {"type": "load_plugin", "name": args.name}
    elif args.command == "list": cmd = {"type": "list"}
    elif args.command == "disable": 
        cmd = {"type": "disable"}
        if args.id is not None: cmd["id"] = args.id
    elif args.command == "uprobe":
        cmd = {"type": "uprobe", "path": args.path, "symbol": args.symbol, 
               "action": args.action, "process_filter": args.proc, "pid_filter": args.pid}
    elif args.command == "syscall":
        cmd = {"type": "syscall", "name": args.name, "action": args.action,
               "process_filter": args.proc, "pid_filter": args.pid}

    if not os.path.exists(args.sock):
        print(f"Error: {args.sock} not found."); sys.exit(1)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.connect(args.sock); c.sendall(json.dumps(cmd).encode()); c.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                chunk = c.recv(4096)
                if not chunk: break
                data += chunk
            
            if not data: sys.exit(1)
            resp = json.loads(data.decode())
            
            if resp.get("status") == "success":
                if "hooks" in resp:
                    print(f"{'ID':<4} {'Type':<12} {'Target':<30} {'Action'}")
                    print("-" * 60)
                    for h in resp['hooks']:
                        t = h.get('target') or "?"
                        if len(t)>28: t = t[:25]+"..."
                        print(f"{h['id']:<4} {h['type']:<12} {t:<30} {h['action']}")
                elif "message" in resp: print(resp['message'])
                else: print(f"Success: ID {resp.get('id')}")
            else:
                print(f"Failed: {resp.get('message')}"); sys.exit(1)
    except Exception as e: print(e); sys.exit(1)

if __name__ == "__main__": main()