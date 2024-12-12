from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine, asc
from rich import print as rprint
from time import sleep
from os.path import join, exists
from events import Event, Syscall

# Optional signal map for readability
SIGNAL_MAP = {
    "1": "SIGHUP",
    "2": "SIGINT",
    "9": "SIGKILL",
    "10": "SIGUSR1",
    "15": "SIGTERM",
    # Add more signals as needed
}

# Limit the number of syscall summaries to store per process
MAX_SYSCALL_SUMMARIES = 5

def wrapper(results, output, print_procname, follow, filter, args):
    include_procname, exclude_procname, include_syscall, exclude_syscall, arg_search, errors, pid, show_process_tree = args

    db_path = join(results, "plugins.db")
    if not exists(db_path):
        print(f"Failed to find db at {db_path}. Check your --results")
        return

    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            # only pretty print if we are printing to stdout
            if output == "/dev/stdout":
                printer = rprint
            else:
                printer = print

            if show_process_tree:
                all_syscalls = sess.query(Syscall).order_by(asc(Syscall.proc_id), asc(Syscall.id)).all()

                process_map = {}
                pid_to_proc_id = {}

                def ensure_proc(proc_id, pid, procname):
                    if proc_id not in process_map:
                        process_map[proc_id] = {
                            'pid': pid,
                            'procname': procname,
                            'children': [],
                            'kills': [],
                            'waits': [],
                            'parent': None,
                            'syscall_summaries': []
                        }
                    else:
                        if process_map[proc_id]['procname'] is None:
                            process_map[proc_id]['procname'] = procname
                        if process_map[proc_id]['pid'] is None:
                            process_map[proc_id]['pid'] = pid

                def add_syscall_summary(proc_id, summary):
                    # Add a summary line for a process
                    process_map[proc_id]['syscall_summaries'].append(summary)
                    # Keep only last MAX_SYSCALL_SUMMARIES entries
                    if len(process_map[proc_id]['syscall_summaries']) > MAX_SYSCALL_SUMMARIES:
                        process_map[proc_id]['syscall_summaries'].pop(0)

                # Populate process_map
                for sc in all_syscalls:
                    ensure_proc(sc.proc_id, sc.pid, sc.procname)
                    if sc.pid not in pid_to_proc_id:
                        pid_to_proc_id[sc.pid] = sc.proc_id

                # Helper to extract arguments from argX_repr
                def extract_args_repr(sc):
                    # Returns a list of strings representing arguments
                    args_list = []
                    for i in range(6):
                        arg_repr = getattr(sc, f"arg{i}_repr", None)
                        if arg_repr is not None:
                            args_list.append(arg_repr)
                    return args_list

                # Identify forks, kills, waits and record details
                for sc in all_syscalls:
                    args_list = extract_args_repr(sc)
                    # Fork/Clone syscalls
                    if sc.name in ["sys_fork", "sys_vfork", "sys_clone"]:
                        # If retno > 0, parent's call returned child's PID
                        # If retno = 0, this is the child's perspective, but child's perspective usually isn't recorded separately
                        # We'll just record from parent's perspective
                        if sc.retno is not None and sc.retno > 0:
                            parent_id = sc.proc_id
                            child_pid = sc.retno
                            ret_str = f"sys_{sc.name[4:]} returned child_pid={child_pid}"
                            add_syscall_summary(parent_id, ret_str)

                            if child_pid in pid_to_proc_id:
                                child_id = pid_to_proc_id[child_pid]
                                process_map[child_id]['parent'] = parent_id
                                process_map[parent_id]['children'].append(child_id)
                                # Mark child's creation
                                add_syscall_summary(child_id, f"Created by {sc.name} from parent_pid={process_map[parent_id]['pid']}")

                    # Wait4 syscalls
                    if sc.name == "sys_wait4":
                        waited_str = sc.arg0_repr.split("(")[0].strip() if sc.arg0_repr else "?"
                        ret_val = sc.retno if sc.retno is not None else "?"
                        wait_summary = f"sys_wait4({waited_str}) returned {ret_val}"
                        add_syscall_summary(sc.proc_id, wait_summary)

                        # Track waited PID for the tree structure as before
                        try:
                            waited_pid = int(waited_str)
                        except ValueError:
                            waited_pid = None
                        if waited_pid is not None:
                            process_map[sc.proc_id]['waits'].append(waited_pid if waited_pid != 0 else None)
                        elif waited_str == "-1":
                            process_map[sc.proc_id]['waits'].append(-1)

                    # Kill syscalls
                    if sc.name == "sys_kill":
                        target_str = sc.arg0_repr.split("(")[0].strip() if sc.arg0_repr else "?"
                        sig_str = "?"
                        if sc.arg1_repr:
                            raw_sig = sc.arg1_repr.split("(")[0].strip()
                            sig_str = SIGNAL_MAP.get(raw_sig, f"SIG{raw_sig}")
                        ret_val = sc.retno if sc.retno is not None else "?"
                        kill_summary = f"sys_kill(target={target_str}, sig={sig_str}) returned {ret_val}"
                        add_syscall_summary(sc.proc_id, kill_summary)

                        # For grouping signals in the tree
                        try:
                            target_pid = int(target_str)
                        except ValueError:
                            target_pid = None
                        if target_pid is not None:
                            process_map[sc.proc_id]['kills'].append((target_pid, sig_str))

                # Functions for formatting waits/kills remain similar
                from collections import defaultdict, Counter

                def format_waits(waits):
                    any_child_count = sum(1 for w in waits if w == -1)
                    pids_waited = [w for w in waits if w not in (-1, None)]
                    lines = []
                    if any_child_count > 0:
                        if any_child_count == 1:
                            lines.append("waits for any child")
                        else:
                            lines.append(f"waits for any child (x{any_child_count})")
                    if pids_waited:
                        unique_pids = sorted(set(pids_waited))
                        if len(unique_pids) == 1:
                            lines.append(f"waits for PID {unique_pids[0]}")
                        else:
                            lines.append(f"waits for PIDs {unique_pids}")
                    return lines

                def format_kills(kills):
                    targets = defaultdict(list)
                    for tpid, sig in kills:
                        targets[tpid].append(sig)
                    lines = []
                    if targets:
                        lines.append("sends signals:")
                        for tpid, sigs in targets.items():
                            target_desc = f"process group {abs(tpid)}" if tpid < 0 else f"PID {tpid}"
                            sig_count = Counter(sigs)
                            sig_list = []
                            for s, c in sig_count.items():
                                if c > 1:
                                    sig_list.append(f"{s} (x{c})")
                                else:
                                    sig_list.append(s)
                            sig_joined = ", ".join(sig_list)
                            lines.append(f"  {sig_joined} to {target_desc}")
                    return lines

                # Identify root processes
                root_processes = [p for p, info in process_map.items() if info['parent'] is None]

                printer("Process Tree (newest processes at the bottom):", file=f)

                def process_display_name(proc_id):
                    info = process_map[proc_id]
                    pname = info['procname'] or '?'
                    pid = info['pid'] if info['pid'] is not None else '?'
                    return f"[pid {pid}] {pname}"

                def print_tree(proc_id, indent=0):
                    info = process_map[proc_id]
                    prefix = "  " * indent
                    printer(f"{prefix}{process_display_name(proc_id)}", file=f)

                    # Print recent syscall summaries
                    for summary in info['syscall_summaries']:
                        printer(f"{prefix}  (call) {summary}", file=f)

                    wait_lines = format_waits(info['waits'])
                    for line in wait_lines:
                        printer(f"{prefix}  {line}", file=f)

                    kill_lines = format_kills(info['kills'])
                    for line in kill_lines:
                        printer(f"{prefix}  {line}", file=f)

                    if info['children']:
                        info['children'].sort(key=lambda cid: process_map[cid]['pid'] if process_map[cid]['pid'] else -1)
                        for child_id in info['children']:
                            print_tree(child_id, indent + 1)

                for root_id in sorted(root_processes, key=lambda rid: process_map[rid]['pid'] if process_map[rid]['pid'] else -1):
                    print_tree(root_id)

            else:
                # Original behavior
                highest_id = -1
                if follow:
                    if id_num := sess.execute(func.max(Event.id)).first():
                        highest_id = (id_num[0] or 0) - 4

                while True:
                    query = filter(sess, include_procname, exclude_procname, include_syscall, exclude_syscall, arg_search, errors, pid)

                    if highest_id != -1:
                        query = query.filter(Event.id > highest_id)

                    events = query.all()
                    for event in events:
                        if print_procname:
                            printer(f"({event.procname})[{event.pid}] {event}", file=f)
                        else:
                            printer(event, file=f)
                        highest_id = max(highest_id, event.id)

                    if not follow:
                        break
                    else:
                        sleep(1)
