from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine, asc
from rich import print as rprint
from time import sleep
from os.path import join, exists
from events import Event, Syscall

def wrapper(results, output, print_procname, follow, filter, args):
    # args format: (include_procname, exclude_procname, include_syscall, exclude_syscall, arg_search, errors, pid, show_process_tree)
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
                # Reconstruct and show the process tree
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
                            'parent': None
                        }
                    else:
                        if process_map[proc_id]['procname'] is None:
                            process_map[proc_id]['procname'] = procname
                        if process_map[proc_id]['pid'] is None:
                            process_map[proc_id]['pid'] = pid

                # Pass 1: populate process_map and pid_to_proc_id
                for sc in all_syscalls:
                    ensure_proc(sc.proc_id, sc.pid, sc.procname)
                    if sc.pid not in pid_to_proc_id:
                        pid_to_proc_id[sc.pid] = sc.proc_id

                # Pass 2: identify forks, kills, waits
                for sc in all_syscalls:
                    # Forks
                    if sc.name in ["sys_fork", "sys_vfork", "sys_clone"] and sc.retno and sc.retno > 0:
                        parent_id = sc.proc_id
                        child_pid = sc.retno
                        if child_pid in pid_to_proc_id:
                            child_id = pid_to_proc_id[child_pid]
                            process_map[child_id]['parent'] = parent_id
                            process_map[parent_id]['children'].append(child_id)

                    # Kills
                    if sc.name == "sys_kill" and sc.arg0_repr:
                        target_str = sc.arg0_repr.split("(")[0].strip()
                        try:
                            target_pid = int(target_str)
                        except ValueError:
                            target_pid = None
                        if target_pid is not None:
                            sig_str = "?"
                            if sc.arg1_repr:
                                sig_str = sc.arg1_repr.split("(")[0].strip()
                            process_map[sc.proc_id]['kills'].append((target_pid, sig_str))

                    # Waits
                    if sc.name == "sys_wait4" and sc.arg0_repr:
                        waited_str = sc.arg0_repr.split("(")[0].strip()
                        try:
                            waited_pid = int(waited_str)
                        except ValueError:
                            waited_pid = None
                        process_map[sc.proc_id]['waits'].append(waited_pid)

                # Identify roots
                root_processes = [p for p, info in process_map.items() if info['parent'] is None]

                def print_tree(proc_id, indent=0):
                    info = process_map[proc_id]
                    prefix = "  " * indent
                    pid = info['pid']
                    pname = info['procname'] or '?'
                    printer(f"{prefix}{pid} [{pname}] (proc_id={proc_id})", file=f)

                    for (tpid, sig) in info['kills']:
                        printer(f"{prefix}  sends signal {sig} to {tpid}", file=f)

                    for wpid in info['waits']:
                        if wpid == -1:
                            printer(f"{prefix}  waits for any child", file=f)
                        else:
                            printer(f"{prefix}  waits for PID {wpid}", file=f)

                    for child_id in info['children']:
                        print_tree(child_id, indent + 1)

                printer("Process Tree (ordered by creation time via proc_id):", file=f)
                for root_id in sorted(root_processes):
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
