import os
import json
from collections import defaultdict
from penguin import plugins, Plugin, getColoredLogger


class Proctree(Plugin):
    """
    Tracks process execution events and builds a process tree.
    Each process is uniquely identified by (pid, start_time, exec_num).
    Supports configurable output formats and live updating.
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.proctree")
        self.procs = {}  # (pid, start_time, exec_num) -> procinfo dict
        self.children = defaultdict(list)  # (ppid, pstart, pexec) -> list of (pid, start_time, exec_num)
        self.exec_counters = defaultdict(int)  # (pid, start_time) -> next exec_num

        # New options
        self.output_types = self.get_arg("output_types") or ["text", "json"]
        self.live_update = self.get_arg("live_update") or False
        # self.live_update = True
        self.output_types = ["text", "csv", "json"]

        plugins.subscribe(plugins.Execs, "exec_event", self.on_exec_event)

    # @plugins.syscalls.syscall("on_sys_exit_enter")
    def on_exit_event(self, pt_regs, proto, syscall, error_code):
        proc = yield from plugins.OSI.get_proc()
        pid = proc.pid
        start_time = proc.create_time
        candidates = [k for k in self.procs if k[0] == pid and k[1] == start_time]
        if candidates:
            latest = max(candidates, key=lambda k: k[2])
            self.procs[latest]["exit_reason"] = f"exit({error_code})"
            # self._write_exit_livelog(latest, error_code)
        else:
            self.logger.warning(f"Exit event for unknown process pid={pid} start_time={start_time}")

    # @plugins.syscalls.syscall("on_sys_exit_group_enter")
    def on_exit_group_event(self, pt_regs, proto, syscall, error_code):
        proc = yield from plugins.OSI.get_proc()
        tgid = proc.tgid
        pid = proc.pid
        start_time = proc.create_time
        # First, set exit_reason for the latest exec of the current process
        candidates = [k for k in self.procs if k[0] == pid and k[1] == start_time]
        if candidates:
            latest = max(candidates, key=lambda k: k[2])
            self.procs[latest]["exit_reason"] = f"{error_code}"
        else:
            breakpoint()
            self.logger.warning(f"Exit group event for unknown process pid={pid} start_time={start_time}")
        # Then, for all other processes with matching tgid and start_time, set exit_reason if not already set and pid != current pid
        updated = False
        for k, info in self.procs.items():
            if info["tgid"] == tgid and info["start_time"] == start_time and info["pid"] != pid and "exit_reason" not in info:
                info["exit_reason"] = f"exit_group({error_code}) (group member)"
                updated = True
        if not updated:
            self.logger.debug(f"No additional group members found for exit_group tgid={tgid} start_time={start_time}")

    def _get_next_exec_num(self, pid, start_time):
        key = (pid, start_time)
        num = self.exec_counters[key]
        self.exec_counters[key] += 1
        return num

    def _add_process(self, pid, tgid, ppid, start_time, parent_start_time, parent_exec_num, procname, argv, exec_num=None):
        self.logger.info(f"Adding process PID={pid} PPID={ppid} START={start_time} NAME={procname}")
        if exec_num is None:
            exec_num = self._get_next_exec_num(pid, start_time)
        reexec_time = None
        exit_reason = None
        if exec_num > 0:
            reexec_time = yield from plugins.OSI.read_time()
            exit_reason = "re-exec"
        proc_id = (pid, start_time, exec_num)
        self.logger.info(f"Registering process PID={pid} PPID={ppid} START={start_time} EXEC={exec_num} NAME={procname}")
        if proc_id in self.procs:
            self.logger.warning(f"Process PID={pid} START={start_time} EXEC={exec_num} already registered")
        self.procs[proc_id] = {
            "pid": pid,
            "tgid": tgid,
            "ppid": ppid,
            "parent_start_time": parent_start_time,
            "parent_exec_num": parent_exec_num,
            "start_time": start_time,
            "exec_num": exec_num,
            "reexec_time": reexec_time,
            "procname": procname,
            "argv": argv,
            "exit_reason": exit_reason,
        }
        # Incrementally update children mapping
        parent_id = (ppid, parent_start_time, parent_exec_num)
        self.children[parent_id].append(proc_id)
        self.children[parent_id].sort(key=lambda cid: (
            self.procs[cid]["start_time"],
            self.procs[cid]["pid"],
            self.procs[cid]["exec_num"]
        ))
        return proc_id

    def on_exec_event(self, event):
        yield from gbreak()
        parent = event.get("parent")
        # Find parent's exec_num if possible
        parent_candidates = [
            k for k in self.procs
            if k[0] == parent.pid and k[1] == parent.start_time
        ]
        parent_exec_num = max([k[2] for k in parent_candidates], default=0)
        exec_num = self._get_next_exec_num(event["proc"].pid, event["proc"].start_time)
        yield from self._add_process(
            event["proc"].pid,
            event["proc"].tgid,
            event["proc"].ppid,
            event["proc"].start_time,
            parent.start_time,
            parent_exec_num,
            event["procname"],
            event["argv"],
            exec_num=exec_num
        )
        parent_id = (parent.pid, parent.start_time, parent_exec_num)
        if parent_id not in self.procs:
            args = yield from plugins.OSI.get_args(parent.pid)
            parent_parent = yield from plugins.OSI.get_proc(parent.ppid)
            parent_parent_start_time = parent_parent.start_time if parent_parent else None
            # Find parent's parent exec_num if possible
            parent_parent_exec_num = 0
            if parent_parent:
                parent_parent_candidates = [
                    k for k in self.procs
                    if k[0] == parent.ppid and k[1] == parent_parent_start_time
                ]
                parent_parent_exec_num = max([k[2] for k in parent_parent_candidates], default=0)
            yield from self._add_process(
                parent.pid,
                parent.tgid,
                parent.ppid,
                parent.start_time,
                parent_parent_start_time,
                parent_parent_exec_num,
                getattr(parent, "name", None),
                args,
                exec_num=parent_exec_num
            )
        # Live update logic
        if self.live_update:
            # self._write_outputs()
            self._write_livelog_tree(event["proc"].pid, event["proc"].start_time, exec_num)

    def _single_pstree_text(self, proc_id, prefix="", is_last=True):
        """Render a tree-style line for a single process and its parent chain."""
        info = self.procs.get(proc_id)
        if not info:
            return []
        name = info["procname"] or str(info["pid"])
        pid = info["pid"]
        exec_num = info["exec_num"]
        if exec_num > 0:
            start_time = info["reexec_time"]
        else:
            start_time = info["start_time"]
        start_time_sec = start_time / 1e9 if start_time is not None else "?"
        argv = " ".join(info["argv"]) if info.get("argv") else ""
        exec_nums = [k[2] for k in self.procs if k[0] == pid and k[1] == info["start_time"]]
        if len(exec_nums) == 1:
            pid_str = f"{pid}"
        else:
            pid_str = f"{pid}/{exec_num}"
        # Add exit reason if present
        exit_reason = info.get("exit_reason")
        exit_str = f" [{exit_reason}]" if exit_reason else ""
        line = prefix
        if prefix:
            line += "└─" if is_last else "├─"
        line += f"{name} ({pid_str}) [t={start_time_sec}] [{argv}]{exit_str}"
        # Find parent
        parent_id = (info["ppid"], info["parent_start_time"], info["parent_exec_num"])
        if parent_id in self.procs:
            # Recursively build parent chain
            parent_lines = self._single_pstree_text(parent_id, prefix + ("   " if is_last else "│  "), True)
            return parent_lines + [line]
        else:
            return [line]

    def _write_livelog_tree(self, pid, start_time, exec_num):
        """Append tree-style line for the new process and its parent chain to livelog.txt."""
        proc_id = (pid, start_time, exec_num)
        lines = self._single_pstree_text(proc_id)
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)
        with open(f"{self.outdir}/livelog.txt", "a") as f:
            for line in lines:
                f.write(line + "\n")

    def _write_livelog(self, event, parent, exec_num, parent_exec_num):
        """Append new process and its ancestor info up to the root to livelog.txt in live mode."""
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)
        proc = event["proc"]
        procname = event["procname"]
        argv = " ".join(event["argv"]) if event.get("argv") else ""
        # Build ancestor chain
        ancestor_lines = []
        current_parent = parent
        current_exec_num = parent_exec_num
        while current_parent is not None:
            parentname = getattr(current_parent, "name", None)
            parent_pid = current_parent.pid
            parent_start = current_parent.start_time
            ancestor_lines.append(
                f"parent={parentname} (pid={parent_pid}, exec={current_exec_num}, start={parent_start})"
            )
            # Find next ancestor in procs if available
            parent_id = (parent_pid, parent_start, current_exec_num)
            parent_info = self.procs.get(parent_id)
            if parent_info:
                next_pid = parent_info["ppid"]
                next_start = parent_info["parent_start_time"]
                next_exec = parent_info["parent_exec_num"]
                # Avoid infinite loop if parent points to itself or missing
                if (next_pid, next_start, next_exec) == parent_id or next_pid is None:
                    break
                # Try to get next ancestor from procs
                next_parent_info = None
                for k, v in self.procs.items():
                    if v["pid"] == next_pid and v["start_time"] == next_start and v["exec_num"] == next_exec:
                        next_parent_info = v
                        break
                if next_parent_info:
                    # Create a dummy object with .pid, .start_time, .name
                    class DummyParent:
                        pass
                    dummy = DummyParent()
                    dummy.pid = next_parent_info["pid"]
                    dummy.start_time = next_parent_info["start_time"]
                    dummy.name = next_parent_info.get("procname")
                    current_parent = dummy
                    current_exec_num = next_parent_info["exec_num"]
                    continue
            break
        # Compose log line
        line = (
            f"NEW: {procname} (pid={proc.pid}, exec={exec_num}, start={proc.start_time}) "
            f"argv=[{argv}] "
            + " <- ".join(ancestor_lines)
        )
        with open(f"{self.outdir}/livelog.txt", "a") as f:
            f.write(line + "\n")

    def _find_roots(self):
        roots = []
        for proc_id, info in self.procs.items():
            ppid = info["ppid"]
            parent_start_time = info["parent_start_time"]
            parent_exec_num = info["parent_exec_num"]
            parent_id = (ppid, parent_start_time, parent_exec_num)
            if parent_id not in self.procs:
                roots.append(proc_id)
        roots.sort(key=lambda cid: (self.procs[cid]["start_time"], self.procs[cid]["pid"], self.procs[cid]["exec_num"]))
        return roots

    def _group_children(self, children):
        # Group children by procname, count, and collect their ids
        name_map = defaultdict(list)
        for cid in children:
            name = self.procs[cid]["procname"] or "?"
            name_map[name].append(cid)
        return name_map

    def _pstree_text(self, proc_id, prefix="", is_last=True):
        info = self.procs[proc_id]
        name = info["procname"] or str(info["pid"])
        pid = info["pid"]
        exec_num = info["exec_num"]
        if exec_num > 0:
            start_time = info["reexec_time"]
        else:
            start_time = info["start_time"]
        # Convert start_time from time64 (nanoseconds) to seconds
        start_time_sec = start_time / 1e9 if start_time is not None else "?"
        argv = " ".join(info["argv"]) if info.get("argv") else ""
        exec_nums = [k[2] for k in self.procs if k[0] == pid and k[1] == start_time]
        if len(exec_nums) == 1:
            pid_str = f"{pid}"
        else:
            pid_str = f"{pid}/{exec_num}"
        line = prefix
        if prefix:
            line += "└─" if is_last else "├─"
        # Show timeline in seconds
        line += f"{name} ({pid_str}) [t={start_time_sec}] [{argv}]"
        children = self.children.get(proc_id, [])
        children = sorted(children, key=lambda cid: (
            self.procs[cid]["start_time"],
            self.procs[cid]["pid"],
            self.procs[cid]["exec_num"]
        ))
        name_map = self._group_children(children)
        result = [line]
        child_items = list(name_map.items())
        for idx, (cname, cids) in enumerate(child_items):
            is_last_group = idx == len(child_items) - 1
            for j, cid in enumerate(cids):
                sub_prefix = prefix + ("   " if is_last else "│  ")
                result += self._pstree_text(cid, sub_prefix, is_last_group and j == len(cids) - 1)
        return result

    def _pstree_json(self, proc_id):
        info = self.procs[proc_id]
        name = info["procname"] or str(info["pid"])
        pid = info["pid"]
        exec_num = info["exec_num"]
        argv = info["argv"] if info.get("argv") else []
        start_time = info["start_time"]
        ppid = info["ppid"]
        parent_start_time = info["parent_start_time"]
        parent_exec_num = info["parent_exec_num"]
        node = {
            "name": name,
            "pid": pid,
            "exec_num": exec_num,
            "argv": argv,
            "start_time": start_time,
            "ppid": ppid,
            "parent_start_time": parent_start_time,
            "parent_exec_num": parent_exec_num,
            "reexec_time": info["reexec_time"],
            "children": []
        }
        children = self.children.get(proc_id, [])
        # Ensure children are sorted by (start_time, pid, exec_num)
        children = sorted(
            children,
            key=lambda cid: (
                self.procs[cid]["start_time"],
                self.procs[cid]["pid"],
                self.procs[cid]["exec_num"]
            )
        )
        for cid in children:
            node["children"].append(self._pstree_json(cid))
        return node

    def _pstree_csv(self, proc_id, parent_chain=None, rows=None):
        if rows is None:
            rows = []
        if parent_chain is None:
            parent_chain = []
        info = self.procs[proc_id]
        name = info["procname"] or str(info["pid"])
        pid = info["pid"]
        exec_num = info["exec_num"]
        argv = " ".join(info["argv"]) if info.get("argv") else ""
        exec_nums = [k[2] for k in self.procs if k[0] == pid and k[1] == info["start_time"]]
        if len(exec_nums) == 1:
            pid_str = f"{pid}"
        else:
            pid_str = f"{pid}/{exec_num}"
        row = parent_chain + [name, pid_str, argv]
        rows.append(row)
        children = self.children.get(proc_id, [])
        children = sorted(children, key=lambda cid: (
            self.procs[cid]["start_time"],
            self.procs[cid]["pid"],
            self.procs[cid]["exec_num"]
        ))
        for cid in children:
            self._pstree_csv(cid, row, rows)
        return rows

    def _write_outputs(self):
        self.logger.info("Writing process tree outputs...")
        """Write all requested output types."""
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)
        roots = self._find_roots()
        if "text" in self.output_types:
            lines = []
            for i, root in enumerate(roots):
                lines += self._pstree_text(root, "", i == len(roots) - 1)
            with open(f"{self.outdir}/proctree.txt", "w") as f:
                for line in lines:
                    f.write(line + "\n")
        if "csv" in self.output_types:
            rows = []
            for root in roots:
                rows += self._pstree_csv(root)
            maxlen = max(len(r) for r in rows) if rows else 0
            with open(f"{self.outdir}/proctree.csv", "w") as f:
                for row in rows:
                    f.write(",".join(row + [""] * (maxlen - len(row))) + "\n")
        if "json" in self.output_types:
            forest = [self._pstree_json(root) for root in roots]
            with open(f"{self.outdir}/proctree.json", "w") as f:
                json.dump(forest, f, indent=2)

    def dump_tree(self, fmt=None):
        # If fmt is specified, only write that format; else write all requested types
        if fmt:
            self.output_types = [fmt]
        self._write_outputs()

    def uninit(self):
        self._write_outputs()
