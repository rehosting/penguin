import os
import json
from collections import defaultdict
from penguin import plugins, Plugin, getColoredLogger


class Proctree(Plugin):
    """
    Tracks process execution events and builds a process tree.
    Each process is uniquely identified by (pid, start_time, exec_num).
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.proctree")
        self.procs = {}  # (pid, start_time, exec_num) -> procinfo dict
        self.children = defaultdict(list)  # (ppid, pstart, pexec) -> list of (pid, start_time, exec_num)
        self.exec_counters = defaultdict(int)  # (pid, start_time) -> next exec_num
        plugins.subscribe(plugins.Execs, "exec_event", self.on_exec_event)

    def _get_next_exec_num(self, pid, start_time):
        key = (pid, start_time)
        num = self.exec_counters[key]
        self.exec_counters[key] += 1
        return num

    def _add_process(self, pid, ppid, start_time, parent_start_time, parent_exec_num, procname, argv, exec_num=None):
        if exec_num is None:
            exec_num = self._get_next_exec_num(pid, start_time)
        proc_id = (pid, start_time, exec_num)
        self.logger.info(f"Registering process PID={pid} PPID={ppid} START={start_time} EXEC={exec_num} NAME={procname}")
        if proc_id in self.procs:
            self.logger.warning(f"Process PID={pid} START={start_time} EXEC={exec_num} already registered")
        self.procs[proc_id] = {
            "pid": pid,
            "ppid": ppid,
            "parent_start_time": parent_start_time,
            "parent_exec_num": parent_exec_num,
            "start_time": start_time,
            "exec_num": exec_num,
            "procname": procname,
            "argv": argv,
        }
        return proc_id

    def on_exec_event(self, event):
        parent = event.get("parent")
        # Find parent's exec_num if possible
        parent_candidates = [
            k for k in self.procs
            if k[0] == parent.pid and k[1] == parent.start_time
        ]
        parent_exec_num = max([k[2] for k in parent_candidates], default=0)
        exec_num = self._get_next_exec_num(event["proc"].pid, event["proc"].start_time)
        self._add_process(
            event["proc"].pid,
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
            self._add_process(
                parent.pid,
                parent.ppid,
                parent.start_time,
                parent_parent_start_time,
                parent_parent_exec_num,
                getattr(parent, "name", None),
                args,
                exec_num=parent_exec_num
            )

    def _rebuild_children(self):
        self.children.clear()
        for proc_id, info in self.procs.items():
            ppid = info["ppid"]
            parent_start_time = info["parent_start_time"]
            parent_exec_num = info["parent_exec_num"]
            parent_id = (ppid, parent_start_time, parent_exec_num)
            if parent_id in self.procs:
                self.children[parent_id].append(proc_id)
        for k in self.children:
            self.children[k].sort(key=lambda cid: (self.procs[cid]["start_time"], self.procs[cid]["pid"], self.procs[cid]["exec_num"]))

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

    def dump_tree(self, fmt="text"):
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)
        self._rebuild_children()
        roots = self._find_roots()
        if fmt == "text":
            lines = []
            for i, root in enumerate(roots):
                lines += self._pstree_text(root, "", i == len(roots) - 1)
            with open(f"{self.outdir}/proctree.txt", "w") as f:
                for line in lines:
                    f.write(line + "\n")
        elif fmt == "csv":
            rows = []
            for root in roots:
                rows += self._pstree_csv(root)
            maxlen = max(len(r) for r in rows)
            with open(f"{self.outdir}/proctree.csv", "w") as f:
                for row in rows:
                    # Pad to maxlen for consistent columns
                    f.write(",".join(row + [""] * (maxlen - len(row))) + "\n")
        elif fmt == "json":
            forest = [self._pstree_json(root) for root in roots]
            with open(f"{self.outdir}/proctree.json", "w") as f:
                json.dump(forest, f, indent=2)

    def uninit(self):
        self.dump_tree("text")
        self.dump_tree("json")
