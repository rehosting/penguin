from penguin import Plugin, plugins
import os
import pdb
import re
import struct
from collections import defaultdict

uprobes = plugins.uprobes
syscalls = plugins.syscalls
mem = plugins.mem
osi = plugins.osi


class HookLogger(Plugin):
    """
    HookLogger Plugin
    =================
    The "easy mode" for dynamic instrumentation.
    
    Transforms simple action strings (e.g., 'print(%s, %d)') into 
    complex, reliable uprobes and syscall hooks.
    
    Features:
    - Parses action strings to determine what data to capture.
    - Automatically handles memory resolution (dereferencing pointers) at entry.
    - **Deferred Resolution**: Use '%s:out' to capture a pointer at entry but read 
      the string at return (useful for output buffers like in read()).
    - Manages context stacks to safely print return values ('func() = ret').
    """

    def __init__(self):
        self.next_hook_id = 1
        self.hooks_by_id = {}
        # Stack: { hook_id: [ [arg1_str, arg2_str], ... ] }
        self.call_stacks = defaultdict(list)

        self.arch_bits = 64 if '64' in self.panda.arch_name else 32
        self.ptr_mask = (1 << self.arch_bits) - 1

    def list_hooks(self):
        hook_list = []
        for hook_id, data in self.hooks_by_id.items():
            info = {
                "id": hook_id,
                "type": data.get('type', '?'),
                "action": data.get('raw_action', '?'),
            }
            if 'target_desc' in data:
                info['target'] = data['target_desc']
            if 'filters' in data:
                info['filters'] = data['filters']
            hook_list.append(info)
        return hook_list

    def disable_hook(self, hook_id):
        if hook_id not in self.hooks_by_id:
            raise ValueError(f"Hook ID {hook_id} not found")
        
        self.logger.info(f"Disabling hook {hook_id}")
        self._unregister_hook(hook_id)
        return True

    def disable_all(self):
        count = len(self.hooks_by_id)
        self.logger.info(f"Disabling all {count} hooks")
        for hid in list(self.hooks_by_id.keys()):
            self._unregister_hook(hid)
        self.call_stacks.clear()
        return count

    def register_uprobe(self, path, symbol, action_str, pid_filter=None, process_filter=None):
        if not path or not symbol:
            raise ValueError("Missing path or symbol")
        
        try:
            target_val = int(symbol, 0)
        except (ValueError, TypeError):
            target_val = symbol

        hook_id = self.next_hook_id
        self.next_hook_id += 1

        is_break = 'break' in action_str or 'bp' in action_str
        arg_fmts, ret_fmts = self._parse_print_formats(action_str)

        entry_method = None
        if arg_fmts and len(arg_fmts) == 1:
            entry_method = self._resolve_plugin_method(arg_fmts[0])
            if entry_method:
                arg_fmts = []

        exit_method = None
        if ret_fmts and len(ret_fmts) == 1:
            exit_method = self._resolve_plugin_method(ret_fmts[0])
            if exit_method:
                ret_fmts = []

        # Check if any argument format requires deferred resolution (e.g. %s:out)
        has_deferred = arg_fmts and any(f.endswith(':out') for f in arg_fmts)

        # We must enable return probe if:
        # 1. We want to print return values (ret_fmts)
        # 2. We have a custom exit method
        # 3. We have deferred arguments (need to read them at exit)
        is_retprobe = (ret_fmts is not None) or (exit_method is not None) or has_deferred
        
        if ret_fmts is None:
            ret_fmts = []

        prefix = f"{os.path.basename(path)}:{target_val}"

        hook_data = {
            'type': 'uretprobe' if is_retprobe else 'uprobe',
            'raw_action': action_str,
            'target_desc': f"{path}:{symbol}",
            'filters': f"pid={pid_filter}" if pid_filter else "",
            'handles': []
        }
        self.hooks_by_id[hook_id] = hook_data

        def entry_handler(regs):
            if hook_id not in self.hooks_by_id:
                return

            if entry_method:
                yield from entry_method(regs)
            else:
                vals = []
                if arg_fmts:
                    count = len([f for f in arg_fmts if f != '%proc'])
                    vals = yield from regs.get_args_portal(count, convention='userland')
                
                resolved_args = []
                if arg_fmts:
                    # Resolve values. If is_retprobe is True, allow deferral (:out)
                    resolved_args = yield from self._resolve_values(arg_fmts, vals, allow_defer=is_retprobe)

                if is_retprobe:
                    # Even if arg_fmts is empty, we might push empty list to track call depth? 
                    # But usually we only push if we have args. 
                    if arg_fmts:
                        self.call_stacks[hook_id].append(resolved_args)
                else:
                    # Print immediately
                    yield from self._log_action(resolved_args, [], prefix, is_break)

        def exit_handler(regs):
            if hook_id not in self.hooks_by_id:
                return

            saved_args = []
            if arg_fmts:
                stack = self.call_stacks[hook_id]
                if stack:
                    # Pop the raw/partially-resolved args
                    raw_saved = stack.pop()
                    
                    # FINAL RESOLUTION: Check for deferred items
                    for arg in raw_saved:
                        # Identifier for deferred: tuple like ("__DEFERRED__", fmt, val)
                        if isinstance(arg, tuple) and len(arg) == 3 and arg[0] == "__DEFERRED__":
                            _, fmt, ptr = arg
                            # Read memory NOW at exit
                            val = yield from self._format_value(fmt, ptr)
                            saved_args.append(val)
                        else:
                            saved_args.append(arg)
                else:
                    saved_args = ["<lost-context>"] * len(arg_fmts)

            if exit_method:
                yield from exit_method(regs)
            else:
                ret_vals = []
                if ret_fmts:
                    try:
                        retval = regs.get_retval()
                    except Exception:
                        retval = 0
                    ret_vals = [retval]
                    if len(ret_fmts) > 1:
                        ret_vals.extend([None]*(len(ret_fmts)-1))
                
                # Return values are always resolved immediately at exit
                resolved_rets = yield from self._resolve_values(ret_fmts, ret_vals, allow_defer=False)
                yield from self._log_action(saved_args, resolved_rets, prefix, is_break, is_ret=True)

        needs_entry = (not is_retprobe) or (is_retprobe and len(arg_fmts) > 0) or (entry_method is not None)
        needs_exit = is_retprobe

        if needs_entry:
            h = uprobes.uprobe(
                path=path, symbol=target_val,
                process_filter=process_filter,
                pid_filter=pid_filter,
                on_enter=True, on_return=False
            )(entry_handler)
            hook_data['handles'].append(('uprobe', h))

        if needs_exit:
            h = uprobes.uprobe(
                path=path, symbol=target_val,
                process_filter=process_filter,
                pid_filter=pid_filter,
                on_enter=False, on_return=True
            )(exit_handler)
            hook_data['handles'].append(('uprobe', h))

        self.logger.info(f"HookLogger: Attached at {hook_data['target_desc']} ({action_str})")
        return hook_id

    def register_syscall(self, name, action_str, pid_filter=None, process_filter=None):
        hook_id = self.next_hook_id
        self.next_hook_id += 1

        is_break = 'break' in action_str
        arg_fmts, _ = self._parse_print_formats(action_str)

        syscall_method = None
        if arg_fmts and len(arg_fmts) == 1:
            syscall_method = self._resolve_plugin_method(arg_fmts[0])

        prefix = f"syscall:{name}"
        self.hooks_by_id[hook_id] = {
            'type': 'syscall', 'raw_action': action_str, 'name': name, 'handles': []
        }

        def handler(regs, proto, sc, *args):
            if hook_id not in self.hooks_by_id:
                return

            if syscall_method:
                yield from syscall_method(regs, proto, sc, *args)
            else:
                vals = []
                if arg_fmts:
                    count = len([f for f in arg_fmts if f != '%proc'])
                    vals = yield from regs.get_args_portal(count, 'syscall')
                
                # Syscalls in this mode are entry-only, so allow_defer=False
                resolved_args = yield from self._resolve_values(arg_fmts, vals, allow_defer=False)
                yield from self._log_action(resolved_args, [], prefix, is_break)

        h = syscalls.syscall(
            name_or_pattern=name,
            comm_filter=process_filter,
            pid_filter=pid_filter
        )(handler)
        self.hooks_by_id[hook_id]['handles'].append(('syscall', h))

        self.logger.info(f"HookLogger: Syscall attached at {name}")
        return hook_id

    def _unregister_hook(self, hook_id):
        if hook_id not in self.hooks_by_id:
            return
        data = self.hooks_by_id[hook_id]
        for h_type, handle in data.get('handles', []):
            try:
                if h_type == 'uprobe':
                    uprobes.unregister(handle)
                elif h_type == 'syscall':
                    syscalls.unregister(handle)
            except Exception as e:
                self.logger.error(
                    f"Error unregistering {h_type} hook {hook_id}: {e}")
        del self.hooks_by_id[hook_id]
        if hook_id in self.call_stacks:
            del self.call_stacks[hook_id]

    # --- Helpers ---

    def _resolve_plugin_method(self, name):
        if '.' not in name:
            return None
        try:
            parts = name.split('.')
            if len(parts) != 2:
                return None
            pname, mname = parts
            if not hasattr(plugins, pname):
                return None
            p = getattr(plugins, pname)
            if hasattr(p, mname):
                return getattr(p, mname)
        except AttributeError:
            return None
        return None

    def _parse_print_formats(self, action_str):
        body = re.sub(r'^print\s*\(?', '', action_str,
                      flags=re.IGNORECASE).rstrip(')')
        if '=' in body:
            parts = body.split('=', 1)
            arg_fmts = [f.strip() for f in parts[0].split(',') if f.strip()]
            ret_fmts = [f.strip() for f in parts[1].split(',') if f.strip()]
            return arg_fmts, ret_fmts
        else:
            fmts = [f.strip() for f in body.split(',') if f.strip()]
            return fmts, None

    def _resolve_values(self, fmts, vals, allow_defer=False):
        """
        Resolves raw register values based on format strings.
        If allow_defer is True and fmt ends with ':out', returns a deferred tuple
        instead of resolving immediately.
        """
        out = []
        val_idx = 0
        for fmt in fmts:
            # Check for deferred modifier
            is_deferred = False
            if allow_defer and fmt.endswith(':out'):
                fmt = fmt[:-4] # Strip :out
                is_deferred = True
            elif fmt.endswith(':out') and not allow_defer:
                # User asked for deferral but we can't do it (e.g. no return probe)
                # Strip it and proceed normally, maybe warn?
                fmt = fmt[:-4]

            if fmt == '%proc':
                try:
                    pname = yield from osi.get_proc_name()
                    out.append(pname)
                except Exception:
                    out.append("?")
            else:
                if val_idx < len(vals):
                    val = vals[val_idx]
                    val_idx += 1
                    
                    if is_deferred:
                        # Store tuple for later resolution
                        out.append(("__DEFERRED__", fmt, val))
                    else:
                        # Resolve immediately
                        formatted = yield from self._format_value(fmt, val)
                        out.append(formatted)
                else:
                    out.append("?")
        return out

    def _log_action(self, arg_strs, ret_strs, prefix, is_break, is_ret=False):
        if is_break:
            self.logger.warning(f"Dynamic Breakpoint: {prefix}")
            pdb.set_trace()
            return

        lhs = ", ".join(arg_strs)
        if is_ret:
            rhs = ", ".join(ret_strs)
            msg = f"{prefix}({lhs}) = {rhs}"
        else:
            msg = f"{prefix}({lhs})"

        self.logger.info(msg)

    def _to_signed(self, val, bits=None):
        bits = bits or self.arch_bits
        if val & (1 << (bits - 1)):
            return val - (1 << bits)
        return val

    def _format_value(self, fmt, val):
        if val is None:
            return "nil"
        if fmt in ['%d', '%i']:
            return str(self._to_signed(val))
        if fmt == '%u':
            return str(val)
        if fmt in ['%x', '%X']:
            return f"{val:x}" if fmt == '%x' else f"{val:X}"
        if fmt == '%p':
            return f"0x{val:0{self.arch_bits//4}x}"
        if fmt == '%c':
            return chr(val & 0xFF) if 32 <= (val & 0xFF) <= 126 else '.'
        if fmt == '%b':
            return str(bool(val))

        if fmt == '%fd':
            try:
                name = yield from osi.get_fd_name(val)
                return f"{val}({name or '?'})"
            except Exception:
                return f"{val}(?)"

        if fmt == '%s':
            try:
                return f'"{yield from mem.read_str(val)}"'
            except Exception:
                return f"<bad-str:{val:x}>"

        m = re.match(r'%(?P<t>[uix])(?P<b>8|16|32|64)', fmt)
        if m:
            t, b = m.group('t'), int(m.group('b'))
            try:
                d = yield from mem.read_bytes(val, b//8)
                c = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[b//8]
                if t == 'i':
                    c = c.lower()
                v = struct.unpack(f"<{c}", d)[0]
                return f"{v:x}" if t == 'x' else str(v)
            except Exception:
                return f"<bad-mem:{val:x}>"

        return f"{val:x}(?)"