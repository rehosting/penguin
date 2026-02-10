from penguin import Plugin, plugins
import asyncio
import threading
import json
import os
import pdb
import re
import traceback
import struct
from collections import defaultdict

uprobes = plugins.uprobes
syscalls = plugins.syscalls


class RemoteCtrl(Plugin):
    """
    RemoteCtrl Plugin
    ================
    Listens on a Unix Domain Socket for commands.

    Features:
    - Register uprobe (entry/return inferred) and syscall hooks.
    - Extended Format Support (%d, %s, %fd, %proc, etc.).
    - Smart Logic:
      - "print args": Prints at entry.
      - "print args = ret": Captures args at entry, prints at exit.
      - "myplugin.method": Delegates execution to another plugin's method.
    """

    def __init__(self):
        outdir = self.get_arg("outdir") or "/tmp"
        self.socket_path = os.path.join(outdir, "penguin_events.sock")

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        self.running = True
        self.logger.info(
            f"RemoteCtrl: Listening for events on: {self.socket_path}")

        self.next_hook_id = 1
        self.hooks_by_id = {}
        self.call_stacks = defaultdict(list)

        self.arch_bits = 64 if '64' in self.panda.arch_name else 32
        self.ptr_mask = (1 << self.arch_bits) - 1

        # Start the asyncio loop in a separate thread to avoid blocking main init
        # and to ensure a loop exists.
        self.loop_thread = threading.Thread(target=self._start_background_loop)
        self.loop_thread.daemon = True
        self.loop_thread.start()

    def uninit(self):
        self.running = False

        # Thread-safe shutdown of the asyncio loop
        if hasattr(self, 'loop') and self.loop.is_running():
            self.loop.call_soon_threadsafe(self._stop_server)
            self.loop_thread.join(timeout=1.0)

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

    def _start_background_loop(self):
        """Runs the asyncio event loop in a background thread."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._socket_server_loop())
        except Exception as e:
            self.logger.error(f"RemoteCtrl server loop error: {e}")
        finally:
            try:
                # Cancel all remaining tasks
                tasks = asyncio.all_tasks(self.loop)
                for task in tasks:
                    task.cancel()
                self.loop.run_until_complete(
                    asyncio.gather(*tasks, return_exceptions=True))
                self.loop.close()
            except Exception:
                # Catch-all strictly for loop teardown to prevent uninit crashes
                pass

    def _stop_server(self):
        """Callback to stop the server from the main thread."""
        if hasattr(self, 'server') and self.server:
            self.server.close()
        # Cancelling the main task (serve_forever) will exit the loop
        for task in asyncio.all_tasks(self.loop):
            task.cancel()

    async def _socket_server_loop(self):
        try:
            self.server = await asyncio.start_unix_server(self._handle_client, self.socket_path)
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Socket server error: {e}")

    async def _handle_client(self, reader, writer):
        try:
            data = await reader.read()

            response = {"status": "error", "message": "No data received"}
            if data:
                # Process message synchronously as plugin APIs are sync
                response = self._process_message(data)

            writer.write(json.dumps(response).encode('utf-8'))
            await writer.drain()
        except Exception as e:
            self.logger.error(f"Socket handler error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                # Connection likely dropped by client already
                pass

    def _process_message(self, data):
        try:
            cmd = json.loads(data.decode('utf-8'))
            cmd_type = cmd.get('type')
            handler_name = f"_handle_{cmd_type}"

            if hasattr(self, handler_name):
                handler = getattr(self, handler_name)
                result = handler(cmd)
                return {"status": "success", **(result if isinstance(result, dict) else {})}
            else:
                return {"status": "error", "message": f"Unknown command: {cmd_type}"}
        except Exception as e:
            self.logger.error(traceback.format_exc())
            return {"status": "error", "message": str(e)}

    # --- Handlers ---

    def _handle_load_plugin(self, cmd):
        name = cmd.get('name')
        args = cmd.get('args', {})
        if not name:
            raise ValueError("Missing 'name'")
        try:
            plugins.load_plugin(name, extra_args=args)
            self.logger.info(f"Loaded plugin: {name} with args: {args}")
            return {"message": f"Plugin '{name}' loaded successfully", "status": "success"}
        except Exception as e:
            self.logger.error(f"Plugin '{name}' not found: {e}")
            return {"status": "error", "message": f"Plugin '{name}' not found: {e}"}

    def _handle_enable_plugin(self, cmd):
        name = cmd.get('name')
        args = cmd.get('args', {})
        if not name:
            raise ValueError("Missing 'name'")

        p = plugins.get_plugin_by_name(name)
        if not p:
            return {"status": "error", "message": f"Plugin '{name}' is not loaded"}

        if hasattr(p, 'enable') and callable(p.enable):
            try:
                p.enable(**args)
                self.logger.info(f"Enabled plugin: {name} with args: {args}")
                return {"status": "success", "message": f"Plugin '{name}' enabled successfully"}
            except Exception as e:
                self.logger.error(f"Error enabling plugin '{name}': {e}")
                return {"status": "error", "message": f"Error enabling plugin '{name}': {e}"}
        else:
            return {"status": "error", "message": f"Plugin '{name}' does not implement 'enable'"}

    def _handle_disable_plugin(self, cmd):
        name = cmd.get('name')
        if not name:
            raise ValueError("Missing 'name'")

        p = plugins.get_plugin_by_name(name)
        if not p:
            return {"status": "error", "message": f"Plugin '{name}' is not loaded"}

        if hasattr(p, 'disable') and callable(p.disable):
            try:
                p.disable()
                return {"status": "success", "message": f"Plugin '{name}' disabled successfully"}
            except Exception as e:
                self.logger.error(f"Error disabling plugin '{name}': {e}")
                return {"status": "error", "message": f"Error disabling plugin '{name}': {e}"}
        else:
            return {"status": "error", "message": f"Plugin '{name}' does not implement 'disable'"}

    def _handle_uprobe(self, cmd):
        return self._register_uprobe(cmd)

    def _handle_syscall(self, cmd):
        return self._register_syscall(cmd)

    def _handle_list(self, cmd):
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
        return {"hooks": hook_list}

    def _handle_disable(self, cmd):
        hook_id = cmd.get('id')
        if hook_id is not None:
            try:
                hook_id = int(hook_id)
            except (ValueError, TypeError):
                raise ValueError("Invalid 'id' format")

            if hook_id not in self.hooks_by_id:
                raise ValueError(f"Hook ID {hook_id} not found")

            self.logger.info(f"Disabling hook {hook_id}")
            self._unregister_hook(hook_id)
            return {"message": f"Hook {hook_id} disabled"}
        else:
            count = len(self.hooks_by_id)
            self.logger.info(f"Disabling all {count} hooks")
            for hid in list(self.hooks_by_id.keys()):
                self._unregister_hook(hid)
            self.call_stacks.clear()
            return {"message": f"All {count} hooks disabled"}

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

    # --- Context & Parsing ---

    def _get_context_key(self):
        try:
            if not hasattr(self.plugins, 'osi'):
                self.plugins.load_plugin('osi')
            proc = yield from self.plugins.osi.get_proc(None)
            if proc:
                return proc.pid
        except Exception:
            # OSI failure is common if introspection isn't ready
            pass
        try:
            return self.panda.get_cpu().env_ptr
        except Exception:
            # Generic PANDA access failure
            return 0

    def _resolve_plugin_method(self, name):
        """Resolves a string 'plugin.method' to a callable."""
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
            # Safely handle missing attributes during resolution
            return None
        return None

    def _parse_print_formats(self, action_str):
        # Normalize
        body = re.sub(r'^print\s*\(?', '', action_str,
                      flags=re.IGNORECASE).rstrip(')')

        if '=' in body:
            parts = body.split('=', 1)
            arg_fmts = [f.strip() for f in parts[0].split(',') if f.strip()]
            ret_fmts = [f.strip() for f in parts[1].split(',') if f.strip()]
            return arg_fmts, ret_fmts
        else:
            # No equals sign -> All formats are for arguments
            fmts = [f.strip() for f in body.split(',') if f.strip()]
            return fmts, None

    # --- Registration ---

    def _register_uprobe(self, cmd):
        path = cmd.get('path')
        target = cmd.get('symbol')
        action_str = cmd.get('action')
        if not path or not target:
            raise ValueError("Missing path or symbol")
        if not action_str:
            raise ValueError("Missing action")

        try:
            target_val = int(target, 0)
        except (ValueError, TypeError):
            target_val = target

        hook_id = self.next_hook_id
        self.next_hook_id += 1

        is_break = 'break' in action_str or 'bp' in action_str
        arg_fmts, ret_fmts = self._parse_print_formats(action_str)

        # Check for method delegation
        # If an action is a valid plugin method, we use that instead of printing.
        entry_method = None
        if arg_fmts and len(arg_fmts) == 1:
            entry_method = self._resolve_plugin_method(arg_fmts[0])
            if entry_method:
                arg_fmts = []  # Clear formats so we don't try to print/save

        exit_method = None
        if ret_fmts and len(ret_fmts) == 1:
            exit_method = self._resolve_plugin_method(ret_fmts[0])
            if exit_method:
                ret_fmts = []

        # Determine if we need return probing
        # inferred from presence of return formats (RHS of =) or exit method
        is_retprobe = (ret_fmts is not None) or (exit_method is not None)

        # If is_retprobe is False, ret_fmts is None. For execution safety set to empty list
        if ret_fmts is None:
            ret_fmts = []

        prefix = f"{os.path.basename(path)}:{target_val}"

        hook_data = {
            'type': 'uretprobe' if is_retprobe else 'uprobe',
            'raw_action': action_str,
            'target_desc': f"{path}:{target}",
            'filters': f"pid={cmd.get('pid_filter')}" if cmd.get('pid_filter') else "",
            'handles': []
        }
        self.hooks_by_id[hook_id] = hook_data

        def entry_handler(regs):
            if hook_id not in self.hooks_by_id:
                return

            if entry_method:
                yield from entry_method(regs)
                # If we delegated entry, we cleared arg_fmts, so no stack push happens here.
            else:
                # Fetch args
                vals = []
                if arg_fmts:
                    count = len([f for f in arg_fmts if f != '%proc'])
                    vals = yield from regs.get_args_portal(count, convention='userland')

                if is_retprobe:
                    # Save for exit. We only push if we have args to match the exit pop.
                    if arg_fmts:
                        key = yield from self._get_context_key()
                        self.call_stacks[key].append(vals)
                else:
                    # Print immediately (Print Once Rule)
                    yield from self._execute_action(vals, [], arg_fmts, [], is_break, prefix)

        def exit_handler(regs):
            if hook_id not in self.hooks_by_id:
                return

            # 1. Recover Args (if they were saved)
            saved_args = []

            # NOTE: If we delegated entry, arg_fmts is empty, so we won't pop.
            # If we had standard entry, arg_fmts is present, so we pop.
            if arg_fmts:
                key = yield from self._get_context_key()
                stack = self.call_stacks[key]
                if stack:
                    saved_args = stack.pop()
                else:
                    saved_args = [None] * len(arg_fmts)  # Error state

            if exit_method:
                yield from exit_method(regs)
            else:
                # 2. Capture Retval
                ret_vals = []
                if ret_fmts:
                    try:
                        retval = regs.get_retval()
                    except Exception:
                        # Fallback if architecture doesn't define retval or access fails
                        retval = 0
                    ret_vals = [retval]
                    if len(ret_fmts) > 1:
                        ret_vals.extend([None]*(len(ret_fmts)-1))

                # Print (Print Once Rule)
                yield from self._execute_action(saved_args, ret_vals, arg_fmts, ret_fmts, is_break, prefix, is_ret=True)

        # Apply Hooks

        # ENTRY: Needed if normal uprobe OR if retprobe needs to capture args OR if we have delegated entry
        needs_entry = (not is_retprobe) or (is_retprobe and len(
            arg_fmts) > 0) or (entry_method is not None)

        # EXIT: Needed only if retprobe
        needs_exit = is_retprobe

        if needs_entry:
            h = uprobes.uprobe(
                path=path, symbol=target_val,
                process_filter=cmd.get('process_filter'),
                pid_filter=cmd.get('pid_filter'),
                on_enter=True, on_return=False
            )(entry_handler)
            hook_data['handles'].append(('uprobe', h))

        if needs_exit:
            h = uprobes.uprobe(
                path=path, symbol=target_val,
                process_filter=cmd.get('process_filter'),
                pid_filter=cmd.get('pid_filter'),
                on_enter=False, on_return=True
            )(exit_handler)
            hook_data['handles'].append(('uprobe', h))

        self.logger.info(
            f"Registered {hook_data['type']} {hook_id}: {action_str}")
        return {"id": hook_id}

    def _register_syscall(self, cmd):
        name = cmd.get('name')
        if not name:
            raise ValueError("Missing 'name'")
        action_str = cmd.get('action')
        if not action_str:
            raise ValueError("Missing action")

        hook_id = self.next_hook_id
        self.next_hook_id += 1

        is_break = 'break' in action_str
        arg_fmts, _ = self._parse_print_formats(action_str)

        syscall_method = None
        if arg_fmts and len(arg_fmts) == 1:
            syscall_method = self._resolve_plugin_method(arg_fmts[0])

        prefix = f"syscall:{name}"

        self.hooks_by_id[hook_id] = {
            'type': 'syscall',
            'raw_action': action_str,
            'name': name,
            'handles': []
        }

        def handler(regs, proto, sc, *args):
            if hook_id not in self.hooks_by_id:
                return

            if syscall_method:
                yield from syscall_method(regs, proto, sc, *args)
            else:
                count = len([f for f in arg_fmts if f != '%proc'])
                vals = yield from regs.get_args_portal(count, 'syscall')
                yield from self._execute_action(vals, [], arg_fmts, [], is_break, prefix)

        h = syscalls.syscall(
            name_or_pattern=name,
            comm_filter=cmd.get('process_filter'),
            pid_filter=cmd.get('pid_filter')
        )(handler)
        self.hooks_by_id[hook_id]['handles'].append(('syscall', h))

        self.logger.info(f"Registered syscall {hook_id}")
        return {"id": hook_id}

    def _execute_action(self, arg_vals, ret_vals, arg_fmts, ret_fmts, is_break, prefix, is_ret=False):
        if is_break:
            self.logger.warning(f"Dynamic Breakpoint: {prefix}")
            pdb.set_trace()
            return

        out_args = []
        idx = 0
        for fmt in arg_fmts:
            if fmt == '%proc':
                try:
                    pname = yield from self.plugins.osi.get_proc_name()
                    out_args.append(pname)
                except Exception:
                    # Introspection failure
                    out_args.append("?")
            else:
                if idx < len(arg_vals):
                    out_args.append((yield from self._format_value(fmt, arg_vals[idx])))
                    idx += 1
                else:
                    out_args.append("?")

        out_rets = []
        idx = 0
        for fmt in ret_fmts:
            if idx < len(ret_vals):
                out_rets.append((yield from self._format_value(fmt, ret_vals[idx])))
                idx += 1
            else:
                out_rets.append("?")

        lhs = ", ".join(out_args)
        rhs = ", ".join(out_rets)

        if is_ret:
            # If we are printing at return, and we had args, format is `func(args) = ret`
            # If no args were captured, just `func = ret`
            msg = f"{prefix}({lhs}) = {rhs}" if arg_fmts else f"{prefix} = {rhs}"
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
                if not hasattr(self.plugins, 'osi'):
                    self.plugins.load_plugin('osi')
                name = yield from self.plugins.osi.get_fd_name(val)
                return f"{val}({name or '?'})"
            except Exception:
                return f"{val}(?)"

        if fmt == '%s':
            try:
                return f'"{yield from self.plugins.mem.read_str(val)}"'
            except Exception:
                return f"<bad-str:{val:x}>"

        m = re.match(r'%(?P<t>[uix])(?P<b>8|16|32|64)', fmt)
        if m:
            t, b = m.group('t'), int(m.group('b'))
            try:
                d = yield from self.plugins.mem.read_bytes(val, b//8)
                c = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[b//8]
                if t == 'i':
                    c = c.lower()
                v = struct.unpack(f"<{c}", d)[0]
                return f"{v:x}" if t == 'x' else str(v)
            except Exception:
                return f"<bad-mem:{val:x}>"

        return f"{val:x}(?)"
