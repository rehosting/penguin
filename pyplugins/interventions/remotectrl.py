from penguin import Plugin, plugins
import asyncio
import threading
import json
import os
import traceback

hooklogger = plugins.hooklogger


class RemoteCtrl(Plugin):
    """
    RemoteCtrl Plugin
    =================
    The remote control plane for Penguin instrumentation.
    Listens on a Unix socket to register probes and manipulate execution
    via the HookLogger plugin.
    """

    def __init__(self):
        outdir = self.get_arg("outdir") or "/tmp"
        self.socket_path = os.path.join(outdir, "remotectrl.sock")

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        self.running = True
        self.logger.info(
            f"RemoteCtrl: Listening for events on: {self.socket_path}")
        
        # Pre-register handlers to avoid repetitive getattr/hasattr calls
        self.handlers = {}
        for attr_name in dir(self):
            if attr_name.startswith("_handle_"):
                handler = getattr(self, attr_name)
                if callable(handler):
                    cmd_type = attr_name[len("_handle_"):]
                    self.handlers[cmd_type] = handler

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
            handler = self.handlers.get(cmd_type)

            if handler:
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
        path = cmd.get('path')
        symbol = cmd.get('symbol')
        action = cmd.get('action')
        pid = cmd.get('pid_filter')
        proc = cmd.get('process_filter')
        logfile = cmd.get('logfile', None)
        
        hid = hooklogger.register_uprobe(path, symbol, action, pid, proc, logfile)
        return {"id": hid}

    def _handle_syscall(self, cmd):
        name = cmd.get('name')
        action = cmd.get('action')
        pid = cmd.get('pid_filter')
        proc = cmd.get('process_filter')
        logfile = cmd.get('logfile', None)
        
        hid = hooklogger.register_syscall(name, action, pid, proc, logfile)
        return {"id": hid}

    def _handle_list(self, cmd):
        return {"hooks": hooklogger.list_hooks()}

    def _handle_disable(self, cmd):
        hook_id = cmd.get('id')
        if hook_id is not None:
            try:
                hook_id = int(hook_id)
            except (ValueError, TypeError):
                raise ValueError("Invalid 'id' format")
            
            hooklogger.disable_hook(hook_id)
            return {"message": f"Hook {hook_id} disabled"}
        else:
            count = hooklogger.disable_all()
            return {"message": f"All {count} hooks disabled"}