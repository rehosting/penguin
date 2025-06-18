"""
# Execs

This plugin provides a generic interface for monitoring process execution events in the guest.
It subscribes to syscall events for both `execve` and `execveat`, extracts execution details (process name,
arguments, environment), and publishes this information to listeners via the plugin event system.
Other plugins can subscribe to these events for custom analysis, logging, or automation.

## Arguments
- `outdir` (`str`): Output directory for any optional logging or artifacts.

## Plugin Interface
- Publishes `exec_event` with a dictionary containing execution details:

```python
{
    'procname': str or None,      # Name of the executed program (target of exec), resolved via OSI if AT_EMPTY_PATH
    'argv': list[str],            # Argument vector for the new program
    'envp': dict[str, str],       # Environment for the new program
    'raw_args': tuple,            # Raw arguments to the handler
    'parent': Wrapper or None,    # Process info wrapper for the process making the exec call
}
```

Both execve and execveat syscalls are tracked and normalized into this unified event format.

## Overall Purpose
The Execs plugin provides a flexible, extensible interface for tracking process execution events
in the guest, enabling downstream plugins to implement their own analysis or response logic.
"""

from typing import List, Dict, Any, Generator, Optional
from penguin import plugins, Plugin
from wrappers.generic import Wrapper
from wrappers.ptregs_wrap import PtRegsWrapper

# Constants needed for execveat handling (define these elsewhere as needed)
AT_FDCWD: int = -100  # Placeholder, define actual value as needed
AT_EMPTY_PATH: int = 0x1000  # Placeholder, define actual value as needed


class Execs(Plugin):
    """
    Plugin for monitoring execve and execveat syscalls and publishing normalized execution events.

    Publishes 'exec_event' with a dictionary containing:
        procname (str or None): Name of the executed program (target of exec), resolved via OSI if AT_EMPTY_PATH
        argv (List[str]): Argument vector for the new program
        envp (Dict[str, str]): Environment for the new program
        flags (Optional[int]): Flags for execveat, None for execve
        syscall (int): Syscall number
        proto (Any): Syscall prototype object
        type (str): 'execve' or 'execveat'
        raw_args (tuple): Raw arguments to the handler
        parent (str): Name of the process making the exec call
    """

    def __init__(self) -> None:
        """
        ### Initialize Execs plugin and subscribe to execve/execveat syscalls.

        Registers the plugin and sets up syscall hooks.
        """
        plugins.register(self, "exec_event")

    def _read_ptrlist(self, ptr: int, chunk_size: int = 8,
                      max_length: int = 256) -> Generator[Any, None, List[str]]:
        """
        ### Dynamically read a NULL-terminated pointer list from guest memory, with a maximum length for safety.

        Coroutine: use `yield from` to call.

        **Args:**
        - `ptr` (`int`): Pointer to the start of the list.
        - `chunk_size` (`int`): Number of pointers to read per chunk.
        - `max_length` (`int`): Maximum number of entries to read (default: 256).

        **Returns:**
        - `List[str]`: List of strings (argument or environment values).
        """
        if not ptr:
            return []
        result = []
        offset = 0
        consecutive_failures = 0
        max_consecutive_failures = 3

        while len(result) < max_length:
            try:
                buf = yield from plugins.mem.read_ptrlist(ptr + offset * 8, chunk_size)

                # If we get an empty buffer, we've likely hit the end
                if not buf or len(buf) == 0:
                    self.logger.debug(
                        f"_read_ptrlist: empty buffer at offset {offset}, stopping")
                    break

                # Reset failure counter on successful read
                consecutive_failures = 0

                found_null = False
                for i, p in enumerate(buf):
                    if p == 0 or len(result) >= max_length:
                        found_null = True
                        break
                    try:
                        val = yield from plugins.mem.read_str(p)
                        if val is None or val == "":
                            # Empty string might indicate end of list
                            self.logger.debug(
                                f"_read_ptrlist: empty string at pointer {hex(p)}, treating as end")
                            found_null = True
                            break
                        result.append(val)
                    except Exception as e:
                        # Log and skip unreadable pointers
                        self.logger.warning(
                            f"_read_ptrlist: error reading string at {hex(p)}: {e}")
                        val = "[unreadable]"
                        result.append(val)

                # If we found a null terminator, stop
                if found_null:
                    break

                offset += chunk_size

            except Exception as e:
                consecutive_failures += 1
                self.logger.warning(
                    f"_read_ptrlist: error reading pointer list at offset {offset}: {e}")

                # If we've had too many consecutive failures, give up
                if consecutive_failures >= max_consecutive_failures:
                    self.logger.error(
                        f"_read_ptrlist: too many consecutive failures ({consecutive_failures}), stopping")
                    break

                # Try to continue with the next chunk
                offset += chunk_size

        # If we reach max_length, log a warning
        if len(result) >= max_length:
            self.logger.warning(
                f"_read_ptrlist: reached max_length={max_length}, possible unterminated list at {hex(ptr)}")

        return result

    def _parse_envp(self, envp_list: List[str]) -> Dict[str, str]:
        """
        ### Convert envp list to a dictionary, handling both 'key=value' and 'key' (empty value) cases.

        **Args:**
        - `envp_list` (`List[str]`): List of environment variable strings.

        **Returns:**
        - `Dict[str, str]`: Dictionary of environment variables.
        """
        env_dict = {}
        for entry in envp_list:
            if '=' in entry:
                k, v = entry.split('=', 1)
                env_dict[k] = v
            else:
                env_dict[entry] = ''
        return env_dict

    def _parse_args_env(
            self, argv_ptr: int, envp_ptr: int) -> Generator[Any, None, tuple[List[str], Dict[str, str]]]:
        """
        ### Unified parsing for argv and envp pointers.

        Coroutine: use `yield from` to call.

        **Args:**
        - `argv_ptr` (`int`): Pointer to argv list.
        - `envp_ptr` (`int`): Pointer to envp list.

        **Returns:**
        - `Tuple[List[str], Dict[str, str]]`: argv list and envp dictionary.
        """
        argv_list = yield from self._read_ptrlist(argv_ptr)
        envp_list = yield from self._read_ptrlist(envp_ptr)
        envp_dict = self._parse_envp(envp_list)
        return argv_list, envp_dict

    def _resolve_procname_val(
            self, procname: str, dirfd: Optional[int], flags: Optional[int]) -> Generator[Any, None, Optional[str]]:
        """
        ### Helper to resolve the effective procname value for execve/execveat, handling dirfd and flags.

        Coroutine: use `yield from` to call.

        **Args:**
        - `procname` (`str`): The raw procname string from memory.
        - `dirfd` (`Optional[int]`): Directory file descriptor (for execveat).
        - `flags` (`Optional[int]`): Flags for execveat.

        **Returns:**
        - `str` or `None`: The resolved procname value.
        """
        if dirfd is not None and flags is not None:
            def is_at_fdcwd(val):
                return int(val) == AT_FDCWD or (isinstance(val, int)
                                                and (val & 0xFFFFFFFF) == (AT_FDCWD & 0xFFFFFFFF))

            is_absolute = procname.startswith("/")

            if procname == "" and (flags & AT_EMPTY_PATH):
                # AT_EMPTY_PATH: execute the program referred to by dirfd
                return (yield from plugins.OSI.get_fd_name(dirfd))
            elif is_absolute:
                # Absolute path: dirfd is ignored
                return procname
            elif is_at_fdcwd(dirfd):
                # AT_FDCWD with relative path: interpret relative to current working directory
                # The procname is already relative, so we return it as-is since the kernel
                # will resolve it relative to the current working directory
                return procname
            else:
                # Relative path with specific dirfd: the path is relative to the directory
                # referred to by dirfd. We return the relative path as-is since the kernel
                # handles the resolution.
                return procname
        else:
            # execve case: no dirfd or flags
            return procname

    def _handle_exec_event(
        self,
        regs: PtRegsWrapper,
        proto: Any,
        syscall: int,
        fname_ptr: int,
        argv_ptr: int,
        envp_ptr: int,
        dirfd: Optional[int] = None,
        flags: Optional[int] = None,
    ) -> Generator[Any, None, None]:
        """
        ### Shared handler for execve and execveat syscalls. Handles argument parsing and event publishing.

        **Args:**
        - `cpu` (`int`): CPU id.
        - `proto` (`Any`): Protocol object.
        - `syscall` (`int`): Syscall number.
        - `fname_ptr` (`int`): Pointer to filename string.
        - `argv_ptr` (`int`): Pointer to argv list.
        - `envp_ptr` (`int`): Pointer to envp list.
        - `dirfd` (`Optional[int]`): Directory file descriptor (for execveat).
        - `flags` (`Optional[int]`): Flags for execveat.

        **Returns:**
        - `None`
        """
        procname = yield from plugins.mem.read_str(fname_ptr)
        argv_list, envp_dict = yield from self._parse_args_env(argv_ptr, envp_ptr)
        parent = yield from plugins.OSI.get_proc()
        procname_val = yield from self._resolve_procname_val(procname, dirfd, flags)
        event = {
            'procname': procname_val,
            'argv': argv_list,
            'envp': envp_dict,
            'raw_args': (regs, proto, syscall, dirfd, fname_ptr, argv_ptr, envp_ptr, flags) if dirfd is not None and flags is not None else (regs, proto, syscall, fname_ptr, argv_ptr, envp_ptr),
            'parent': parent,
        }
        yield from plugins.portal_publish(self, "exec_event", Wrapper(event))

    @plugins.syscalls.syscall("on_sys_execve_enter")
    def on_execve(self, regs: PtRegsWrapper, proto: Any, syscall: int,
                  fname_ptr: int, argv_ptr: int, envp_ptr: int) -> Generator[Any, None, None]:
        """
        ### Callback for execve syscall. Delegates to shared handler.
        """
        yield from self._handle_exec_event(regs, proto, syscall, fname_ptr, argv_ptr, envp_ptr)

    @plugins.syscalls.syscall("on_sys_execveat_enter")
    def on_execveat(self, regs: PtRegsWrapper, proto: Any, syscall: int, dirfd: int,
                    fname_ptr: int, argv_ptr: int, envp_ptr: int, flags: int) -> Generator[Any, None, None]:
        """
        ### Callback for execveat syscall. Delegates to shared handler.
        """
        yield from self._handle_exec_event(regs, proto, syscall, fname_ptr, argv_ptr, envp_ptr, dirfd, flags)
