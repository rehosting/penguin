"""
OSI plugin for querying process, file descriptor, and memory mapping information from the guest OS via the hypervisor portal.
Provides utilities for process arguments, environment, handles, mappings, and file descriptors.
"""

from penguin import Plugin, plugins
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from wrappers.generic import Wrapper
from wrappers.osi_wrap import MappingWrapper, MappingsWrapper

kffi = plugins.kffi


class OSI(Plugin):
    """
    Plugin for querying OS-level information (processes, FDs, mappings) from the guest via the hypervisor portal.
    """
    def get_fd_name(self, fd, pid=None):
        """
        Get the filename for a specific file descriptor.

        This uses the more efficient get_fds function that can return information
        for a specific file descriptor instead of sending a separate hypercall.

        Args:
            fd (int): File descriptor number
            pid (int, optional): Process ID, or None for current process

        Returns:
            str: The file descriptor name, or None if not found
        """
        self.logger.debug(f"get_fd_name called: fd={fd}")

        # Try using the get_fds functionality first (more efficient)
        # Only request the single FD we need
        fds = yield from self.get_fds(pid=pid, start_fd=fd, count=1)
        if fds and len(fds) > 0 and fds[0].fd == fd:
            fd_name = fds[0].name
            self.logger.debug(
                f"File descriptor name read successfully: {fd_name}")
            return fd_name

    def get_args(self, pid=None):
        """
        Get the argument list for a process.

        Args:
            pid (int, optional): Process ID, or None for current process

        Returns:
            list: List of argument strings
        """
        self.logger.debug("read_process_args called")
        proc_args = yield PortalCmd(hop.HYPER_OP_READ_PROCARGS, pid=pid)

        if not proc_args:
            return []

        # From examining the handle_op_read_procargs function in portal_osi.c:
        # - The kernel reads the process args area (mm->arg_start to mm->arg_end)
        # - In Linux, arguments are already null-terminated in memory
        # - The kernel converts nulls to spaces (except the final one)
        # - This creates a space-separated string, similar to /proc/pid/cmdline

        # First, strip any trailing null bytes at the end of the buffer
        proc_args = proc_args.rstrip(b'\0')

        # Split by spaces which is how the kernel formats the arguments
        # The kernel function converts nulls to spaces except for the last one
        args = proc_args.decode('latin-1', errors='replace').split()

        # Remove any binary garbage that might be present (common issue with syscalls)
        clean_args = []
        for arg in args:
            # Remove trailing null characters from each argument
            arg = arg.rstrip('\0')

            # Simple heuristic: if most chars are printable, it's probably a valid arg
            if sum(c.isprintable() for c in arg) > len(arg) * 0.8:
                clean_args.append(arg)

        self.logger.debug(f"Proc args read successfully: {clean_args}")
        return clean_args

    def get_proc_name(self, pid=None):
        """
        Get the process name (first argument) for a process.

        Args:
            pid (int, optional): Process ID, or None for current process

        Returns:
            str: Process name or '[???]' if not found
        """
        self.logger.debug("get_process_name called")
        proc_name = yield from self.get_args(pid)
        if proc_name:
            return proc_name[0]
        return "[???]"

    def get_env(self, pid=None):
        """
        Get the environment variables for a process.

        Args:
            pid (int, optional): Process ID, or None for current process

        Returns:
            dict: Dictionary of environment variables
        """
        self.logger.debug("get_process_env called")
        proc_env = yield PortalCmd(hop.HYPER_OP_READ_PROCENV, pid=pid)
        if proc_env:
            args = [i.decode("latin-1").split("=")
                    for i in proc_env.split(b"\0") if i]
            env = {k: v for k, v in args}
            self.logger.debug(f"Proc env read successfully: {env}")
            return env
        return {}

    def get_proc(self, pid=None):
        """
        Get detailed process information for a process.

        Args:
            pid (int, optional): Process ID, or None for current process

        Returns:
            Wrapper: Process information wrapper object
        """
        proc_bytes = yield PortalCmd(hop.HYPER_OP_OSI_PROC, 0, 0, pid)
        if proc_bytes:
            pb = kffi.from_buffer("osi_proc", proc_bytes)
            wrap = Wrapper(pb)
            wrap.name = proc_bytes[pb.name_offset:].decode("latin-1")
            return wrap

    def get_mappings(self, pid=None):
        """
        Get memory mappings for a process.

        Args:
            pid (int, optional): Process ID, or None for current process

        Returns:
            MappingsWrapper: Wrapper containing all memory mappings
        """
        skip = 0
        self.logger.debug(
            f"get_proc_mappings called for pid={pid}, skip={skip}")

        all_mappings = []
        current_skip = skip
        total_count = 0

        while True:
            # Send skip count in addr field, as per portal.c implementation
            self.logger.debug(f"Fetching mappings with skip={current_skip}")
            mappings_bytes = yield PortalCmd(hop.HYPER_OP_OSI_MAPPINGS, current_skip, 0, pid)

            if not mappings_bytes:
                self.logger.debug("No mapping data received")
                if not all_mappings:  # If this was our first request
                    return [], 0
                break

            orh_struct = kffi.from_buffer("osi_result_header", mappings_bytes)
            count = orh_struct.result_count
            total_count = orh_struct.total_count

            # Get the actual size of data returned from the kernel
            total_size = len(mappings_bytes)

            self.logger.debug(
                f"Received {count} mappings out of {total_count}, buffer size: {total_size}")

            # Skip the header (two 64-bit counts)
            offset = 16
            mappings = []
            t_size = kffi.sizeof("osi_module")

            # Verify expected module array size against buffer size
            expected_end = offset + (count * t_size)
            if expected_end > total_size:
                self.logger.warning(
                    f"Buffer too small for all mappings: need {expected_end}, got {total_size}. Adjusting count.")
                # Adjust count to fit available buffer
                adjusted_count = (total_size - offset) // t_size
                if adjusted_count < count:
                    count = adjusted_count
                    self.logger.warning(f"Adjusted mapping count to {count}")

            # Each mapping entry
            for i in range(count):
                # Ensure we have enough data
                if offset + t_size > total_size:
                    self.logger.error(
                        f"Buffer too short for mapping {i}: offset {offset}, len {total_size}")
                    break

                try:
                    # Create wrapper object for the mapping
                    b = kffi.from_buffer(
                        "osi_module", mappings_bytes, instance_offset_in_buffer=offset)
                    mapping = MappingWrapper(b)

                    # Check if name_offset is within bounds, and if the offset makes sense
                    if mapping.name_offset and mapping.name_offset < total_size:
                        try:
                            # Find null terminator - safely handle potential out-of-bounds access
                            end = mappings_bytes.find(
                                b'\0', mapping.name_offset)
                            if end != -1 and end < total_size:
                                name = mappings_bytes[mapping.name_offset:end].decode(
                                    'latin-1', errors='replace')
                                mapping.name = name
                            else:
                                # If no null terminator found or out of bounds, use a limited slice
                                max_name_len = total_size - mapping.name_offset
                                if max_name_len > 0:
                                    name = mappings_bytes[mapping.name_offset:mapping.name_offset+max_name_len].decode(
                                        'latin-1', errors='replace')
                                    mapping.name = name
                                else:
                                    mapping.name = "[unknown]"
                        except Exception as e:
                            self.logger.warning(
                                f"Error decoding name for mapping {i}: {e}")
                            mapping.name = "[invalid name]"
                    else:
                        mapping.name = "[unknown]"

                    mappings.append(mapping)
                    offset += t_size  # Size of struct osi_module
                except Exception as e:
                    self.logger.error(f"Error unpacking mapping {i}: {e}")
                    break

            all_mappings.extend(mappings)

            # If we received less mappings than requested or already have all mappings, we're done
            if len(mappings) == 0 or len(all_mappings) >= total_count:
                break

            # Update skip for next request
            current_skip += len(mappings)
        ret_mappings = MappingsWrapper(all_mappings)

        self.logger.debug(f"Retrieved a total of {len(all_mappings)} mappings")
        return ret_mappings

    def get_proc_handles(self):
        """
        Retrieve a list of process handles from the kernel.

        Returns:
            list: List of process handle objects with properties: pid, taskd, start_time
        """
        self.logger.debug("get_proc_handles called")

        # Fetch proc handles from the kernel
        proc_handles_bytes = yield PortalCmd(hop.HYPER_OP_OSI_PROC_HANDLES, 0, 0)

        if not proc_handles_bytes:
            self.logger.debug("No process handles data received")
            return []

        # Get the actual size of data returned from the kernel
        total_size = len(proc_handles_bytes)

        # Ensure we have enough data for the header
        if total_size < 16:
            self.logger.error(
                f"Buffer too small for header: {total_size} bytes")
            return []

        # Extract header information
        orh_struct = kffi.from_buffer("osi_result_header", proc_handles_bytes)
        count = orh_struct.result_count
        total_count = orh_struct.total_count

        self.logger.debug(
            f"Received {count} process handles out of {total_count}")

        # Validate count values
        if count > 10000:
            self.logger.warning(
                f"Unreasonably large handle count: {count}, capping at 1000")
            count = 1000

        # Skip the header
        offset = kffi.sizeof("osi_result_header")
        handles = []
        handle_type = "osi_proc_handle"
        handle_size = kffi.sizeof(handle_type)

        # Calculate how many handles can actually fit in the buffer
        max_possible_count = (total_size - offset) // handle_size
        safe_count = min(count, max_possible_count)

        if safe_count < count:
            self.logger.warning(
                f"Buffer can only fit {safe_count} handles out of reported {count}")
            count = safe_count

        # Process each handle
        for i in range(count):
            if offset + handle_size > total_size:
                self.logger.error(
                    f"Buffer too short for handle {i}: offset {offset}, len {total_size}")
                break

            try:
                # Create wrapper object for the handle
                handle = kffi.from_buffer(
                    "osi_proc_handle", proc_handles_bytes, instance_offset_in_buffer=offset)
                handle_wrapper = Wrapper(handle)
                handles.append(handle_wrapper)
                offset += handle_size
            except Exception as e:
                self.logger.error(f"Error unpacking handle {i}: {e}")
                break

        self.logger.debug(f"Retrieved {len(handles)} process handles")
        return handles

    def get_fds(self, pid=None, start_fd=0, count=None):
        """
        Retrieve file descriptors for a process.

        Args:
            pid (int, optional): Process ID, or None for current process
            start_fd (int, optional): FD number to start listing from (default: 0)
            count (int, optional): Maximum number of file descriptors to return (None for all)

        Returns:
            list: List of file descriptor objects with fd and name properties
        """
        # Ensure start_fd is an integer
        if start_fd is None:
            start_fd = 0

        self.logger.debug(
            f"get_fds called: start_fd={start_fd}, pid={pid}, count={count}")
        fds = []
        current_fd = start_fd
        while True:
            fds_bytes = yield PortalCmd(hop.HYPER_OP_READ_FDS, current_fd, 0, pid)

            if not fds_bytes:
                self.logger.debug("No file descriptors data received")
                # Return empty list only if we haven't fetched any FDs yet
                if not fds:
                    return []
                break

            # Get the actual size of data returned from the kernel
            total_size = len(fds_bytes)

            # Ensure we have enough data for the header
            if total_size < 16:
                self.logger.error(
                    f"Buffer too small for header: {total_size} bytes")
                return []

            # Make sure we're using the correct header structure format
            orh_struct = kffi.from_buffer("osi_result_header", fds_bytes)
            # In the kernel, these are LE64 values, need to access correctly
            batch_count = orh_struct.result_count
            total_count = orh_struct.total_count

            self.logger.debug(
                f"Raw header values: result_count={batch_count}, total_count={total_count}")

            self.logger.debug(
                f"Received {batch_count} file descriptors out of {total_count}")

            # Break if there are no FDs in this batch to avoid infinite loop
            if batch_count == 0:
                self.logger.debug(
                    "No file descriptors in this batch, breaking loop")
                break

            # Skip the header
            offset = kffi.sizeof("osi_result_header")
            fd_size = kffi.sizeof("osi_fd_entry")

            # Process each FD entry
            for i in range(batch_count):
                if offset + fd_size > total_size:
                    self.logger.error(
                        f"Buffer too short for FD {i}: offset {offset}, len {total_size}")
                    break

                try:
                    # Create wrapper object for the FD
                    fd_entry = kffi.from_buffer(
                        "osi_fd_entry", fds_bytes, instance_offset_in_buffer=offset)
                    fd_wrapper = Wrapper(fd_entry)

                    # Extract the path name using name_offset
                    if fd_entry.name_offset and fd_entry.name_offset < total_size:
                        try:
                            # Find null terminator
                            end = fds_bytes.find(b'\0', fd_entry.name_offset)
                            if end != -1 and end < total_size:
                                name = fds_bytes[fd_entry.name_offset:end].decode(
                                    'latin-1', errors='replace')
                                fd_wrapper.name = name
                            else:
                                # Limited slice if no null terminator
                                max_name_len = min(
                                    256, total_size - fd_entry.name_offset)
                                if max_name_len > 0:
                                    name = fds_bytes[fd_entry.name_offset:fd_entry.name_offset+max_name_len].decode(
                                        'latin-1', errors='replace')
                                    fd_wrapper.name = name
                                else:
                                    fd_wrapper.name = "[unknown]"
                        except Exception as e:
                            self.logger.warning(
                                f"Error decoding name for FD {i}: {e}")
                            fd_wrapper.name = "[invalid name]"
                    else:
                        fd_wrapper.name = "[unknown]"

                    fds.append(fd_wrapper)
                    offset += fd_size
                except Exception as e:
                    self.logger.error(f"Error unpacking FD entry {i}: {e}")
                    break
            # Track how many FDs we've processed in this batch
            self.logger.debug(
                f"Retrieved {batch_count} file descriptors in this batch, total now: {len(fds)}")

            # Update current_fd for next iteration (pagination)
            # We need to update by batch_count, not the total accumulated fds
            # Otherwise we might skip entries or go into an infinite loop
            current_fd += batch_count

            # Break if we've got all available FDs from kernel
            if len(fds) >= total_count:
                break

            # Break if we've fetched enough FDs based on count parameter
            if count is not None and len(fds) >= count:
                break

        # Protection against incorrect data in the list or count mismatch
        if count is not None and len(fds) > count:
            fds = fds[:count]

        # Just return the list of FDs
        return fds

    def get_mapping_by_addr(self, addr):
        """
        Get the memory mapping containing a specific address.

        Args:
            addr (int): Address to look up

        Returns:
            MappingWrapper or None: Mapping containing the address, or None if not found
        """
        self.logger.debug(f"get_mapping_by_addr called: addr={addr:#x}")
        maps = yield from self.get_mappings()
        if maps:
            mapping = maps.get_mapping_by_addr(addr)
            if mapping:
                self.logger.debug(
                    f"Mapping found: {mapping.name} at {mapping.start:#x} - {mapping.end:#x}")
                return mapping
            else:
                self.logger.debug(f"No mapping found for addr={addr:#x}")