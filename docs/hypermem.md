# Hypermem

## What is Hypermem?

**Hypermem** is a powerful memory introspection and manipulation tool that provides a cooperative, hypercall-based protocol for reading from and writing to guest memory. Unlike traditional memory introspection approaches that directly access the physical memory, Hypermem uses a cooperative approach between the guest and hypervisor, providing robust memory access and manipulation capabilities across different architectures and OS versions.

## How Hypermem Works

1. **Guest-Hypervisor Communication:** The guest OS registers a memory region with the hypervisor via a hypercall. This region serves as a communication channel between the guest and hypervisor.

2. **Memory Operations:** The hypervisor can request various operations (read, write, etc.) by writing commands to this shared memory region. The guest kernel then processes these requests and writes results back to the shared region.

3. **Python API:** Hypermem exposes a convenient Python API for PANDA plugins to read and write guest memory, access process information, inspect file descriptors, and more.

## Memory Region Structure

The communication between the guest kernel and hypervisor happens through a shared memory region with the following structure:

```c
struct mem_region {
    __le64 op;       // Operation code (read, write, etc.)
    __le64 addr;     // Target address or parameter
    __le64 size;     // Size of data or parameter
    char data[CHUNK_SIZE]; // Data buffer (4072 bytes)
};
```

## Example: Using Hypermem in a Python Plugin

### Basic Usage Pattern

```python
from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins

class MemoryAccess(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.memory_access")
        self.hyp = plugins.hypermem
        
        # Register a callback for syscall events - note the self.hyp.wrap() wrapper
        # This wrapper is essential when using hypermem within a callback
        self.panda.hsyscall("on_sys_read_return")(self.hyp.wrap(self.on_read))
    
    def on_read(self, cpu, proto, syscall, hook, fd, buf_addr, count):
        # Read a string from the buffer address
        buffer_content = yield from self.hyp.read_str(buf_addr)
        self.logger.info(f"Read buffer content: {buffer_content}")
        
        # Write a string to memory
        yield from self.hyp.write_str(buf_addr, "Modified content")
        
        # Read an integer value from memory
        value = yield from self.hyp.read_int(buf_addr + 16)
        self.logger.info(f"Integer value: {value:#x}")
```

### Advanced Examples

#### Reading and Manipulating Kernel Data Structures

This example shows how to read and modify a complex kernel structure by accessing its fields:

```python
class SocketMonitor(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.socket_monitor")
        self.hyp = plugins.hypermem
        
        # Register the syscall handler with proper wrapping
        self.panda.hsyscall("on_sys_socket_enter")(self.hyp.wrap(self.inspect_socket_setup))
        
    def inspect_socket_setup(self, cpu, proto, syscall, hook, domain, type, protocol):
        # Read kernel structure at socket_options address
        sock_opts_addr = yield from self.hyp.read_ptr(some_known_addr)
        
        # Read individual fields from the structure
        flags = yield from self.hyp.read_int(sock_opts_addr)
        timeout = yield from self.hyp.read_int(sock_opts_addr + 4)
        
        self.logger.info(f"Socket options - flags: {flags:#x}, timeout: {timeout}")
        
        # Modify the timeout value
        yield from self.hyp.write_int(sock_opts_addr + 4, 30000)  # 30 second timeout
```

#### Memory Buffer Inspection and Modification

This example shows how to inspect and modify a buffer, useful for packet or data inspection:

```python
class BufferInspector(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.buffer_inspector")
        self.hyp = plugins.hypermem
        
        # Register the syscall handler with proper wrapping
        self.panda.hsyscall("on_sys_write_enter")(self.hyp.wrap(self.inspect_buffer))
        
    def inspect_buffer(self, cpu, proto, syscall, hook, fd, buf_addr, count):
        if count <= 0 or count > 1024*1024:  # Sanity check
            return
            
        # Read the entire buffer
        buffer = yield from self.hyp.read_bytes(buf_addr, count)
        
        # Inspect buffer contents (e.g., looking for a signature)
        if b"HTTP/1.1" in buffer:
            self.logger.info("Found HTTP request in buffer")
            
            # Modify the buffer (e.g., changing a header)
            if b"User-Agent:" in buffer:
                # Create a modified buffer with a different User-Agent
                modified = buffer.replace(
                    b"User-Agent: Mozilla",
                    b"User-Agent: CustomAgent"
                )
                
                # Write the modified buffer back
                yield from self.hyp.write_bytes(buf_addr, modified)
                
                # Update count if necessary
                if len(modified) != len(buffer):
                    syscall.args[2] = len(modified)
```

#### Process Environment Information

This example demonstrates how to access process information:

```python
class ProcessInfoPlugin(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.process_info")
        self.hyp = plugins.hypermem
        
        # Register the syscall handler with proper wrapping
        self.panda.hsyscall("on_sys_execve_enter")(self.hyp.wrap(self.process_info))
        
    def process_info(self, cpu, proto, syscall, hook, filename, argv, envp):
        # Get command line arguments
        args = yield from self.hyp.get_proc_args()
        self.logger.info(f"Process arguments: {args}")
        
        # Get environment variables
        env = yield from self.hyp.get_proc_env()
        self.logger.info(f"Environment variables: {env}")
        
        # Get process ID
        pid = yield from self.hyp.get_proc_pid()
        self.logger.info(f"Process ID: {pid}")
        
        # Read the executable path
        exe_path = yield from self.hyp.read_str(filename)
        self.logger.info(f"Executing: {exe_path}")
        
        # If PATH environment variable exists, log it
        if "PATH" in env:
            self.logger.info(f"PATH: {env['PATH']}")
```

## API Reference

### Reading Memory

#### Reading Raw Bytes

```python
data = yield from self.hyp.read_bytes(addr, size)
```

Reads `size` bytes from memory starting at `addr`.

#### Reading Strings

```python
string = yield from self.hyp.read_str(addr)
```

Reads a null-terminated string from memory starting at `addr`.

#### Reading Integers/Pointers

```python
# 32-bit integer
value = yield from self.hyp.read_int(addr)

# 64-bit integer
value = yield from self.hyp.read_long(addr)

# Architecture-appropriate pointer
ptr = yield from self.hyp.read_ptr(addr)
```

### Writing Memory

#### Writing Raw Bytes

```python
yield from self.hyp.write_bytes(addr, data)
```

Writes the bytes in `data` to memory starting at `addr`.

#### Writing Strings

```python
yield from self.hyp.write_str(addr, string)
```

Writes `string` to memory at `addr`

#### Writing Integers/Pointers

```python
# 32-bit integer
yield from self.hyp.write_int(addr, value)

# 64-bit integer
yield from self.hyp.write_long(addr, value)

# Architecture-appropriate pointer
yield from self.hyp.write_ptr(addr, value)
```

### Process Information

```python
# Get command line arguments
args = yield from self.hyp.get_proc_args()

# Get environment variables
env = yield from self.hyp.get_proc_env()

# Get process ID
pid = yield from self.hyp.get_proc_pid()
```

### File Descriptor Information

```python
# Get file name associated with a file descriptor
fd_name = yield from self.hyp.read_fd_name(fd)
```

## Real-world Example: IOCTL Interaction Test

Here's an example from the `ioctl_interaction_test.py` that demonstrates advanced memory manipulation using Hypermem:

```python
def syscall_test(self, cpu, proto, syscall, hook, fd, op, arg):
    if op == SIOCDEVPRIVATE:
        # Read a string from the arg address
        interface = yield from self.hyp.read_str(arg)
        self.logger.info(f"Interface: {interface}")
        
        # Read an integer from memory at offset IFNAMSIZ from arg
        data = yield from self.hyp.read_int(arg + IFNAMSIZ)
        self.logger.info(f"Data: {data:#x}")

        # Write a string to memory and read it back to verify
        to_write = "test"
        yield from self.hyp.write_str(arg, to_write)
        interface = yield from self.hyp.read_str(arg)
        assert interface == to_write, f"Expected {to_write}, got {interface}, r/w failed"

        # Write an integer to memory and read it back to verify
        to_write_int = 0x12345678
        yield from self.hyp.write_int(arg + IFNAMSIZ, to_write_int)
        data = yield from self.hyp.read_int(arg + IFNAMSIZ)
        assert data == to_write_int, f"Expected {to_write_int:#x}, got {data:#x}, r/w failed"

        # Get file descriptor name
        fd_name = yield from self.hyp.read_fd_name(fd) or "[???]"
        self.logger.info(f"FD: {fd_name}")

        # Get process arguments
        args = yield from self.hyp.get_proc_args()
        self.logger.info(f"Found process: {args}")
        
        # Get environment variables
        env = yield from self.hyp.get_proc_env()
        self.logger.info(f"Found env: {env}")
        
        # Get process ID
        pid = yield from self.hyp.get_proc_pid()
        self.logger.info(f"Found pid: {pid}")
```

## Understanding the Kernel Implementation

The Hypermem system works by registering a shared memory region between the guest kernel and hypervisor. The kernel module `hypermemcall.c` handles the guest-side implementation:

1. **Memory Region Registration:**
   ```c
   // Called when the hypervisor registers a memory region
   static void _register_cpu_memregion(cpu) {
       self.cpu_memregions[cpu] = self.panda.arch.get_arg(cpu, 1, convention="syscall")
   }
   ```

2. **Operation Handling:** The kernel module defines a set of operations and handlers:
   ```c
   enum HYPER_OP {
       HYPER_OP_NONE = 0,
       HYPER_OP_READ,
       HYPER_RESP_READ_OK,
       // ...and more
   };
   ```

3. **Handler Functions:** The kernel implements handlers for each operation:
   ```c
   static void handle_op_read(struct mem_region *mem_region) {
       // Copy data from user memory to the shared buffer
       resp = copy_from_user(
           (void*)mem_region->data,
           (const void __user *)(uintptr_t)le64_to_cpu(mem_region->addr),
           le64_to_cpu(mem_region->size));
       // Set response code
       mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
   }
   ```

## Operation Flow

1. The Python plugin requests an operation through the Hypermem API
2. The Hypermem plugin writes the operation code and parameters to the shared memory region
3. The hypervisor signals the guest kernel via a hypercall
4. The guest kernel processes the operation, accessing memory as needed
5. Results are written back to the shared memory region
6. The hypervisor reads the results and provides them to the Python plugin

## Differences from Traditional Memory Access

| Feature | Hypermem | Traditional Memory Access |
|---------|----------|---------------------------|
| **Access Method** | Cooperative via guest kernel | Direct physical memory access |
| **Reliability** | High - Uses proper kernel APIs | Medium - May break with kernel changes |
| **Error Handling** | Guest provides explicit error codes | Silent failures possible |
| **Virtual Memory** | Access respects virtual memory mappings | Requires manual translation |
| **Higher-level Functions** | Read strings, FDs, process info, etc. | Basic memory reads only |
| **Performance** | Slight overhead due to guest involvement | Generally faster |
| **Use Case** | Deep introspection, advanced manipulation | Simple memory access |

## References

- See [`pyplugins/analysis/hypermem.py`](../pyplugins/analysis/hypermem.py) for the full implementation
- See [`pyplugins/testing/ioctl_interaction_test.py`](../pyplugins/testing/ioctl_interaction_test.py) for usage examples
- See [`linux_builder/linux/6.13/drivers/igloo/hypermemcall.c`](../linux_builder/linux/6.13/drivers/igloo/hypermemcall.c) for the kernel implementation