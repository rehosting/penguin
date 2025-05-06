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

#### Worked Example: IOCTL Interaction with RALink Ethernet

This example demonstrates how Hypermem can be used to monitor and modify IOCTL calls for hardware interaction, specifically for the RALink Ethernet device used in TP-Link routers.

### The Problem

When rehosting TP-Link Archer C20 devices, the boot process stalls with a process repeatedly printing "swRegRead" to stderr. This function is responsible for reading registers from the ethernet switch hardware through IOCTL calls. Since the actual hardware isn't present in our emulation environment, we need to intercept these calls and provide appropriate responses.

### The Original Function (from GPL code)

```c
// From ArcherC20_V4_GPL/mtk_ApSoC_4320/apps/mtk7530_switch/switch.c
int reg_read(int offset, int *value)
{
    struct ifreq ifr;
    esw_reg reg;

    if (value == NULL)
        return -1;
    reg.off = offset;
    strncpy(ifr.ifr_name, "eth0", 5);
    ifr.ifr_data = &reg;
    if (-1 == ioctl(esw_fd, RAETH_ESW_REG_READ, &ifr)) {
        perror("ioctl");
        close(esw_fd);
        exit(0);
    }
    *value = reg.val;
    return 0;
}
```

This function is called by code that polls for specific bit patterns in the register values:

```c
// From ArcherC20_V4_GPL/mtk_ApSoC_4320/apps/mtk7530_switch/switch.c
void table_del(int argc, char *argv[])
{
    // ...
    for (i = 0; i < 20; i++) {
        reg_read(REG_ESW_WT_MAC_AD0, &value);
        if (value & 0x2) { //w_mac_done
            if (argv[1] != NULL)
                printf("done.\n");
            return;
        }
        usleep(1000);
    }
    if (i == 20)
        printf("timeout.\n");
}
```

### The Solution with Hypermem and Syscall Filtering

Using Hypermem combined with hypersyscalls filtering capabilities, we can create a plugin that specifically targets IOCTL system calls for the RALink Ethernet device and provides appropriate register values to allow the device to boot:

```python
from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins

# RALink Ethernet register definitions
RAETH_ESW_REG_READ = 0x89F1
REG_ESW_WT_MAC_AD0 = 0x34
REG_ESW_WT_MAC_ATC = 0x80
REG_ESW_TABLE_STATUS0 = 0x90

class RAEthPlugin(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.raeth")
        self.hyp = plugins.hypermem
        
        # Register our callback for IOCTL syscalls with specific filtering
        # Only intercept ioctl calls with cmd=RAETH_ESW_REG_READ (0x89F1)
        self.panda.hsyscall(
            "on_sys_ioctl_return", 
            arg_filter=[None, RAETH_ESW_REG_READ, None]
        )(self.hyp.wrap(self.handle_raeth_ioctl))
        
        # Register definitions for logging
        self.registers = {
            REG_ESW_WT_MAC_AD0: "REG_ESW_WT_MAC_AD0",
            REG_ESW_WT_MAC_ATC: "REG_ESW_WT_MAC_ATC",
            REG_ESW_TABLE_STATUS0: "REG_ESW_TABLE_STATUS0"
        }
        
    def handle_raeth_ioctl(self, cpu, proto, syscall, hook, fd, cmd, arg):
        """Handler specifically for RALink Ethernet register read operations"""
        # Read the interface name
        interface = yield from self.hyp.read_str(arg)
        
        # Only handle eth0 ioctls
        if interface != "eth0":
            return
            
        # Read the esw_reg structure pointer from ifr_data
        esw_reg_ptr = yield from self.hyp.read_ptr(arg + 16)
        
        # Read the register code (offset)
        code = yield from self.hyp.read_int(esw_reg_ptr)
        
        # Decide what value to provide based on the register
        if code == REG_ESW_WT_MAC_AD0:
            # Set bit 0x2 to indicate w_mac_done
            val = 0x2
        elif code == REG_ESW_WT_MAC_ATC:
            val = 0x8234
        elif code == REG_ESW_TABLE_STATUS0:
            # This value needs to meet 0x1 & 0x2
            val = 0x73
        else:
            val = 0x10173
            
        # Log the operation
        self.logger.info(f"RAEth ioctl: reg={self.registers.get(code, hex(code))}, returning val={hex(val)}")
        
        # Write the value back to the esw_reg structure (at offset +4 for val)
        yield from self.hyp.write_int(esw_reg_ptr + 4, val)
        
        # Set the syscall return value to 0 (success)
        syscall.retval = 0
```

### Using Advanced Filtering to Target Specific Code Paths

We can further refine our intervention by combining various filters to precisely target specific code paths:

```python
class AdvancedRAEthPlugin(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.advanced_raeth")
        self.hyp = plugins.hypermem
        
        # Target only table_del's register read operations
        # This uses both command filtering and process name filtering
        self.panda.hsyscall(
            "on_sys_ioctl_enter", 
            comm_filter="mtk7530_switch",  # Process name filter 
            arg_filter=[None, RAETH_ESW_REG_READ, None]  # Argument filter
        )(self.hyp.wrap(self.handle_table_del_ioctl))
        
    def handle_table_del_ioctl(self, cpu, proto, syscall, hook, fd, cmd, arg):
        """
        This function specifically targets the table_del function's ioctl calls
        by checking the register being read
        """
        # Read the interface name
        interface = yield from self.hyp.read_str(arg)
        if interface != "eth0":
            return
            
        # Read the esw_reg structure pointer from ifr_data
        esw_reg_ptr = yield from self.hyp.read_ptr(arg + 16)
        
        # Read the register code (offset)
        code = yield from self.hyp.read_int(esw_reg_ptr)
        
        # Check if this is the specific register read from table_del
        if code == REG_ESW_WT_MAC_AD0:
            self.logger.info("Detected table_del function polling for w_mac_done bit")
            
            # Instead of modifying the value, we can skip the syscall entirely
            # and provide our own return value directly
            syscall.skip_syscall = True
            
            # Write the w_mac_done bit directly to the return value pointer
            # First, get the value pointer from the calling code
            caller_frame_ptr = yield from self.hyp.read_ptr(self.panda.arch.get_reg(cpu, "sp"))
            value_ptr = yield from self.hyp.read_ptr(caller_frame_ptr + 8)  # Assuming x86_64 calling convention
            
            # Set the value with the w_mac_done bit set
            yield from self.hyp.write_int(value_ptr, 0x2)
            
            # Make the ioctl call itself return success
            syscall.retval = 0
            
            self.logger.info("Bypassed ioctl call and directly set w_mac_done bit")
```

### Benefits of Using Hypermem with Syscall Filtering

1. **Precision Targeting**: By using arg_filter and comm_filter, we can precisely target only the specific ioctl calls we need to handle.

2. **Reduced Overhead**: We avoid intercepting irrelevant syscalls, improving performance.

3. **Contextual Awareness**: We can make decisions based on process name, syscall arguments, and other context.

4. **Flexible Intervention**: We can choose to modify arguments, skip syscalls, or change return values as needed.

5. **Clean Memory Access**: Using Hypermem's higher-level API (`read_int`, `write_int`, etc.) is much cleaner than direct memory manipulation.

### Result

By intercepting only the specific IOCTL calls needed and providing appropriate register values, the TP-Link device bootup process continues successfully beyond the hardware check. The filtering capabilities ensure we only intervene where necessary, maintaining performance while still providing the emulation needed for the missing hardware.

This example demonstrates how combining Hypermem with hypersyscalls' filtering capabilities provides a powerful and precise approach to firmware rehosting.

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