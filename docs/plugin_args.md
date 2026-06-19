# Plugin arguments

Plugins that declare an `Args` schema validate their arguments and document them here. Configure them under the top-level `plugins:` section, keyed by the plugin name. This page is generated from the plugins' declared `Args`; run `penguin schema <plugin>` for the same information at the CLI.

> The first-class top-level form (writing `<plugin>:` at the config root instead of under `plugins:`) is **deprecated**: it still loads but logs a warning and may be removed.

**Plugins:** [`db`](#plugin-db-arguments), [`fetch_web`](#plugin-fetch_web-arguments), [`ficd`](#plugin-ficd-arguments), [`kernelversion`](#plugin-kernelversion-arguments), [`kmods`](#plugin-kmods-arguments), [`mount`](#plugin-mount-arguments), [`netbinds`](#plugin-netbinds-arguments), [`nvram2`](#plugin-nvram2-arguments), [`pseudofiles`](#plugin-pseudofiles-arguments), [`qemu_mem`](#plugin-qemu_mem-arguments), [`syscalls_logger`](#plugin-syscalls_logger-arguments), [`verifier`](#plugin-verifier-arguments), [`vpn`](#plugin-vpn-arguments)

# Plugin `db` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`bufsize`|integer|`100000`||Number of events to buffer in memory before flushing to the SQLite database.|

Configure under `plugins:`:
```yaml
plugins:
  db:
    # args...
```

# Plugin `fetch_web` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`fetch_delay`|integer or null|`null`||Seconds to wait before fetching a newly bound web service. Defaults to 20 when unset.|
|`shutdown_after_www`|boolean|`false`||If true, shut down emulation after a successful web fetch.|
|`shutdown_on_failure`|boolean|`false`||If true, shut down emulation if no responsive servers are found.|

Configure under `plugins:`:
```yaml
plugins:
  fetch_web:
    # args...
```

# Plugin `ficd` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`stop_on_if`|boolean|`false`||If true, end analysis when the FICD Ifin (firmware initialization finished) point is reached.|

Configure under `plugins:`:
```yaml
plugins:
  ficd:
    # args...
```

# Plugin `kernelversion` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`sysname`|string or null|`null`||uname sysname field (OS name); leave unset to keep the kernel default.|
|`nodename`|string or null|`null`||uname nodename field (hostname); leave unset to keep the kernel default.|
|`release`|string or null|`null`||uname release field (kernel release string); leave unset to keep the kernel default.|
|`kversion`|string or null|`null`||uname version field (kernel version string); leave unset to keep the kernel default.|
|`machine`|string or null|`null`||uname machine field (hardware/architecture name); leave unset to keep the kernel default.|
|`domainname`|string or null|`null`||uname domainname field (NIS/domain name); leave unset to keep the kernel default.|

Configure under `plugins:`:
```yaml
plugins:
  kernelversion:
    # args...
```

# Plugin `kmods` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`allowlist`|list of string|`[]`||Kernel module names allowed to load (no .ko extension).|
|`denylist`|list of string|`[]`||Kernel module names to explicitly block. Takes precedence over allowlist.|
|`quiet`|boolean|`false`||If true, only errors are logged.|

Configure under `plugins:`:
```yaml
plugins:
  kmods:
    # args...
```

# Plugin `mount` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`fake_mounts`|list of string|`[]`||Mount targets to fake as successful.|
|`all_succeed`|boolean|`false`||If true, fake all mount attempts as successful.|
|`verbose`|boolean|`false`||Enable debug logging.|

Configure under `plugins:`:
```yaml
plugins:
  mount:
    # args...
```

# Plugin `netbinds` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`shutdown_on_www`|boolean|`false`||If true, shut down emulation when a bind occurs on port 80.|
|`debounce_period`|float|`2.0`||Seconds a close is held pending before being treated as a real close. A re-bind within this window is recorded as a flap, not a close.|
|`transient_threshold`|integer|`3`||Number of flaps at which a socket is labelled transient.|

Configure under `plugins:`:
```yaml
plugins:
  netbinds:
    # args...
```

# Plugin `nvram2` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`logging`|boolean|`true`||Enable logging of NVRAM get/set operations to nvram.csv.|
|`persist`|boolean|`false`||Persist NVRAM set values across runs via nvram_state.yaml.|

Configure under `plugins:`:
```yaml
plugins:
  nvram2:
    # args...
```

# Plugin `pseudofiles` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`disable_tracking`|boolean|`false`||If true, do not initialize the pseudofile_tracker plugin alongside pseudofiles.|

Configure under `plugins:`:
```yaml
plugins:
  pseudofiles:
    # args...
```

# Plugin `qemu_mem` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`mmap_alignment`|integer or string or null|`null`||Alignment for mmap allocations within the aperture; page-aligned. Accepts int or size string (e.g. '4K'). Defaults to page size (4096).|
|`mmap_base`|integer or string or null|`null`||Base guest physical address of the mmap aperture; must be page aligned. Accepts int or size string. Defaults to 0xfe000000.|
|`mmap_size`|integer or string or null|`null`||Total size of the mmap aperture; positive and page aligned. Accepts int or size string (e.g. '64M'). Defaults to 16 MiB.|

Configure under `plugins:`:
```yaml
plugins:
  qemu_mem:
    # args...
```

# Plugin `syscalls_logger` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`procs`|list of string or null|`null`||Process names to filter syscall logging to. If unset, all processes are logged.|

Configure under `plugins:`:
```yaml
plugins:
  syscalls_logger:
    # args...
```

# Plugin `verifier` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`conditions`|mapping from string to mapping or null|`null`||Mapping of test-case name to its test definition (each must have a 'type').|
|`continuous_eval`|boolean|`false`||If true, re-evaluate test conditions periodically and end analysis once all pass.|

Configure under `plugins:`:
```yaml
plugins:
  verifier:
    # args...
```

# Plugin `vpn` arguments

|Argument|Type|Default|Required|Description|
|-|-|-|-|-|
|`IGLOO_VPN_PORT_MAPS`|string or null|`null`||Comma-separated guest->host port mapping rules in the form <proto>:<host_port>:<guest_ip>:<guest_port>. Falls back to the IGLOO_VPN_PORT_MAPS environment variable when unset.|
|`log`|boolean|`false`||If true, enable logging of VPN traffic to the output directory.|
|`pcap`|boolean|`false`||If true, enable PCAP capture of VPN traffic.|
|`spoof`|mapping or null|`null`||Source IP spoofing configuration keyed by <proto>:<guest_ip>:<guest_port> with 'source' and 'dev' entries.|

Configure under `plugins:`:
```yaml
plugins:
  vpn:
    # args...
```


<!-- 31 plugin file(s) could not be imported for introspection and were skipped. -->

