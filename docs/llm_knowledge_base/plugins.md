# Penguin Plugins
The following penguin plugins are currently supported. Each is documented below.
* [Coverage](#coverage): Track block-level coverage of binaries
* [Env](#env): Track usage of boot arguments, environment variable accesses, and environment variable comparisons.
* [Health](#health): Track system health metrics including processes run.
* [Interfaces](#interfaces): Track network interfaces referenced
* [Lifeguard](#lifeguard): Track and block signals
* [Mounts](#mounts): Track attempts to mount file systems
* [NVRAM2](#nvram2): Tracks accesses to NVRAM
* [Netbinds](#netbinds): Track network listening guest processes
* [Nmap](#nmap): Network scanning for guest applications that bind to TCP ports
* [Pseudofiles](#pseudofiles): Model and monitor interactions to devices in `/dev` `/proc` and `/sys`
* [Shell](#shell): Track behavior of shell scripts including lines executed
* [VPNguin](#vpnguin): Bridge network connections to networked guest processes
* [Zap](#zap): **Currently disabled** Network scanning of guest web applications

## Coverage
This plugin tracks the module and offset block level coverage of all binaries
in the system. These results are reported in `coverage.csv`.
The file `coverage_tree.csv` stores this information with parent/child
relationships to visualize as a tree. The file `coverage_transitions.csv`
records all context switches between processes.

## Env
The `env` plugin dynamically tracks linux environment variables accessed through
`/proc/cmdline` and calls to `getenv`. It also tracks accesses to `/proc/mtd`
as well as `/dev/mtdX` to identify accesses to u-boot environment variables.

If an env value is set to the magic string `DYNVALDYNVALDYNVAL` a dynamic analysis
to detect comparisons between this magic string and any other string will be enabled.
The results of this analysis will be stored in `env_cmp_py.txt`. On the next run, set
the environment variable to the first of these concrete values.

In a config file, a user may add key-value pairs into the `env` filed to set new
values into the linux environment. Note that a number of required internal variables
(e.g., `root=/dev/vda`) will added to the system's arguments _after_ any arguments you specify here.

## Health
The `health` plugin tracks the system health over time. `health.csv` tracks counts
of various behaviors of interest over time while `health_final.yaml` just reports
these values at the end of execution.

The plugin also creates `health_procs.txt` as a sorted list of processes run and
`health_procs_with_args.txt` as a sorted list of processes with their arguments.

## Interfaces
Track network interfaces referenced in executed commands. Results are
reported in `iface.log`.

## Lifeguard
Track and block signals sent between processes. Results stored in `lifeguard.csv`

## Mounts
Track which file systems are mounted (or attempted to be mounted) at which paths.
Results stored in `mounts.csv`. Note this plugin will track some penguin-internal
initialization logic with mounts in the `/igloo` directory.

## NVRAM2
This plugin tracks accesses to keys and values stored in NVRAM. Results
are stored in `nvram.csv`

## Netbinds
This plugin detects and logs network binds by guest processes. The results
are logged into `netbinds.csv` and include a `time` column indicating how
many seconds after boot until the bind occurred.

## Nmap
This plugin runs nmap scans on all network-listening services.
It depends on the VPN plugin to establish network connections to guest services.
Logs are written to `nmap_{protocol}_{port}.log`

## Pseudofiles
This plugin tracks accesses and interactions with files in `/dev/` and `/proc/`.
In `pseudofiles_failures.yaml` details of failed interactions are reported.

Users can add pseudofiles and configure models for reads, writes, and IOCTLs on
these files by adding entries into the `pseudofiles` config section.

## Shell
This plugin tracks the behavior of shell scripts, capturing coverage in `shell_cov.csv`, environment variable values in `shell_env.csv` and a combined trace in `shell_cov_trace.csv`.

## VPNguin
This plugin detects network binds and configures a custom VPN to bridge
network connections to guest services. The mappings between guest
network services and what port the VPN exposes them on are listed
in `vpn_bridges.csv` For example, if the file contains:

```
procname,ipvn,domain,guest_ip,guest_port,host_port
lighttpd,ipv4,tcp,127.0.0.1,80,80
lighttpd,ipv4,tcp,192.168.0.1,80,48823
```

This means `lighttpd` started listening on port 80 on the loopback interface as well as another IP address.
To talk to the service as if you were connecting via loopback, you'd connect to the relevant `host_port`, here 80.
To talk to the service as if you were connecting via the other IP address, you'd connect to the other `host_port`, here 48823.
Note these are ports within your container, not on your host, so you must connect to the appropriate IP address to reach
the container.

## ZAP
**Currently disabled**
This plugin runs the [zap web application scanner](https://github.com/zaproxy/) to crawl and interact with guest
web applications listening on TCP port 80. Logs are written to `zap.log` and `zap_tcp_80.log`.
