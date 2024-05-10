# Penguin Plugins
The following penguin plugins are currently supported. Each is documented below.
* `env`
* `health`
* `pseudofiles`
* `shell`
* `coverage`
* `vpn`
* `nmap`
* `zap`


## Env
The `env` plugin dynamically tracks linux environment variables accessed through
`/proc/cmdline` and calls to `getenv`. It also tracks accesses to `/proc/mtd`
as well as `/dev/mtdX` to identify accesses to u-boot environment variables.

If an env value is set to the magic string `DYNVALDYNVALDYNVAL` a dynamic analysis
to detect comparisons between this magic string and any other string will be enabled.
The results of this analysis will be stored in `env_cmp.txt`

In a config file, a user may add key-value pairs into the `env` filed to set new
values into the linux environment. Note that a number of required internal variables
(e.g., `root=/dev/vda`) will added to the system's arguments _after_ any arguments you specify here.

## Health
The `health` plugin tracks the system health over time. `health.csv` tracks counts
of various behaviors of interest over time while `health_final.yaml` just reports
these values at the end of execution.

The plugin also creates `health_procs.txt` as a sorted list of processes run and
`health_procs_with_args.txt` as a sorted list of processes with their arguments.

## Pseudofiles
This plugin tracks accesses and interactions with files in `/dev/` and `/proc/`.
In `pseudofiles_failures.yaml` details of failed interactions are reported.

Users can add pseudofiles and configure models for reads, writes, and IOCTLs on
these files by adding entries into the `pseudofiles` config section.

## Shell
This plugin tracks the behavior of shell scripts, capturing coverage in `shell_cov.csv`, environment variable values in `shell_env.csv` and a combined trace in `shell_cov_trace.csv`.

## Coverage
This plugin tracks the module and offset block level coverage of all binaries
in the system. These results are reported in `coverage.csv`.
The file `coverage_tree.csv` stores this information with parent/child
relationships to visualize as a tree. The file `coverage_transitions.csv`
records all context switches between processes.

## VPN
When running your container with sufficent privileges, this
plugin detects network binds and configures the IGLOO VPN to bridge
network connections to guest services. The details of network-listening guest
services are recorded in `vpn_netbinds.csv` while the details of what
host ports are bridged are recorded in `vpn_bridges.csv`.

For example, if `vpn_bridges.csv` contains:

```
procname,ipvn,domain,guest_ip,guest_port,host_port
lighttpd,ipv4,tcp,127.0.0.1,80,80
lighttpd,ipv4,tcp,192.168.0.1,80,48823
```

This means lighttpd started listeing on port 80 on the loopback interface as well as another IP address.
To talk to the service as if you were connecting via loopback, you'd connect to the relevant `host_port`, here 80.
To talk to the service as if you were connecting via the other IP address, you'd connect to the other `host_port`, here 48823.

Note these are ports within your container, not on your host. You can configure docker to bridge traffic between guest and host ports
or you can connect using command line tools from within your container.

## Nmap
This plugin runs nmap scans on all network-listening services.
It depends on the VPN plugin to establish network connections to guest services.
Logs are written to `nmap_{protocol}_{port}.log`

## ZAP
This plugin runs the [zap web application scanner](https://github.com/zaproxy/) to crawl and interact with guest
web applications listening on TCP port 80. Logs are written to `zap.log` and `zap_tcp_80.log`.
