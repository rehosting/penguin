# Example Rehosting Workflow

This guide walks through the process of rehosting the
[StrideLinx](https://www.automationdirect.com/stride/stridelinx/vpn-router)
router. 

After installing `penguin` and `fw2tar` as described in the README,
download a copy of the target firmware from
[https://ftp.automationdirect.com/pub/stride_firmware_5.3.174.zip](https://ftp.automationdirect.com/pub/stride_firmware_5.3.174.zip).

Rename `stride_firmware_5.3.174.zip` to `stride.bin` for convenience.

## Convert firmware blob to root filesystem archive

To begin, we'll convert the firmware blob into a root filesystem archive with `fw2tar`.
This utility handles unpacking files from a wide variety of storage formats while preserving
the extracted file's permissions and symlinks. To learn more about the utility or try non-standard options, you can run `fw2tar --help`. To enable all extractors you can run
`fw2tar --extractors binwalk,unblob yourfw.bin`. For our use case, we'll just run the utility on the firmware we downloaded with no
special options:

```sh
fw2tar stride.bin
```

After a few seconds, you should see a message saying the best filesystem was created as `stride.rootfs.tar.gz`.

You can use the command `tar tvf stride.rootfs.tar.gz` to view the contents of that archive:
```sh
drwxr-xr-x root/root         0 2018-12-31 19:00 ./
drwxrwxrwx root/root         0 2018-12-31 19:00 ./alternate/
drwxrwxrwx root/root         0 2018-12-31 19:00 ./bin/
lrwxrwxrwx root/root         0 2018-12-31 19:00 ./bin/ash -> busybox
-rwxr-xr-x root/root    504332 2018-12-31 19:00 ./bin/busybox
```

If `fw2tar` had failed to extract the filesystem, you could have tried creating or finding
your own extraction utilities and then generated a rootfs archive of that extraction (with 
correct permissions and a root of `./`). But it works most of the time, so that's not likely
something you'll ever need to do.

## Initialize penguin project from root filesystem archive
Now that we have our filesystem, we can begin the rehosting process by initializing a
new penguin project for it.

```sh
penguin init stride.rootfs.tar.gz
```

This command will create a new project in `./projects/stride` which will contain a
`config.yaml` which precisely specifies how this firmware is to be rehosted. Note that the 
paths logged by Penguin may include `/host_...` these paths are mapped between the container
and your host machine but are based on defaults or the paths you've specified on the command line. For example, the command above will report the project is created at `/host_projects/stride` which corresponds to `./projects/stride`.

When a project is initialized, Penguin uses a **static analysis** of the filesystem to
generate an initial **configuration** specifying the rehosting process for this firmware.The static analysis results are stored in `./projects/stride/base/` and the configuration is
stored at `./projects/stride/config.yaml`.

### Static analysis outputs

Notable files within the `./projects/stride/base` directory include:

* `fs.tar.gz`: A copy of the input filesystem archive
* `env.yaml`: A list of statically-identified environment variables you may later need to set. Of particular note is the `igloo_init` section which lists potential *init* programs.
* `pseudofiles.yaml`: A list of statically-identified `/dev` and `/proc` files that you may later need to model in the rehosting process.
* `initial_config.yaml`: A backup of the auto-generated configuration
* `nvram.csv`: A list of all statically-identified NVRAM keys and values along with the source (a source of `defaults` indicate generic values while other sources are specific to the system under analysis).
* `library_symbols.csv`: A list of all exported library functions along with their names and offsets

### Configuration

The format of autogenerated configuration `./projects/stride/config.yaml` is documented in
[docs/schema_doc.md](docs/schema_doc.md), but the following sections and fields are worth
highlighting:

`core`: This section indicates project-wide settings such as the architecture. Within this section there are 3 notable options:
* `force_www`: if enabled, the rehosting will agressively attempt to start standard webservers
* `strace`: if enabled, every process in the system will have its system calls traced and logged to the output.
* `show_output`: if this is set to true, console output will be shown on standard out of penguin. Otherwise console output will be logged into the results directory at `console.log`

`static_files`: This section specifies static modifications to make to the root filesystem
before boot. Of particular note is the `/igloo/init` script that you can edit to control what
happens in the system before the specified *init* program runs (i.e., that you set in `env.igloo_init`).

`env`: This section stores the kernel boot arguments passed to the system. Of particular note is the `igloo_init` field which is used by penguin to select the *init* program to run during boot. While a default value is typically set here, you may wish to change this to another
value shown in the `env.yaml` file within the base directory.

`pseudofiles`: This section specifies pseudofiles in `/dev`, `/sys`, and `/proc` to model in
the rehosting. Note that you may see yaml variables used where a dictionary is first defined 
as `&id001` and then later referenced as `*id001`.

`nvram`: This is a set of keys and corresponding values to initialize the system's non-volatile RAM (NVRAM) with. The sources for these values will be listed in `base/nvram.csv`.

`netdevs`: This is a list of network device names to configure within the guest


## Run your configuration and collect output:

Run the auto-generated configuration:
```
penguin run projects/stride/config.yaml
```

This rehosting will run until you terminate the command or the system shuts down. It will not
log the firmware's console output by default, but it will inform you whenever new network
services start in the guest and how to reach them. You should expect to see output like:

```
20:25:34 penguin INFO Running config /host_projects/stride/config.yaml
20:25:34 penguin INFO Saving results to /host_projects/stride/results/0
20:25:34 penguin INFO Note messages referencing /host paths reflect automatically-mapped shared directories based on your command line arguments
20:25:37 penguin.gen_image INFO Generating new image from config...
20:25:38 penguin.gen_image WARNING Deleting existing file /etc/hosts to replace it
copying from tar archive /host_projects/stride/qcows/fs_out.tar
20:25:42 penguin.runner INFO Logging console output to /host_projects/stride/results/0/console.log
PANDA[core]:os_familyno=2 bits=32 os_details=generic
PANDA[syscalls2]:using profile for linux arm
PANDA[osi_linux]:W> failed to read task.switch_task_hook_addr
PANDA[osi_linux]:W> kernelinfo bytes [20-23] not read
20:25:42 penguin.runner INFO Loading plugins
20:25:42 plugins.core INFO Root shell will be available at: 192.168.0.2:4321
20:25:42 plugins.core INFO Connect with: telnet 192.168.0.2 4321
20:25:50 penguin.runner INFO Launching rehosting
20:27:49 plugins.VPN INFO            inetd binds tcp 0.0.0.0:7        reach it at 192.168.0.2:7
20:27:49 plugins.VPN INFO            inetd binds udp 0.0.0.0:7        reach it at 192.168.0.2:54933
20:27:49 plugins.VPN INFO     7 is already in use
20:27:49 plugins.VPN INFO            inetd binds tcp 0.0.0.0:9        reach it at 192.168.0.2:9
20:27:49 plugins.VPN INFO            inetd binds udp 0.0.0.0:9        reach it at 192.168.0.2:38301
20:27:49 plugins.VPN INFO     9 is already in use
20:27:49 plugins.VPN INFO            inetd binds tcp 0.0.0.0:23       reach it at 192.168.0.2:23
20:28:18 plugins.VPN INFO            snmpd binds udp 0.0.0.0:161      reach it at 192.168.0.2:161
```

### Dynamic analysis results
By default the `penguin run` command will store dynamic analysis results in
`<project directory>/results/<auto-incrementing number>` so the first run will generate output
in `./projects/stride/results/0`. Launch a second terminal to examine results while your 
rehosting continues to running.

* Examine the console output by looking at `./projects/stride/results/0/console.log`. To view the output as it is updated you can run `tail -f ./projects/stride/results/0/console.log`.
* Examine dynamically-traced shell script execution at `./projects/stride/results/0/shell_cov_trace.csv` and note that concrete values for each variable are included in the trace.

Note that some files will not be created or populated until the emulation terminates. To learn
more about the outputs created in this directory, check out [docs/plugins.md](docs/plugins.md).

### Root shell

After examining these files, use your second terminal to connect to the root shell with `telnet` at the IP address and port that was specified when you launched the `penguin run` 
command. After launching `telnet` you may need to push enter to see a prompt

```sh
$ telnet 192.168.1.2 4321
Trying 192.168.1.2...
Connected to 192.168.1.2.
Escape character is '^]'.

~ #
```

This is a penguin-provided root shell into the running firmware. From here you can run
commands inside the guest. Note that the root shell will prioritize running commands from a 
penguin-provided busybox binary over guest binaries. This ensures that standard commands are
available regardless of what the firmware provides. But if you'd like to run the guest's 
version of a specific command such as `httpd` you should either run it from the absolute path
in the guest filesystem or run `unalias httpd` first.

While you're connected to the guest shell, try running commands like `ps` and `whoami` to
take a look around the system you're connected to. To disconnect you should press `ctrl + ]`
and then `ctrl + d`.

### Network connectivity with VPN

After allowing your rehosting to run for a few minutes, you should see output about
various processes binding to network IPs and ports. For each bind, another IP and port
will be logged indicating how you can connect to that service from your host machine:

```
20:27:49 plugins.VPN INFO            inetd binds tcp 0.0.0.0:23       reach it at 192.168.0.2:23
20:28:18 plugins.VPN INFO            snmpd binds udp 0.0.0.0:161      reach it at 192.168.0.2:161
```

When you send traffic to the specified IP address (i.e., 192.168.0.2), it will be bridged into
the running firmware as if you connected to the bound IP listed.

### Shut down rehosting
In the terminal where you ran `penguin run` press `ctrl + c` to gracefully shut down the
rehosting. The shutdown may take up to 30s as dynamic analysis data must be written to
disk at this time.

## Update configuration

At this point you have run an auto-generated rehosting for the stride firmware. But you may
have noticed that the VPN logs didn't indicate a webserver was reachable on port 80. Let's
go through the *iterative rehosting process* to try finding and fixing errors related to this.

In our initial results directory we can examine `env_missing.yaml` and see that two unset 
environment variables were referenced: `sxid` and `sxserno`. If we examine `console.log` we
see a number of errors about `No configuration for 'SXID'` so we'll start by trying to fix 
this.

### Finding SXID

We could now manually analyze binaries and scripts in the filesystem to understand what the 
`sxid` variable is used for and what it controls. But we'll instead use a dynamic analysis.

Edit `projects/stride/config.yaml` and within the `env` section add the `sxid` keys as shown:

```yaml
env:
  igloo_init: /sbin/init
  sxid: DYNVALDYNVALDYNVAL
```

Here we're setting `sxid` to a magic value that we'll dynamically detect comparisons to. We can re-run our rehosting for a few minutes. Note that this time it will log to
`projects/stride/results/1`.

```
penguin run projects/stride/config.yaml
```

While it runs examine the console.log file and wait until you see message saying "sxid not 
found." At that point (or after a few minutes) press `ctrl + c` to stop the run.

Examine the result file `env_cmp.txt` to view strings that were compared against the magic value:

```sh
$ cat projects/stride/results/1/env_cmp.txt
0150_5MS-MDM-1
0150S_5MS-5SC
H
```

Either of the first two values will be valid, so update your configuration's env section to be:

```yaml
env:
  igloo_init: /sbin/init
  sxid: 0150_5MS-MDM-1
```

### New errors with SXID
Now run your updated configuration, this time it will log to `projects/stride/results/2`

```sh
penguin run projects/stride/config.yaml
```

After a few minutes (or when you see an error about "unable to open DSA"), press `ctrl + c` to terminate the run.

Compare the output from your inintial run (0) versus the that run (2) using a diffing tool:

```sh
git diff --no-index --word-diff projects/stride/results/0/console.log projects/stride/results/2/console.log
```

Scroll past the lines that only have different timestamps and you should see that other messages are changing. For example "SkippingNo configuration for SXID '0190_???'" is gone
and new errors like "Dsa: Failed to open /dev/dsa: No such file or directory" are present.

To learn more about what's happening with that device, we can examine
`projects/stride/results/2/pseudofiles_failures.yaml` which shows that the system tried
to open that device many times while our rehosting was running.

### Adding `/dev/dsa`

We can add the device `/dev/dsa` into our rehosting by updating the `pseudofiles` section of 
our configuration. At this point we don't know what the system was trying to do with the
device, so we'll just add it and not yet configure antyhing else

Update your configuration's pseudofiles section to look like the following. You can delete
the default pseudofile models that were already present or leave them alone.

```yaml
pseudofiles:
  /dev/dsa: {}
```

Now run your rehosting again, this time it will log to `projects/stride/results/3`:

```sh
penguin run projects/stride/config.yaml
```

After a few minures (or when you see an error about "ioctl()-error -1"), press `ctrl + c` to terminate the run and examine `projects/stride/results/3/pseudofiles_failures.yaml`. Note that you can even examine the pseudofile_failures file while the system is running.

### IOCTL modeling

Now that we've added the `/dev/dsa` device, we don't see any `open` failures and we should
see that some `ioctl` errors are reported instead for ioctl number 1074029569 (0x40046401).

```yaml
/dev/dsa:
  ioctl:
    1074029569:
      count: 40
```

We can update our `/dev/dsa` pseudofile to simply return 0 or "success" on this ioctl:

```yaml
pseudofiles:
  /dev/dsa:
    ioctl:
      1074029569:
        model: return_const
        val: 0
```

and run again. If we repeat this process (results directory 4), we'll see other IOCTLs are
issued on the device such as 3221513218 (0xc0046402). We could keep adding models for each
observed ioctl, or we can take a heavy-handed approach and say any ioctl issued on `/dev/dsa` 
should return 0.

```yaml
pseudofiles:
  /dev/dsa:
    ioctl:
      "*":
        model: return_const
        val: 0
```

### Webserver starts

With the config changes described above, a `lighttpd` webserver should start after a minute.

In total the changes we made to the auto-generated configuration are adding `sxid` into the `env` section and `/dev/dsa` into `pseudofiles:

```yaml
env:
  igloo_init: /sbin/init
  sxid: 0150_5MS-MDM-1
pseudofiles:
  /dev/dsa:
    ioctl:
      "*":
        model: return_const
        val: 0
```

With these changes the VPN should log that a lighttpd server is listening:
```
21:14:41 plugins.VPN INFO         lighttpd binds tcp [::]:80          reach it at 192.168.0.2:80
21:14:41 plugins.VPN INFO         lighttpd binds tcp [::]:443         reach it at 192.168.0.2:443
```

If you are running penguin on your local machine, you can try using a web browser to reach http://192.168.0.2 and log in with `admin` and `admin`. If penguin is running on a remote 
machine you can run the following command to get a long response:

```sh
curl -u admin:admin 192.168.0.2/cgi-bin/menubar.cgi
```

If you'd like to connect to the rehosting from a remote machine you can use ssh port
forwarding. For example, to make localhost:9000 on your desktop connect to `192.168.0.2`
port 80 on the machine where you're running penguin, you could run:

```sh
user@desktop$ ssh -L 9000:192.168.0.2:80 user@your_penguin_dev_machine -N
```
