PANData
====

```
Lifecycle of a guest web application
Kernel:
Parse packets from NIC, identify userspace FDs to send to

Webserver main:
sock_fd = create_socket(port)->bind(sock_fd)->listen(sock_fd)->new_fd = accept(sock_fd)

Webserver worker (thread):
Validate HTTP request: recv(new_fd). Identify requested file from path, compare to config rules to map to host path and to handle auth requirements. Auth validation.

IF STATIC:
  Read requested file (if allowed), write back to FD with send(new_fd)

IF DYNAMIC:
  Execute binary or interpreter on script. Varies per format (cgi-bin, python, php, etc)
  Input via environment and stdio. Output returned via stdout


```

# Idea
Two-pronged approach to exploring attack surface of a web application.
As we identify new pages/forms/requests to make, add to a queue.
Requests are processed from the queue until none are left.

The queue is initially populated with `index.html`

## Thrust 1: Simple scraping
Load the next page from the queue Identify `SRC`, `HREF` and `form` data to find other
pages to load. Add identified pages to the queue. For forms, generate junk data for each parameter.

## Thrust 2: FS Introspection
When the webserver loads a file - examine other files in that directory and generate appropriate
paths to potentially access them. Add these to the queue.

For example, if a request to `https://server/parent/child.html` triggers an open of `fw_dir/var/www/parent/child.html`, get the list of files in `fw_dir/var/www/parent/`:
for example `child2.html`, `child3.html`.
 Then rewrite each filename into a potentially-correct web-reachable path: `https://server/parent/child2.html`,  `https://server/parent/child3.html`.

 Record and report calls to execve.
 
 (TODO) identify if submitted data is passed as args.

# Auth Bypass
Using PANDA, we identify and bypass authentication functions so we can explore
authenticated-only areas of the web application.

This is implemented by a simple expert-knowledge system. For each web server we support, we encode the library function name for checking auth and desired return value. We dynamically hook this name and set the correct return value.

# CGI-Bin IO
`cgi-bin` scripts are driven by stdin and environment variables and generate data on stdout. Inputs and outputs are printed to the log.

(TODO) Take snapshots before postdata is processed (after relevant `sys_read_return`) and use these for fuzzing cgi-bin programs.

# Future work
* Identify crashes
* Meaningful presentation of results 
* Integrations (export URLs for burp?)

# Supported webservers
* Lighttpd with `mod_auth` (should work as long as it uses `http_auth_basic_check()`)

### PANData?
It's like `POSTDATA`, but with some more PANDA!


### Application Lifecycle - WIP
1. Rehosting script setups on `on_init` function which registers rehosting
hooks
2. Rehosting script initializes `Crawler` object with panda, base URL, mount point, and init function.
3. Rehosting script calls `.crawl()` on Crawler object.


Crawler reverts to www snapshot
Crawler waits for first WWW BB, enables OSI, and calls rehosting script's init fn.
