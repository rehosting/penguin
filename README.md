PANData
====

# Idea
Two-pronged approach to exploring attack surface of a web application.
As we identify new pages/forms/requests to make, add to a queue.
Requests are processed from the queue until none are left.

The queue is initially populated with `index.html`

## Thurst 1: Simple scraping
Load the next page from the queue Identify `SRC`, `HREF` and `form` data to find other
pages to load. Add identified pages to the queue. For forms, generate junk data for each parameter.

## Thrust 2: FS Introspection
When the webserver loads a file - examine other files in that directory and generate approperiate
paths to potentially access them. Add these to the queue.

For example, if a request to `https://server/parent/child.html` triggers an open of `fw_dir/var/www/parent/child.html`, get the list of files in `fw_dir/var/www/parent/`:
for example `child2.html`, `child3.html`.
 Then rewrite each filename into a potentially-correct web-reachable path: `https://server/parent/child2.html`,  `https://server/parent/child3.html`.

 Record and report calls to execve.
 
 (TODO) identify if submitted data is passed as args.

# Auth Bypass
Using PANDA, we dynamically identify andy bypass authentication functions so we can explore
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
