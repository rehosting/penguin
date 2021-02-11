PANData
====

# Idea
Gray-box fuzzing of whole-system web applications. Start at a given page, queue up crawling of all href/src attributes we see.
While we crawl, analyze how the guest maps our requests into the filesystem. Use ground truth FS knowledge to populate queue
with additional pages to visit.  During crawling, record all forms observed - action, method, parameters and default values.

Once crawl-queue is exhausted, begin fuzzing forms.
For each form we see, mutate each parameter.
Using PANDA's introspection (in particular, `OSI`, `hooks` and `dynamic_symbols`) we drive a state machine
around each fuzzed request we send. This lets us identify precisely when the request is fully decrypted, at which point we begin a detailed analysis of how
the guest responds to the network request.

While processing a request, we analyze all system calls to determine if attacker-controlled POSTdata is passed as a string. In particular, we examine arguments to `execve`. 
We also search for reflected data in responses which may indicate the presense of cross site scripting bugs.

## State 1: Crawling
### 1a: Simple scraping
Load the next page from the queue Identify `SRC`, `HREF` and `form` data to find other
pages to load. Add identified pages to the queue. For forms, generate junk data for each parameter.

### 1b: FS Introspection
When the webserver loads a file - examine other files in that directory and generate appropriate
paths to potentially access them. Add these to the queue.

For example, if a request to `https://server/parent/child.html` triggers an open of `fw_dir/var/www/parent/child.html`, get the list of files in `fw_dir/var/www/parent/`:
for example `child2.html`, `child3.html`.
 Then rewrite each filename into a potentially-correct web-reachable path: `https://server/parent/child2.html`,  `https://server/parent/child3.html`.

![Crawl anddriver state machine](https://github.com/panda-re/pandata/blob/main/docs/crawl_driver.png?raw=true)

## State 2: Fuzzing
We issue a bunch of requests to each form and determine if the webserver launches any child processes (and if they launch children as well).
We analyze all system call string arguments to compare with attacker-controlled data sent into the form.

![Fuzz state machine](https://github.com/panda-re/pandata/blob/main/docs/fuzz.png?raw=true)



# General techniques
## Auth Bypass
Using PANDA, we identify and bypass authentication functions so we can explore
authenticated-only areas of the web application.

This is implemented by a simple configuration powered by PANDA's `dynamic_symbols` plugin.
For each web server we support, we simply provide the library and function names to hook and a desired return value.
If a web server does not use a library function for hooking, the address of a function to bypass must be provided explicitly.
When the guest executes the authentication logic, we immediately return with the specified result.

## Snapshot restore
If the webserver fails to respond to a request (i.e., times out), we reset the guest to a snapshot and try again. If repeating the request still
fails, we revert (again) and indicate the request as fatal.

# Future work
## Collect coverage information of child processes
Identify how mutating form parameters affects the amount of code covered
In particular, look at measuring coverage of CGI-BIN binaries and PHP scripts

## Snapshot-based fuzzing
We identify precisely when a guest has a decrypted buffer of attacker-controlled data.
We could snapshot at this point and mutate the buffer to fuzz.

## SOAP-fuzzing
If we identify WSDLs or soap endpoints, we should use the WSDL to create valid messages and fuzz

## Identify crashes
When child processes die it should be reported

## Result presentation
It's ugly right now.

## Integrations
Perhaps we should export URLs we identify to burp for fuzzing? Or maybe we just do it all on our own.

# Supported webservers
Lighttpd with `mod_auth` (should work as long as it uses `http_auth_basic_check()`)


# PANData?
It's like `POSTDATA`, but with some more PANDA!

Supported Webstacks
====
## Auth hooking
lighttpd: `mod_auth.so`'s `http_auth_basic_check` should return 1
apache2 - ret 1 from `ap_get_basic_auth_components` or `mod_authnz_fcgi`'s `ap_get_basic_auth_pw`  TODO

## SSL Decryption
lighttpd OR apache2 `libssl.so`'s `SSL_read` function places decrypted data in an argumnet buffer


Target firmwares tested
====
## Stride Router
Arm. Lighttpd with cgi-bin executables
Two post-auth command-injection vulnerabilities identified

## Firmadyne IID2: `DIR-300_fw_revb1_212wwb02_ALL_en_20120118.tar.gz`
mipsel php
