# Penguin Development Guide

## Installation and `./penguin` usage

After cloning this repository you can use the local `./penguin` script
to build your container and to run Penguin.

To build the container you can run:
```sh
./penguin --build
```

You can view all the wrapper arguments that may assist with development by running
```sh
./penguin --wrapper-help
```

The penguin wrapper arguments go before penguin commands (e.g. `run`, `init`), but
can be combined, for example the following command will rebuild your container
and then run the configuration in `projects/myfw/config.yaml`

```sh
./penguin --build run projects/myfw
```

Note that the standard `penguin` wrapper command that we recommend users install
supports these development options, so you can use these wrapper flags even if
the `penguin` command is installed for a user or system.

## Private dependencies

Members of penguin development team who wish to use our private nmap fork may build it
by first launching ssh-agent and then rebuilding their penguin container. This fork is not
distributed externally (as binaries or source) due to licensing restrictions, but the changes
are minor.

```sh
eval $(ssh-agent)
ssh-agent add ~/.ssh/id_rsa
penguin --build
```

## Dependency Development

If you wish to prototype changes to a Penguin dependency, you can develop the
dependency locally, build the artifacts, and then modify the Penguin Dockerfile
to use the local artifacts instead of pulling them from GitHub.

For example, the following workflow shows how to test modifications to the Penguin
Linux kernel.

# Example: Local kernel development

First clone and update the Linux kernel repo

```sh
$ git clone --recurse-submodules  git@github.com:rehosting/linux_builder.git && cd linux_builder
$ # Edit some files in linux/4.10 (not shown)
```

Then build the artifacts - note you don't have to build all kernels if you just wish to test
with a single architecture.

```sh
$ # Build kernels-latest.tar.gz, for example with just 4.10 and armel
$ ./build.sh --versions 4.10 --targets armel
```

Next, copy the artifacts into your Penguin source directory.

```sh
$ cp kernels-latest.tar.gz ../penguin/
```

Finally, you'll update your Penguin Dockerfile to pull this dependency locally.
Find the commented code at the end of the Dockerfile that copies the relevant artifact
from your host and installs it into the container. Uncomment that code.

```Dockerfile
COPY kernels-latest.tar.gz /tmp
RUN rm -rf /igloo_static/kernels && \
    tar xvf /tmp/kernels-latest.tar.gz -C /igloo_static/
```

Now when you build your container, it will use this local version and allow you to use
or test your changes without needing to tag a new release of the dependency on GitHub.

```sh
./penguin --build ...
```
