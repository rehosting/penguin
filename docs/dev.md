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
dependency locally, build the artifacts, and place them into a directory called
`local_packages`. When build artifacts are present in this directory, they will
be installed and replace the standard versions at container build.

The following filenames are expected in the `local_packages` directory:

* busybox-latest.tar.gz
* hyperfs.tar.gz
* kernels-latest.tar.gz
* libnvram-latest.tar.gz
* pandare_22.04.deb
* penguin_plugins.tar.gz
* vpn.tar.gz

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
$ mkdir ../penguin/local_packages
$ cp kernels-latest.tar.gz ../penguin/local_packages/
```

Now when you build your container, it will use this local version and allow you to use
or test your changes without needing to tag a new release of the dependency on GitHub.

```sh
./penguin --build ...
```

When you have finished prototyping with your local dependency, you should delete your `local_packages`
directory so subsequent builds of `penguin` use standard versions of dependencies.