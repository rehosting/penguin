# Singularity

Penguin can be built as a singularity container for use in HPC environments where limited permissions are available.

## Building Singularity container
On a machine where you have docker and root, clone this repo and `cd` into it. Then build a docker container
and convert it to singularity with

```sh
./penguin --build-singularity
```

This will produce a singularity image named `penguin.sif`.

Alternatively, you can build the container directly and convert to singularity by
running the following within the root directory of the project.

```sh
# Build container
DOCKER_BUILDKIT=1 docker build -t rehosting/pegnuin .

# Convert to singularity
docker run -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd):/output \
    --privileged  -t \
    --rm quay.io/singularity/docker2singularity:v3.9.0 rehosting/penguin

# Rename to penguin.sif
mv rehosting_penguin*.sif penguin.sif
```

Now copy your `penguin.sif` file to your target machine with singularity.

## Using your Singularity container

Finally, run your container under singularity with a host directory and projects directory
mapped into the container in your home directory. Note the following explanation of the arguments:

* `-e` unsets host environment variables so a host `$TMPDIR` (which isn't mapped) isn't used
* -`c` contains the container filesystem to be isolated from the host (i.e., only explicitly shared directories are shared)
* -`B` binds two directories from the host into the container: the current directory and ./projects. Both
are mapped into the home directory in the container (which is the same as it is on your host).

```sh
mkdir projects
singularity exec -e -c -B $(pwd):$HOME/host,$(pwd)/projects:$HOME/projects,$TMPDIR:/tmp penguin.sif bash
Singularity> penguin init host/fws/my_fw.rootfs.tar.gz
Singularity> penguin run projects/my_fw
```

Alternatively, you can run these commands from your host directly:
```sh
mkdir projects
singularity exec -e -c -B $(pwd):$HOME/host,$(pwd)/projects:$HOME/projects,$TMPDIR:/tmp penguin.sif penguin init host/fws/my_fw.rootfs.tar.gz
singularity exec -e -c -B $(pwd):$HOME/host,$(pwd)/projects:$HOME/projects,$TMPDIR:/tmp penguin.sif penguin run projects/my_fw
```


If the VPN informs you of a network-reachable service, you'll connect to localhost on the specified port.