# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:22.04"
ARG GENEXT2FS_VERSION="9bc57e232e8bb7a0e5c8ccf503b57b3b702b973a"
ARG PANDA_VERSION="1.8.8"
ARG BUSYBOX_VERSION="25c906fe05766f7fc4765f4e6e719b717cc2d9b7"
ARG LINUX_VERSION="1.9.23"
ARG LIBNVRAM_VERSION="1ff1c9b83ff7833e386fc83d8289e230f03a0e35"
ARG CONSOLE_VERSION="389e179dde938633ff6a44144fe1e03570497479"
ARG PENGUIN_PLUGINS_VERSION="1.5.3"
ARG UTILS_VERSION="4"

### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing
FROM $BASE_IMAGE as download_base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    xmlstarlet wget ca-certificates && \
    rm -rf /var/lib/apt/lists/* 

### DEB DOWNLOADER: get genext2fs and pandare debs ###
FROM download_base as deb_downloader
ARG BASE_IMAGE
ARG GENEXT2FS_VERSION
ARG PANDA_VERSION
RUN wget -O /tmp/genext2fs.deb https://github.com/panda-re/genext2fs/releases/download/release_${GENEXT2FS_VERSION}/genext2fs.deb && \
    wget -O /tmp/pandare.deb https://github.com/panda-re/panda/releases/download/v${PANDA_VERSION}/pandare_$(echo "$BASE_IMAGE" | awk -F':' '{print $2}').deb
    # wget -O /tmp/pandare.deb https://panda.re/secret/pandare_1.8.1b_2204.deb

### DOWNLOADER: get zap, libguestfs, busybox, libnvram, console, vpn, kernels, and penguin plugins ###
FROM download_base as downloader
ARG BUSYBOX_VERSION
ARG LINUX_VERSION
ARG LIBNVRAM_VERSION
ARG CONSOLE_VERSION
ARG PENGUIN_PLUGINS_VERSION
ARG UTILS_VERSION
# Download ZAP into /zap
RUN mkdir /zap && \
wget -qO- https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml | \
    xmlstarlet sel -t -v //url | grep -i Linux | wget -q --content-disposition -i - -O - | \
    tar zxv -C /zap && \
	mv /zap/ZAP*/* /zap && \
	rm -R /zap/ZAP*

# Libguestfs appliance
RUN wget --quiet https://download.libguestfs.org/binaries/appliance/appliance-1.46.0.tar.xz -O /tmp/libguestfs.tar.xz

# Download busybox from CI. Populate /igloo_static/utils.bin/utils/busybox.*
RUN mkdir /igloo_static && \
  wget -qO - https://github.com/panda-re/busybox/releases/download/release_${BUSYBOX_VERSION}/busybox-latest.tar.gz | \
  tar xzf - -C /igloo_static/ && \
  mv /igloo_static/build/ /igloo_static/utils.bin && \
  for file in /igloo_static/utils.bin/busybox.*-linux*; do mv "$file" "${file%-linux-*}"; done && \
  mv /igloo_static/utils.bin/busybox.arm /igloo_static/utils.bin/busybox.armel

# Download kernels from CI. Populate /igloo_static/kernels
RUN wget -qO - https://github.com/panda-re/linux_builder/releases/download/v${LINUX_VERSION}/kernels-latest.tar.gz | \
      tar xzf - -C /igloo_static

# Download libnvram from CI. Populate /igloo_static/libnvram
RUN wget -qO - https://github.com/panda-re/libnvram/releases/download/release_${LIBNVRAM_VERSION}/libnvram-latest.tar.gz | \
  tar xzf - -C /igloo_static

# Download  console from CI. Populate /igloo_static/console
RUN wget -qO - https://github.com/panda-re/console/releases/download/release_${CONSOLE_VERSION}/console-latest.tar.gz | \
  tar xzf - -C /igloo_static && \
  mv /igloo_static/build /igloo_static/console && \
  mv /igloo_static/console/console-arm-linux-musleabi /igloo_static/console/console.armel && \
  mv /igloo_static/console/console-mipsel-linux-musl /igloo_static/console/console.mipsel && \
  mv /igloo_static/console/console-mipseb-linux-musl /igloo_static/console/console.mipseb && \
  mv /igloo_static/console/console-mips64eb-linux-musl /igloo_static/console/console.mips64eb

# Download syscalls lists
RUN mkdir /igloo_static/syscalls && \
  cd /igloo_static/syscalls && \
  for arch in arm mips mips64; do \
  wget -q https://raw.githubusercontent.com/panda-re/panda/dev/panda/plugins/syscalls2/generated-in/linux_${arch}_prototypes.txt; \
  done

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
# XXX this dependency should be versioned!
RUN wget -qO - https://panda.re/igloo/vpn.tar.gz | \
  tar xzf - -C /

# Download custom panda plugins built from CI. Populate /panda_plugins
RUN mkdir /panda_plugins && \
  wget -qO - https://panda.re/secret/penguin_plugins_v${PENGUIN_PLUGINS_VERSION}.tar.gz | \
  tar xzf - -C /panda_plugins

RUN mkdir /static_deps && \
  wget -qO - https://panda.re/secret/utils${UTILS_VERSION}.tar.gz | \
  tar xzf - -C /static_deps

# Download firmadyne's libnvram and place in /igloo_static/firmadyne_libnvram. For armel, mipsel, and mipseb
RUN mkdir /igloo_static/firmadyne_libnvram && \
  wget -q https://github.com/firmadyne/libnvram/releases/download/v1.0/libnvram.so.armel -O /igloo_static/firmadyne_libnvram/libnvram.so.armel && \
  wget -q https://github.com/firmadyne/libnvram/releases/download/v1.0/libnvram.so.mipsel -O /igloo_static/firmadyne_libnvram/libnvram.so.mipsel && \
  wget -q https://github.com/firmadyne/libnvram/releases/download/v1.0/libnvram.so.mipseb -O /igloo_static/firmadyne_libnvram/libnvram.so.mipseb

# Download FirmAE's libnvram and place in /igloo_static/firmae_libnvram. For armel, mipsel, and mipseb
RUN mkdir /igloo_static/firmae_libnvram && \
  wget -q https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.armel -O /igloo_static/firmae_libnvram/libnvram.so.armel && \
  wget -q https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipseb -O /igloo_static/firmae_libnvram/libnvram.so.mipseb && \
  wget -q https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipsel -O /igloo_static/firmae_libnvram/libnvram.so.mipsel && \
  wget -q https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.armel -O /igloo_static/firmae_libnvram/libnvram_ioctl.so.armel && \
  wget -q https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipseb -O /igloo_static/firmae_libnvram/libnvram_ioctl.so.mipseb && \
  wget -q https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipsel -O /igloo_static/firmae_libnvram/libnvram_ioctl.so.mipsel


#### CROSS BUILDER: Build send_hypercall ###
FROM ghcr.io/panda-re/embedded-toolchains:latest as cross_builder
COPY ./utils/send_hypercall.c /
RUN cd / && \
  mkdir out && \
  wget -q https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h && \
  mipseb-linux-musl-gcc -mips32r3 -s -static send_hypercall.c -o out/send_hypercall.mipseb && \
  mipsel-linux-musl-gcc -mips32r3 -s -static send_hypercall.c -o out/send_hypercall.mipsel && \
  arm-linux-musleabi-gcc -s -static send_hypercall.c -o out/send_hypercall.armel

#### QEMU BUILDER: Build qemu-img ####
FROM $BASE_IMAGE as qemu_builder
ENV DEBIAN_FRONTEND=noninteractive
# Enable source repos
RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update && apt-get build-dep -y qemu-utils qemu && \
    apt-get install -q -y --no-install-recommends ninja-build git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/panda-re/qemu.git /src
RUN mkdir /src/build && cd /src/build && ../configure --disable-user --disable-system --enable-tools \
    --disable-capstone --disable-guest-agent && \
  make -j$(nproc)

### MAIN CONTAINER ###
FROM $BASE_IMAGE as penguin
# Environment setup
ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""

# Add rootshell helper command
RUN echo "#!/bin/sh\ntelnet localhost 4321" > /usr/local/bin/rootshell && chmod +x /usr/local/bin/rootshell

COPY --from=deb_downloader /tmp/pandare.deb /tmp/genext2fs.deb /tmp/

# We need pycparser>=2.21 for angr. If we try this later with the other pip commands,
# we'll fail because we get a distutils distribution of pycparser 2.19 that we can't
# uninstall somewhere in setting up other dependencies.

RUN apt-get update && \
    apt-get install -y python3-pip && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cache/pip \
      pip install --upgrade \
        pip \
        "pycparser>=2.21"

# Install apt dependencies - largely for binwalk, some for pandata
RUN apt-get update && apt-get install -y \
    fakechroot \
    fakeroot \
    firefox \
    git \
    graphviz \
    graphviz-dev \
    libarchive13 \
    libguestfs-tools \
    libxml2 \
    nmap \
    openjdk-11-jdk \
    python3 \
    python3-guestfs \
    python3-lxml \
    python3-venv \
    telnet \
    vim \
    wget \
    libcapstone-dev && \
    apt install -yy -f /tmp/pandare.deb /tmp/genext2fs.deb && \
    rm /tmp/pandare.deb /tmp/genext2fs.deb &&  \
    rm -rf /var/lib/apt/lists/*

# If we want to run in a venv, we can use this. System site packages means
# we can still access the apt-installed python packages (e.g. guestfs) in our venv
#RUN python3 -m venv --system-site-packages /venv
#ENV PATH="/venv/bin:$PATH"

      #http://panda.re/secret/pandare-0.1.2.0.tar.gz
RUN --mount=type=cache,target=/root/.cache/pip pip install \
      angr \
      beautifulsoup4 \
      coloredlogs \
      git+https://github.com/AndrewFasano/angr-targets.git@af_fixes \
      html5lib \
      https://panda.re/secret/pandare-0.1.2.0-py3-none-any.whl \
      ipdb \
      lief  \
      lxml \
      lz4 \
      matplotlib \
      pandas \
      pyelftools \
      pygraphviz \
      python-owasp-zap-v2.4 \
      python_hosts \
      pyyaml \
      pyvis \
      jsonschema \
      setuptools \
      twisted

# ZAP setup
COPY --from=downloader /zap /zap
RUN /zap/zap.sh -cmd -silent -addonupdate -addoninstallall && \
    cp /tmp/ZAP/plugin/*.zap /zapplugin/ || :

# Install JAVA for ZAP
ENV JAVA_HOME=/opt/java/openjdk
COPY --from=eclipse-temurin:11 $JAVA_HOME $JAVA_HOME
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Libguestfs setup
COPY --from=downloader /tmp/libguestfs.tar.xz /tmp/libguestfs.tar.xz
RUN tar xf /tmp/libguestfs.tar.xz -C /usr/local/
ENV LIBGUESTFS_PATH=/usr/local/appliance

# qemu-img
COPY --from=qemu_builder /src/build/qemu-img /usr/local/bin/qemu-img

# VPN, libnvram, kernels, console
COPY --from=downloader /igloo_static/ /igloo_static/

# Copy plugins into panda install. We want /panda_plugins/arch/foo to go into /usr/local/lib/panda/foo
COPY --from=downloader /panda_plugins/arm/ /usr/local/lib/panda/arm/
COPY --from=downloader /panda_plugins/mips/ /usr/local/lib/panda/mips/
COPY --from=downloader /panda_plugins/mipsel/ /usr/local/lib/panda/mipsel/
COPY --from=downloader /panda_plugins/mips64/ /usr/local/lib/panda/mips64/

# Copy utils.source (scripts) and utils.bin (binaries) from host
# Files are named util.[arch] or util.all
COPY --from=downloader /static_deps/utils/* /igloo_static/utils.bin
COPY --from=cross_builder /out/* /igloo_static/utils.bin
COPY utils/* /igloo_static/utils.source/

#COPY fws/kernels-latest.tar.gz /tmp
#RUN rm -rf /igloo_static/kernels && \
#    tar xvf /tmp/kernels-latest.tar.gz -C /igloo_static/
#
#COPY fws/libnvram-latest.tar.gz /tmp
#RUN rm -rf /igloo_static/libnvram && \
#    tar xvf /tmp/libnvram-latest.tar.gz -C /igloo_static/

WORKDIR /penguin

# Now copy in our module and install it
# penguin is editable so we can mount local copy for dev
# setuptools is workaround for igloo #131
COPY ./penguin /pkg
RUN --mount=type=cache,target=/root/.cache/pip \
      pip install -e /pkg && \
      pip install setuptools==67.7.2

# Copy pyplugins into our the pandata directory. We might mount
# this from the host during development. In the long term we'll
# merge these into the main penguin module
COPY ./pyplugins/ /pandata