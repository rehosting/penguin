# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:22.04"
ARG DOWNLOAD_TOKEN="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"
ARG PANDA_VERSION="1.8.26"
ARG BUSYBOX_VERSION="0.0.1"
ARG LINUX_VERSION="2.2.9"
ARG LIBNVRAM_VERSION="0.0.5"
ARG CONSOLE_VERSION="1.0.3"
ARG PENGUIN_PLUGINS_VERSION="1.5.8"
ARG VPN_VERSION="1.0.10"
ARG HYPERFS_VERSION="0.0.15"
ARG GLOW_VERSION="1.5.1"
ARG LTRACE_PROTOTYPES_VERSION="0.7.91"
ARG LTRACE_PROTOTYPES_HASH="9db3bdee7cf3e11c87d8cc7673d4d25b"

FROM rust as vhost_builder
RUN git clone -q https://github.com/rust-vmm/vhost-device/ /root/vhost-device
RUN cd /root/vhost-device/ && \
  RUSTFLAGS="-C target-feature=+crt-static" PATH="/root/.cargo/bin:${PATH}" cargo build --release --bin vhost-device-vsock --target x86_64-unknown-linux-gnu

### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing
FROM $BASE_IMAGE as downloader
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    curl \
    jq \
    less \
    wget \
    bzip2 \
    xmlstarlet && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /igloo_static \
             /igloo_static/syscalls \
             /panda_plugins

COPY ./utils/get_release.sh /get_release.sh

# 1) Get external resources
# Download ZAP into /zap
#RUN mkdir /zap && \
#wget -qO- https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml | \
#    xmlstarlet sel -t -v //url | grep -i Linux | wget -q --content-disposition -i - -O - | \
#    tar zxv -C /zap && \
#	mv /zap/ZAP*/* /zap && \
#	rm -R /zap/ZAP*

# 2) Get PANDA resources
# Get panda .deb
ARG PANDA_VERSION
ARG BASE_IMAGE
RUN wget -O /tmp/pandare.deb https://github.com/panda-re/panda/releases/download/v${PANDA_VERSION}/pandare_$(echo "$BASE_IMAGE" | awk -F':' '{print $2}').deb

# Get syscall list from PANDA
RUN for arch in arm arm64 mips mips64; do \
    wget -q https://raw.githubusercontent.com/panda-re/panda/dev/panda/plugins/syscalls2/generated-in/linux_${arch}_prototypes.txt -O /igloo_static/syscalls/linux_${arch}_prototypes.txt; \
  done

ARG GLOW_VERSION
RUN wget -qO /tmp/glow.deb https://github.com/charmbracelet/glow/releases/download/v${GLOW_VERSION}/glow_${GLOW_VERSION}_amd64.deb

# 3) Get penguin resources
# Download kernels from CI. Populate /igloo_static/kernels
ARG DOWNLOAD_TOKEN
ARG LINUX_VERSION
RUN /get_release.sh rehosting linux_builder ${LINUX_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static

# Populate /igloo_static/utils.bin/utils/busybox.*
ARG BUSYBOX_VERSION
RUN /get_release.sh rehosting busybox ${BUSYBOX_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static/ && \
    mv /igloo_static/build/ /igloo_static/utils.bin && \
    for file in /igloo_static/utils.bin/busybox.*-linux*; do mv "$file" "${file%-linux-*}"; done && \
    mv /igloo_static/utils.bin/busybox.arm /igloo_static/utils.bin/busybox.armel

# Get panda provided console from CI. Populate /igloo_static/console
ARG CONSOLE_VERSION
RUN /get_release.sh rehosting console ${CONSOLE_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static


# Download libnvram from CI. Populate /igloo_static/libnvram
ARG LIBNVRAM_VERSION
RUN /get_release.sh rehosting libnvram ${LIBNVRAM_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static --exclude 'libnvram.so.*'

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
ARG VPN_VERSION
RUN /get_release.sh rehosting vpnguin ${VPN_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static

ARG HYPERFS_VERSION
RUN /get_release.sh rehosting hyperfs ${HYPERFS_VERSION} ${DOWNLOAD_TOKEN} | \
  tar xzf - -C / && \
  mv /result/utils/* /igloo_static/utils.bin/ && \
  mv /result/dylibs /igloo_static/dylibs && \
  rm -rf /result && \
  for f in  /igloo_static/utils.bin/*.arm64; do mv -- "$f" "${f%.arm64}.aarch64"; done

# Download prototype files for ltrace.
#
# Download the tarball from Fedora, because ltrace.org doesn't store old
# versions and we want this container to build even when dependencies are
# outdated.
ARG LTRACE_PROTOTYPES_VERSION
ARG LTRACE_PROTOTYPES_HASH
RUN wget -qO- https://src.fedoraproject.org/repo/pkgs/ltrace/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2/${LTRACE_PROTOTYPES_HASH}/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2 \
  | tar xjf - -C / && \
  mv /ltrace-*/etc /tmp/ltrace && \
  rm -rf /ltrace-*

# Download custom panda plugins built from CI. Populate /panda_plugins
ARG PENGUIN_PLUGINS_VERSION
RUN /get_release.sh rehosting penguin_plugins ${PENGUIN_PLUGINS_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /panda_plugins

#### CROSS BUILDER: Build send_hypercall ###
FROM ghcr.io/panda-re/embedded-toolchains:latest as cross_builder
COPY ./utils/send_hypercall.c /
RUN cd / && \
  mkdir out && \
  wget -q https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h && \
  mipseb-linux-musl-gcc -mips32r3 -s -static send_hypercall.c -o out/send_hypercall.mipseb && \
  mips64eb-linux-musl-gcc -mips64r2 -s -static send_hypercall.c -o out/send_hypercall.mips64eb  && \
  mipsel-linux-musl-gcc -mips32r3 -s -static send_hypercall.c -o out/send_hypercall.mipsel && \
  arm-linux-musleabi-gcc -s -static send_hypercall.c -o out/send_hypercall.armel && \
  aarch64-linux-musl-gcc -s -static send_hypercall.c -o out/send_hypercall.aarch64

#### QEMU BUILDER: Build qemu-img ####
FROM $BASE_IMAGE as qemu_builder
ENV DEBIAN_FRONTEND=noninteractive
# Enable source repos
RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update && apt-get build-dep -y qemu-utils qemu && \
    apt-get install -q -y --no-install-recommends ninja-build git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --no-checkout https://github.com/qemu/qemu.git /src && \
  cd /src && \
  git fetch --depth 1 origin tag v7.2.0 && \
  git checkout v7.2.0
RUN mkdir /src/build && cd /src/build && ../configure \
    --without-default-features \
    --disable-system \
    --disable-user \
    --enable-tools \
    && make -j$(nproc)

#### NMAP BUILDER: Build nmap ####
FROM $BASE_IMAGE as nmap_builder
ENV DEBIAN_FRONTEND=noninteractive
# Enable source repos
RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update && apt-get install -q -y \
      git \
      python3-setuptools \
    && apt-get build-dep -y nmap \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/rehosting/nmap.git /src
# We want to install into /build/nmap
RUN cd /src && ./configure --prefix=/build/nmap && make -j$(nproc) && make install

### Python Builder: Build all wheel files necessary###
FROM $BASE_IMAGE as python_builder
ARG PANDA_VERSION

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN apt-get update && apt-get install -y python3-pip git
RUN --mount=type=cache,target=/root/.cache/pip \
      pip wheel --no-cache-dir --wheel-dir /app/wheels \
      angr \
      beautifulsoup4 \
      coloredlogs \
      git+https://github.com/AndrewFasano/angr-targets.git@af_fixes \
      html5lib \
      pandare==${PANDA_VERSION} \
      ipdb \
      lief  \
      lxml \
      lz4 \
      pydantic \
      pyelftools \
      pyyaml \
      pyvis \
      jsonschema \
      click \
      art \
      setuptools


### MAIN CONTAINER ###
FROM $BASE_IMAGE as penguin
# Environment setup
ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""

# Add rootshell helper command
RUN echo "#!/bin/sh\ntelnet localhost 4321" > /usr/local/bin/rootshell && chmod +x /usr/local/bin/rootshell

COPY --from=downloader /tmp/pandare.deb /tmp/
COPY --from=downloader /tmp/glow.deb /tmp/

# We need pycparser>=2.21 for angr. If we try this later with the other pip commands,
# we'll fail because we get a distutils distribution of pycparser 2.19 that we can't
# uninstall somewhere in setting up other dependencies.

RUN apt-get update && \
    apt-get --no-install-recommends install -y python3-pip && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cache/pip \
      pip install --upgrade \
        pip \
        "pycparser>=2.21"

# Install apt dependencies - largely for binwalk, some for penguin
RUN apt-get update && apt-get install -y \
    fakeroot \
    genext2fs \
    graphviz \
    graphviz-dev \
    libarchive13 \
    libcapstone-dev \
    libgcc-s1 \
    liblinear4 \
    liblua5.3-0\
    libpcap0.8 \
    libpcre3 \
    libssh2-1 \
    libssl3 \
    libstdc++6 \
    libxml2 \
    lua-lpeg \
    python3 \
    python3-lxml \
    python3-venv \
    sudo \
    telnet \
    vim \
    wget \
    clang-11 \
    lld-11 \
    zlib1g && \
    apt install -yy -f /tmp/pandare.deb -f /tmp/glow.deb && \
    rm -rf /var/lib/apt/lists/* /tmp/*.deb

# If we want to run in a venv, we can use this. System site packages means
# we can still access the apt-installed python packages (e.g. guestfs) in our venv
#RUN python3 -m venv --system-site-packages /venv
#ENV PATH="/venv/bin:$PATH"
# install prebuilt python packages
COPY --from=python_builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# ZAP setup
#COPY --from=downloader /zap /zap
#RUN /zap/zap.sh -cmd -silent -addonupdate -addoninstallall && \
#    cp /tmp/ZAP/plugin/*.zap /zapplugin/ || :
#
# Install JAVA for ZAP
#ENV JAVA_HOME=/opt/java/openjdk
#COPY --from=eclipse-temurin:11 $JAVA_HOME $JAVA_HOME
#ENV PATH="${JAVA_HOME}/bin:${PATH}"


# qemu-img
COPY --from=qemu_builder /src/build/qemu-img /usr/local/bin/qemu-img

# VPN, libnvram, kernels, console
COPY --from=downloader /igloo_static/ /igloo_static/

# Copy plugins into panda install. We want /panda_plugins/arch/foo to go into /usr/local/lib/panda/foo
COPY --from=downloader /panda_plugins/arm/ /usr/local/lib/panda/arm/
COPY --from=downloader /panda_plugins/aarch64/ /usr/local/lib/panda/aarch64/
COPY --from=downloader /panda_plugins/mips/ /usr/local/lib/panda/mips/
COPY --from=downloader /panda_plugins/mipsel/ /usr/local/lib/panda/mipsel/
COPY --from=downloader /panda_plugins/mips64/ /usr/local/lib/panda/mips64/

# Copy nmap build into /usr/local/bin
COPY --from=nmap_builder /build/nmap /usr/local/

COPY --from=downloader /tmp/ltrace /igloo_static/ltrace

# Copy utils.source (scripts) and utils.bin (binaries) from host
# Files are named util.[arch] or util.all
COPY --from=cross_builder /out/* /igloo_static/utils.bin
COPY utils/* /igloo_static/utils.source/
COPY --from=vhost_builder /root/vhost-device/target/x86_64-unknown-linux-gnu/release/vhost-device-vsock /usr/local/bin/vhost-device-vsock

# Copy wrapper script into container so we can copy out - note we don't put it on guest path
COPY ./penguin /usr/local/src/penguin_wrapper
# And add install helpers which generate shell commands to install it on host
COPY ./src/resources/banner.sh ./src/resources/penguin_install ./src/resources/penguin_install.local /usr/local/bin/
# Warn on interactive shell sessions and provide instructions for install. Suppress with `docker run ... -e NOBANNER=1 ... bash`
RUN echo '[ ! -z "$TERM" ] && [ -z "$NOBANNER" ] && /usr/local/bin/banner.sh' >> /etc/bash.bashrc

# Install docs
COPY ./docs /docs
COPY ./README.md /docs/README.md

# Now copy in our module and install it
# penguin is editable so we can mount local copy for dev
# setuptools is workaround for igloo #131
COPY ./src /pkg
RUN --mount=type=cache,target=/root/.cache/pip \
      pip install -e /pkg && \
      pip install setuptools==67.7.2

# Copy pyplugins into our the pandata directory. We might mount
# this from the host during development. In the long term we'll
# merge these into the main penguin module
COPY ./pyplugins/ /pandata

# Default command: echo install instructions
CMD ["/usr/local/bin/banner.sh"]


# To install local builds of penguin deps, build and copy
# into this directory and then uncomment the relevant lines

#COPY penguin_plugins.tar.gz /tmp
#RUN mkdir -p /tmp/plug && \
#    tar xzf /tmp/penguin_plugins.tar.gz -C /tmp/plug && \
#    mv /tmp/plug/arm/* /usr/local/lib/panda/arm && \
#    mv /tmp/plug/mips/* /usr/local/lib/panda/mips && \
#    mv /tmp/plug/mipsel/* /usr/local/lib/panda/mipsel && \
#    mv /tmp/plug/mips64/* /usr/local/lib/panda/mips64

#COPY kernels-latest.tar.gz /tmp
#RUN rm -rf /igloo_static/kernels && \
#    tar xvf /tmp/kernels-latest.tar.gz -C /igloo_static/

#COPY pandare_22.04.deb /tmp
#RUN dpkg -i /tmp/pandare_22.04.deb

#COPY libnvram-latest.tar.gz /tmp
#RUN rm -rf /igloo_static/libnvram && \
#    tar xvf /tmp/libnvram-latest.tar.gz -C /igloo_static/

#COPY busybox-latest.tar.gz /tmp
#RUN rm /igloo_static/utils.bin/busybox.* && \
#  tar xzf /tmp/busybox-latest.tar.gz -C /igloo_static/ && \
#  mv /igloo_static/build/* /igloo_static/utils.bin/ && \
#  for file in /igloo_static/utils.bin/busybox.*-linux*; do mv "$file" "${file%-linux-*}"; done && \
#  mv /igloo_static/utils.bin/busybox.arm /igloo_static/utils.bin/busybox.armel
