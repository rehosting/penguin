# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:22.04"
ARG DOWNLOAD_TOKEN="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"
ARG PANDA_VERSION="1.8.8" # XXX UNUSED: we have a hardcoded branch used below in downloader - this has a fix for targetcmp we really want
ARG BUSYBOX_VERSION="0.0.1"
ARG LINUX_VERSION="1.9.29n"
ARG LIBNVRAM_VERSION="0.0.1"
ARG CONSOLE_VERSION="1.0.2"
ARG PENGUIN_PLUGINS_VERSION="1.5.4"
ARG UTILS_VERSION="4"
ARG VPN_VERSION="1.0.5"
ARG HYPERFS_VERSION="0.0.2"

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
    wget \
    xmlstarlet && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /igloo_static \
             /igloo_static/syscalls \
             /panda_plugins \
             /static_deps

COPY ./utils/get_release.sh /get_release.sh

# 1) Get external resources
# Download ZAP into /zap
#RUN mkdir /zap && \
#wget -qO- https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml | \
#    xmlstarlet sel -t -v //url | grep -i Linux | wget -q --content-disposition -i - -O - | \
#    tar zxv -C /zap && \
#	mv /zap/ZAP*/* /zap && \
#	rm -R /zap/ZAP*

# Libguestfs appliance
RUN wget --quiet https://download.libguestfs.org/binaries/appliance/appliance-1.46.0.tar.xz -O /tmp/libguestfs.tar.xz

# 2) Get PANDA resources
# Get panda .deb
ARG PANDA_VERSION
ARG BASE_IMAGE
RUN  wget -O /tmp/pandare.deb https://panda.re/secret/pandare_1.8.1b_2204.deb
    #wget -O /tmp/pandare.deb https://github.com/panda-re/panda/releases/download/v${PANDA_VERSION}/pandare_$(echo "$BASE_IMAGE" | awk -F':' '{print $2}').deb

# Get syscall list from PANDA
RUN for arch in arm mips mips64; do \
    wget -q https://raw.githubusercontent.com/panda-re/panda/dev/panda/plugins/syscalls2/generated-in/linux_${arch}_prototypes.txt -O /igloo_static/syscalls/linux_${arch}_prototypes.txt; \
  done

ARG UTILS_VERSION
RUN wget -qO - https://panda.re/secret/utils${UTILS_VERSION}.tar.gz | \
    tar xzf - -C /static_deps

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
    tar xzf - -C /igloo_static

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
ARG VPN_VERSION
RUN /get_release.sh rehosting vpnguin ${VPN_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static

ARG HYPERFS_VERSION
RUN /get_release.sh rehosting hyperfs ${HYPERFS_VERSION} ${DOWNLOAD_TOKEN} | \
  tar xzf - -C / && \
  mv /result/* /igloo_static/utils.bin/ && \
  rmdir /result

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
RUN git clone --depth 1 --no-checkout https://github.com/qemu/qemu.git /src && \
  cd /src && \
  git fetch --depth 1 origin tag v7.2.0 && \
  git checkout v7.2.0
RUN mkdir /src/build && cd /src/build && ../configure --disable-user --disable-system --enable-tools \
    --disable-capstone --disable-guest-agent && \
  make -j$(nproc)

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
RUN git clone --depth 1 https://github.com/AndrewFasano/nmap.git /src
# We want to install into /build/nmap
RUN cd /src && ./configure --prefix=/build/nmap && make -j$(nproc) && make install


### MAIN CONTAINER ###
FROM $BASE_IMAGE as penguin
# Environment setup
ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""

# Add rootshell helper command
RUN echo "#!/bin/sh\ntelnet localhost 4321" > /usr/local/bin/rootshell && chmod +x /usr/local/bin/rootshell

COPY --from=downloader /tmp/pandare.deb /tmp/

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

# Install apt dependencies - largely for binwalk, some for penguin
RUN apt-get update && apt-get install -y \
    fakechroot \
    fakeroot \
    firefox \
    genext2fs \
    git \
    graphviz \
    graphviz-dev \
    libarchive13 \
    libcapstone-dev \
    libgcc-s1 \
    libguestfs-tools \
    liblinear4 \
    liblua5.3-0\
    libpcap0.8 \
    libpcre3 \
    libssh2-1 \
    libssl3 \
    libstdc++6 \
    libxml2 \
    lua-lpeg \
    openjdk-11-jdk \
    python3 \
    python3-guestfs \
    python3-lxml \
    python3-venv \
    telnet \
    vim \
    wget \
    zlib1g && \
    apt install -yy -f /tmp/pandare.deb && \
    rm -rf /var/lib/apt/lists/* /tmp/pandare.deb

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
      pyelftools \
      python-owasp-zap-v2.4 \
      python_hosts \
      pyyaml \
      pyvis \
      jsonschema \
      setuptools

# ZAP setup
#COPY --from=downloader /zap /zap
#RUN /zap/zap.sh -cmd -silent -addonupdate -addoninstallall && \
#    cp /tmp/ZAP/plugin/*.zap /zapplugin/ || :
#
# Install JAVA for ZAP
#ENV JAVA_HOME=/opt/java/openjdk
#COPY --from=eclipse-temurin:11 $JAVA_HOME $JAVA_HOME
#ENV PATH="${JAVA_HOME}/bin:${PATH}"

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

# Copy nmap build into /usr/local/bin
COPY --from=nmap_builder /build/nmap /usr/local/

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
