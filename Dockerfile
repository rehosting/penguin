# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:22.04"
ARG DOWNLOAD_TOKEN="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"
ARG PANDA_VERSION="1.8.54"
ARG BUSYBOX_VERSION="0.0.8"
ARG LINUX_VERSION="2.4.12"
ARG LIBNVRAM_VERSION="0.0.15"
ARG CONSOLE_VERSION="1.0.5"
ARG PENGUIN_PLUGINS_VERSION="1.5.15"
ARG VPN_VERSION="1.0.18"
ARG HYPERFS_VERSION="0.0.37"
ARG GUESTHOPPER_VERSION="1.0.4"
ARG GLOW_VERSION="1.5.1"
ARG GUM_VERSION="0.14.5"
ARG LTRACE_PROTOTYPES_VERSION="0.7.91"
ARG LTRACE_PROTOTYPES_HASH="9db3bdee7cf3e11c87d8cc7673d4d25b"
ARG MUSL_VERSION="1.2.5"
ARG VHOST_DEVICE_VERSION="vhost-device-vsock-v0.2.0"

FROM rust as vhost_builder
RUN git clone --depth 1 -q https://github.com/rust-vmm/vhost-device/ /root/vhost-device
ARG VHOST_DEVICE_VERSION
RUN cd /root/vhost-device/ && \
  git fetch --depth 1 origin tag $VHOST_DEVICE_VERSION && \
  git checkout $VHOST_DEVICE_VERSION && \
  RUSTFLAGS="-C target-feature=+crt-static" PATH="/root/.cargo/bin:${PATH}" cargo build --release --bin vhost-device-vsock --target x86_64-unknown-linux-gnu

### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing
FROM $BASE_IMAGE as downloader
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    bzip2 \
    ca-certificates \
    curl \
    jq \
    less \
    wget \
    make \
    xmlstarlet && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /igloo_static \
             /igloo_static/syscalls \
             /panda_plugins

COPY ./get_release.sh /get_release.sh

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
RUN wget -O /tmp/pandare.deb https://github.com/panda-re/panda/releases/download/v${PANDA_VERSION}/pandare_$(. /etc/os-release ; echo $VERSION_ID).deb

# Get syscall list from PANDA
RUN for arch in arm arm64 mips mips64 x64; do \
    wget -q https://raw.githubusercontent.com/panda-re/panda/dev/panda/plugins/syscalls2/generated-in/linux_${arch}_prototypes.txt -O /igloo_static/syscalls/linux_${arch}_prototypes.txt; \
  done

ARG GLOW_VERSION
RUN wget -qO /tmp/glow.deb https://github.com/charmbracelet/glow/releases/download/v${GLOW_VERSION}/glow_${GLOW_VERSION}_amd64.deb

ARG GUM_VERSION
RUN wget -qO /tmp/gum.deb https://github.com/charmbracelet/gum/releases/download/v${GUM_VERSION}/gum_${GUM_VERSION}_amd64.deb

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
    mv /igloo_static/build/* /igloo_static/

# Get panda provided console from CI. Populate /igloo_static/console
ARG CONSOLE_VERSION
RUN /get_release.sh rehosting console ${CONSOLE_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static


# Download libnvram. Populate /igloo_static/libnvram.
ARG LIBNVRAM_VERSION
RUN wget -qO- https://github.com/rehosting/libnvram/archive/refs/tags/v${LIBNVRAM_VERSION}.tar.gz | \
    tar xzf - -C /igloo_static && \
    mv /igloo_static/libnvram-${LIBNVRAM_VERSION} /igloo_static/libnvram

# Build musl headers for each arch
ARG MUSL_VERSION
RUN wget -qO- https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz | \
    tar xzf - && \
    for arch in arm aarch64 mips mips64 mipsn32 x86_64 i386; do \
        make -C musl-* \
            ARCH=$arch \
            DESTDIR=/ \
            prefix=/igloo_static/musl-headers/$arch \
            install-headers; \
    done && \
    rm -rf musl-*

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
ARG VPN_VERSION
RUN /get_release.sh rehosting vpnguin ${VPN_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static

ARG HYPERFS_VERSION
RUN /get_release.sh rehosting hyperfs ${HYPERFS_VERSION} ${DOWNLOAD_TOKEN} | \
  tar xzf - -C / && \
  cp -r /result/utils/* /igloo_static/ && \
  mv /result/dylibs /igloo_static/dylibs && \
  rm -rf /result

# Download guesthopper from CI. Populate /igloo_static/guesthopper
ARG GUESTHOPPER_VERSION
RUN /get_release.sh rehosting guesthopper ${GUESTHOPPER_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /igloo_static

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

# Add libnvram ltrace prototype file
COPY ./src/resources/ltrace_nvram.conf /tmp/ltrace/lib_inject.so.conf

# Download custom panda plugins built from CI. Populate /panda_plugins
ARG PENGUIN_PLUGINS_VERSION
RUN /get_release.sh rehosting penguin_plugins ${PENGUIN_PLUGINS_VERSION} ${DOWNLOAD_TOKEN} | \
    tar xzf - -C /panda_plugins

# Build capstone v5 libraries for panda callstack_instr to improve arch support
FROM $BASE_IMAGE as capstone_builder
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update && apt-get build-dep -y libcapstone-dev && \
    apt-get install -q -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
RUN cd /tmp && \
    git clone https://github.com/capstone-engine/capstone/ -b v5 && \
    cd capstone/ && ./make.sh && make install && \
    rm -rf /tmp/capstone

#### CROSS BUILDER: Build send_hypercall ###
FROM ghcr.io/rehosting/embedded-toolchains:latest as cross_builder
COPY ./guest-utils/native/send_hypercall.c /
RUN cd / && \
  mkdir -p out/mipseb out/mips64eb out/mipsel out/mips64el  out/armel out/aarch64 out/x86_64 && \
  wget -q https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h && \
  mipseb-linux-musl-gcc -mips32r3 -s -static send_hypercall.c -o out/mipseb/send_hypercall && \
  mips64eb-linux-musl-gcc -mips64r2 -s -static send_hypercall.c -o out/mips64eb/send_hypercall  && \
  mips64el-linux-musl-gcc -mips64r2 -s -static send_hypercall.c -o out/mips64el/send_hypercall  && \
  mipsel-linux-musl-gcc -mips32r3 -s -static send_hypercall.c -o out/mipsel/send_hypercall && \
  arm-linux-musleabi-gcc -s -static send_hypercall.c -o out/armel/send_hypercall && \
  aarch64-linux-musl-gcc -s -static send_hypercall.c -o out/aarch64/send_hypercall && \
  x86_64-linux-musl-gcc -s -static send_hypercall.c -o out/x86_64/send_hypercall

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
ARG SSH

RUN apt-get update && apt-get install -q -y \
    git \
    openssh-client \
    python3-setuptools

# OPTIONALLY build and install custom nmap at /build/nmap. Only if SSH keys available and can clone
# Failure is allowed and non-fatal.
# If you have access run the following to build your container:
# eval `ssh-agent -s`; ssh-add ~/.ssh/id_rsa; ./penguin --build
RUN --mount=type=ssh \
    mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts && \
    git clone git@github.com:rehosting/nmap.git /src && \
    sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list && \
    apt-get update && apt-get build-dep -y nmap && \
    rm -rf /var/lib/apt/lists/* && \
    cd /src && ./configure --prefix=/build/nmap && make -j$(nproc) && \
    make install && \
    mkdir -p /build/nmap/etc/nmap && \
    touch /build/nmap/etc/nmap/.custom \
    || mkdir -p /build/nmap

# Support buidling from source with local_packages. Make sure to
# package from within nmap with `git clean -fx; tar cvzf nmap.tar.gz .`
COPY ./local_package[s] /tmp/local_packages
RUN if [ -f /tmp/local_packages/nmap.tar.gz ]; then \
    rm -rf /src /build/nmap && \
    mkdir /src && \
    tar xzf /tmp/local_packages/nmap.tar.gz -C /src && \
    cd /src && ./configure --prefix=/build/nmap && make -j$(nproc) && \
    make install && \
    mkdir -p /build/nmap/etc/nmap && \
    touch /build/nmap/etc/nmap/.custom /build/nmap/etc/nmap/.custom_local; \
    fi

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
      python-Levenshtein \
      lief  \
      lxml \
      lz4 \
      openai \
      pydantic \
      pyelftools \
      pyyaml \
      pyvis \
      jsonschema \
      click \
      art \
      setuptools \
      sqlalchemy \
      yamlcore \
      junit-xml


FROM python_builder as version_generator
ARG OVERRIDE_VERSION=""
COPY .git /app/.git
RUN if [ ! -z "${OVERRIDE_VERSION}" ]; then \
        echo ${OVERRIDE_VERSION} > /app/version.txt; \
        echo "Pretending version is ${OVERRIDE_VERSION}"; \
    else \
        python3 -m pip install setuptools_scm; \
        echo -n "v" >> /app/version.txt; \
        python3 -m setuptools_scm -r /app/ >> /app/version.txt; \
        echo "Generating version from git"; \
    fi;


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
COPY --from=downloader /tmp/gum.deb /tmp/
COPY --from=capstone_builder /usr/lib/libcapstone* /usr/lib/

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
    nmap \
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
    apt install -yy -f /tmp/pandare.deb -f /tmp/glow.deb -f /tmp/gum.deb && \
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
COPY --from=downloader /panda_plugins/mips64el/ /usr/local/lib/panda/mips64el/
COPY --from=downloader /panda_plugins/x86_64/ /usr/local/lib/panda/x86_64/

# Copy nmap build into /usr/local/bin
COPY --from=nmap_builder /build/nmap /usr/local/

COPY --from=downloader /tmp/ltrace /igloo_static/ltrace

# Copy source and binaries from host
COPY --from=cross_builder /out /igloo_static/
COPY guest-utils /igloo_static/guest-utils
COPY --from=vhost_builder /root/vhost-device/target/x86_64-unknown-linux-gnu/release/vhost-device-vsock /usr/local/bin/vhost-device-vsock

# Generate syscall table
COPY ./pyplugins/build_syscall_info_table.py /pandata/build_syscall_info_table.py
RUN python3 /pandata/build_syscall_info_table.py

# Copy wrapper script into container so we can copy out - note we don't put it on guest path
COPY ./penguin /usr/local/src/penguin_wrapper
# And add install helpers which generate shell commands to install it on host
COPY ./src/resources/banner.sh ./src/resources/penguin_install ./src/resources/penguin_install.local /usr/local/bin/
# Warn on interactive shell sessions and provide instructions for install. Suppress with `docker run ... -e NOBANNER=1 ... bash`
RUN echo '[ ! -z "$TERM" ] && [ -z "$NOBANNER" ] && /usr/local/bin/banner.sh' >> /etc/bash.bashrc

# Install docs
COPY ./docs /docs
COPY ./README.md /docs/README.md

# Add DB module
COPY ./db /db
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -e /db

# Now copy in our module and install it
# penguin is editable so we can mount local copy for dev
COPY --from=version_generator /app/version.txt /pkg/penguin/version.txt
COPY ./src /pkg
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -e /pkg

# Copy pyplugins into our the pandata directory. We might mount
# this from the host during development. In the long term we'll
# merge these into the main penguin module
COPY ./pyplugins/ /pandata

# Copy schema doc into LLM docs as is
COPY ./docs/schema_doc.md /docs/llm_knowledge_base

# Default command: echo install instructions
CMD ["/usr/local/bin/banner.sh"]


# If we have dependencies in ./local_packages, we'll copy these in at build-time
# and replace the previously-installed version.

# Supported packages filesnames are listed in docs/dev.md

# The [s] allows the copy from local_packages to fail if the directory is missing
COPY ./local_package[s] /tmp/local_packages

RUN if [ -d /tmp/local_packages ]; then \
        if [ -f /tmp/local_packages/console.tar.gz ]; then \
            tar xvf /tmp/local_packages/console.tar.gz -C /igloo_static/; \
        fi; \
        if [ -f /tmp/local_packages/penguin_plugins.tar.gz ]; then \
            mkdir -p /tmp/plug && \
            tar xzf /tmp/local_packages/penguin_plugins.tar.gz -C /tmp/plug && \
            mv /tmp/plug/arm/* /usr/local/lib/panda/arm && \
            mv /tmp/plug/aarch64/* /usr/local/lib/panda/aarch64 && \
            mv /tmp/plug/mips/* /usr/local/lib/panda/mips && \
            mv /tmp/plug/mipsel/* /usr/local/lib/panda/mipsel && \
            mv /tmp/plug/mips64/* /usr/local/lib/panda/mips64 && \
            mv /tmp/plug/mips64el/* /usr/local/lib/panda/mips64el && \
            mv /tmp/plug/x86_64/* /usr/local/lib/panda/x86_64; \
        fi; \
        if [ -f /tmp/local_packages/kernels-latest.tar.gz ]; then \
            rm -rf /igloo_static/kernels && \
            tar xvf /tmp/local_packages/kernels-latest.tar.gz -C /igloo_static/; \
        fi; \
        if [ -f /tmp/local_packages/pandare_22.04.deb ]; then \
            dpkg -i /tmp/local_packages/pandare_22.04.deb; \
        fi; \
        if [ -f /tmp/local_packages/vpn.tar.gz ]; then \
            tar xzf /tmp/local_packages/vpn.tar.gz -C /igloo_static; \
        fi; \
        if [ -f /tmp/local_packages/busybox-latest.tar.gz ]; then \
            tar xvf /tmp/local_packages/busybox-latest.tar.gz -C /igloo_static/;  \
        fi; \
        if [ -f /tmp/local_packages/hyperfs.tar.gz ]; then \
            tar xzf /tmp/local_packages/hyperfs.tar.gz -C / && \
            cp -rv /result/utils/* /igloo_static/ && \
            mv /result/dylibs /igloo_static/dylibs && \
            rm -rf /result; \
        fi; \
        if [ -f /tmp/local_packages/libnvram-latest.tar.gz ]; then \
            rm -rf /igloo_static/libnvram; \
            tar xzf /tmp/local_packages/libnvram-latest.tar.gz -C /igloo_static; \
        fi; \
        if [ -f /tmp/local_packages/pandare-*.whl ]; then \
            pip install /tmp/local_packages/pandare-*.whl; \
        fi; \
    fi
RUN mkdir /igloo_static/utils.source && \
    for file in /igloo_static/guest-utils/scripts/*; do \
        ln -s "$file" /igloo_static/utils.source/"$(basename "$file")".all; \
    done
RUN  cd /igloo_static && mv arm64/* aarch64/ && rm -rf arm64 && mkdir -p utils.bin && \
    for arch in "aarch64" "armel" "mipsel" "mips64eb" "mips64el" "mipseb" "x86_64"; do \
        mkdir -p /igloo_static/vpn /igloo_static/console; \
        for file in /igloo_static/"$arch"/* ; do \
            if [ $(basename "$file") = *"vpn"* ]; then \
                ln -s "$file" /igloo_static/vpn/vpn."$arch"; \
            elif [ $(basename "$file") = *"console"* ]; then \
                ln -s "$file" /igloo_static/console/console."$arch"; \
            else \
                ln -s "$file" /igloo_static/utils.bin/"$(basename "$file")"."$arch"; \
            fi; \
        done \
    done
RUN date +%s%N > /igloo_static/container_timestamp.txt
