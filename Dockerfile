# versions of the various dependencies.
ARG REGISTRY="docker.io"
ARG BASE_IMAGE="${REGISTRY}/ubuntu:22.04"
ARG VPN_VERSION="1.0.25"
ARG BUSYBOX_VERSION="0.0.15"
ARG LINUX_VERSION="3.4.0-beta"
ARG IGLOO_DRIVER_VERSION="0.0.3"
ARG LIBNVRAM_VERSION="0.0.22"
ARG CONSOLE_VERSION="1.0.7"
ARG GUESTHOPPER_VERSION="1.0.17"
ARG HYPERFS_VERSION="0.0.42"
ARG GLOW_VERSION="1.5.1"
ARG GUM_VERSION="0.14.5"
ARG LTRACE_PROTOTYPES_VERSION="0.7.91"
ARG LTRACE_PROTOTYPES_HASH="9db3bdee7cf3e11c87d8cc7673d4d25b"
ARG MUSL_VERSION="1.2.5"
ARG VHOST_DEVICE_VERSION="vhost-device-vsock-v0.2.0"
ARG FW2TAR_TAG="v2.0.6"
ARG PANDA_VERSION="pandav0.0.47"
ARG PANDANG_VERSION="0.0.32"
ARG RIPGREP_VERSION="14.1.1"

FROM ${REGISTRY}/rust:1.86 AS rust_builder
RUN git clone --depth 1 -q https://github.com/rust-vmm/vhost-device/ /root/vhost-device
ARG VHOST_DEVICE_VERSION
ENV PATH="/root/.cargo/bin:$PATH"
ENV CARGO_INSTALL_ROOT="/usr/local" 

RUN apt-get update && apt-get install -y -q build-essential libfontconfig1-dev liblzma-dev

RUN cargo install binwalk --target x86_64-unknown-linux-gnu --locked

ARG FW2TAR_TAG
RUN cargo install --target x86_64-unknown-linux-gnu \
    --tag ${FW2TAR_TAG} \
    --git https://github.com/rehosting/fw2tar.git

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cd /root/vhost-device/ && \
  git fetch --depth 1 origin tag $VHOST_DEVICE_VERSION && \
  git checkout $VHOST_DEVICE_VERSION && \
   cargo build --release --bin vhost-device-vsock --target x86_64-unknown-linux-gnu

### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing
FROM $BASE_IMAGE AS downloader
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
    mkdir -p /igloo_static

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
ARG PANDANG_VERSION
# RUN wget -O /tmp/pandare.deb https://github.com/panda-re/panda/releases/download/v${PANDA_VERSION}/pandare_$(. /etc/os-release ; echo $VERSION_ID).deb
RUN wget -O /tmp/pandare.deb \
    https://github.com/panda-re/qemu/releases/download/${PANDA_VERSION}/pandare_22.04.deb && \
    wget -O /tmp/pandare-plugins.deb \
    https://github.com/panda-re/panda-ng/releases/download/v${PANDANG_VERSION}/pandare-plugins_22.04.deb
    # RUN wget -O /tmp/pandare.deb https://github.com/panda-re/panda/releases/download/v${PANDA_VERSION}/pandare_$(. /etc/os-release ; echo $VERSION_ID).deb

ARG RIPGREP_VERSION
RUN wget -O /tmp/ripgrep.deb \
        https://github.com/BurntSushi/ripgrep/releases/download/${RIPGREP_VERSION}/ripgrep_${RIPGREP_VERSION}-1_amd64.deb

ARG GLOW_VERSION
RUN wget -qO /tmp/glow.deb https://github.com/charmbracelet/glow/releases/download/v${GLOW_VERSION}/glow_${GLOW_VERSION}_amd64.deb

ARG GUM_VERSION
RUN wget -qO /tmp/gum.deb https://github.com/charmbracelet/gum/releases/download/v${GUM_VERSION}/gum_${GUM_VERSION}_amd64.deb

# 3) Get penguin resources
# Download kernels from CI. Populate /igloo_static/kernels
ARG LINUX_VERSION
RUN /get_release.sh rehosting linux_builder ${LINUX_VERSION} kernels-latest.tar.gz | \
    tar xzf - -C /igloo_static

# Populate /igloo_static/utils.bin/utils/busybox.*
ARG BUSYBOX_VERSION
RUN /get_release.sh rehosting busybox ${BUSYBOX_VERSION} busybox-latest.tar.gz | \
    tar xzf - -C /igloo_static/ && \
    mv /igloo_static/build/* /igloo_static/

# Get panda provided console from CI. Populate /igloo_static/console
ARG CONSOLE_VERSION
RUN /get_release.sh rehosting console ${CONSOLE_VERSION} console.tar.gz | \
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
    for arch in arm aarch64 mips mips64 mipsn32 powerpc powerpc64 riscv32 riscv64 loongarch64 x86_64 i386; do \
        make -C musl-* \
            ARCH=$arch \
            DESTDIR=/ \
            prefix=/igloo_static/musl-headers/$arch \
            install-headers; \
    done && \
    rm -rf musl-*

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
ARG VPN_VERSION
RUN /get_release.sh rehosting vpnguin ${VPN_VERSION} vpn.tar.gz | \
    tar xzf - -C /igloo_static

ARG HYPERFS_VERSION
RUN /get_release.sh rehosting hyperfs ${HYPERFS_VERSION} hyperfs.tar.gz | \
  tar xzf - -C / && \
  /get_release.sh rehosting hyperfs 0.0.38 hyperfs.tar.gz | \
  tar xzf - -C / && \
  cp -r /result/utils/* /igloo_static/ && \
  mv /result/dylibs /igloo_static/dylibs && \
  rm -rf /result

# Download guesthopper from CI. Populate /igloo_static/guesthopper
ARG GUESTHOPPER_VERSION
RUN /get_release.sh rehosting guesthopper ${GUESTHOPPER_VERSION} guesthopper.tar.gz | \
    tar xzf - -C /igloo_static

# Download igloo_driver. Should fill in to kernel directories
ARG IGLOO_DRIVER_VERSION
RUN /get_release.sh rehosting igloo_driver ${IGLOO_DRIVER_VERSION} igloo_driver.tar.gz | \
    tar xzf - -C /igloo_static

RUN wget https://github.com/wtdcode/DebianOnQEMU/releases/download/v2024.01.05/bios-loong64-8.1.bin -O /igloo_static/loongarch64/bios-loong64-8.1.bin

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

#### CROSS BUILDER: Build send_hypercall ###
FROM ${REGISTRY}/rehosting/embedded-toolchains:latest AS cross_builder
COPY ./guest-utils/native/ /source
WORKDIR /source
RUN wget -q https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h
RUN make all

#### NMAP BUILDER: Build nmap ####
FROM $BASE_IMAGE AS nmap_builder
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
FROM $BASE_IMAGE AS python_builder
ARG PANDANG_VERSION

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y python3-pip git wget liblzo2-dev
RUN wget -O /tmp/pandare2-${PANDANG_VERSION}-py3-none-any.whl \
    https://github.com/panda-re/panda-ng/releases/download/v${PANDANG_VERSION}/pandare2-${PANDANG_VERSION}-py3-none-any.whl
RUN --mount=type=cache,target=/root/.cache/pip \
      pip wheel --no-cache-dir --wheel-dir /app/wheels \
      angr \
      beautifulsoup4 \
      coloredlogs \
      git+https://github.com/AndrewFasano/angr-targets.git@af_fixes \
      html5lib \
      /tmp/pandare2-${PANDANG_VERSION}-py3-none-any.whl \
      ipdb \
      python-Levenshtein \
      lief  \
      lxml \
      lz4 \
      openai \
      pydantic \
      pydantic-partial \
      pyelftools \
      pyyaml \
      pyvis \
      jsonschema \
      click \
      art \
      setuptools \
      sqlalchemy \
      yamlcore \
      junit-xml \
      jc \
      git+http://github.com/jrspruitt/ubi_reader.git@v0.8.5-master \
      git+https://github.com/rehosting/binwalk.git \
      git+https://github.com/ahupp/python-magic \
      git+https://github.com/devttys0/yaffshiv.git \
      git+https://github.com/marin-m/vmlinux-to-elf \
      jefferson \
      gnupg \
      poetry \
      psycopg2-binary \
      pycryptodome \
      pylzma \
      setuptools \
      sqlalchemy \
      telnetlib3 \
      tk \
      ujson \
      cxxfilt \
      zstandard \
      pdoc

FROM python_builder AS version_generator
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

### Build fw2tar deps ahead of time ###
FROM $BASE_IMAGE AS fw2tar_dep_builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y -q git android-sdk-libsparse-utils arj automake build-essential bzip2 cabextract clang cpio cramfsswap curl default-jdk e2fsprogs fakeroot gcc git gzip lhasa libarchive-dev libfontconfig1-dev libacl1-dev libcap-dev liblzma-dev liblzo2-dev liblz4-dev libbz2-dev libssl-dev libmagic1 locales lz4 lziprecover lzop mtd-utils openssh-client p7zip p7zip-full python3 python3-pip qtbase5-dev sleuthkit squashfs-tools srecord tar unar unrar unrar-free unyaffs unzip wget xz-utils zlib1g-dev zstd

ARG FW2TAR_TAG
RUN git clone --depth=1 -b ${FW2TAR_TAG} https://github.com/rehosting/fw2tar.git /tmp/fw2tar
RUN git clone --depth=1 https://github.com/davidribyrne/cramfs.git /cramfs && \
    cd /cramfs && make
RUN git clone --depth=1 https://github.com/rehosting/unblob.git /unblob

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
ARG SSH
RUN --mount=type=ssh git clone git@github.com:rehosting/fakeroot.git /fakeroot && \
    sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list && \
    apt-get update && apt-get build-dep -y fakeroot && \
    cd /fakeroot && ./bootstrap && ./configure && make || true

# Create empty directory to copy if it doesn't exist
RUN mkdir /fakeroot || true

### MAIN CONTAINER ###
FROM $BASE_IMAGE AS penguin
# Environment setup
ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""

# Install unblob dependencies, curl, and fakeroot
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV HOME=/root

# Add rootshell helper command
RUN echo "#!/bin/sh\ntelnet localhost 4321" > /usr/local/bin/rootshell && chmod +x /usr/local/bin/rootshell

COPY --from=downloader /tmp/pandare.deb /tmp/
COPY --from=downloader /tmp/pandare-plugins.deb /tmp/
COPY --from=downloader /tmp/glow.deb /tmp/
COPY --from=downloader /tmp/gum.deb /tmp/
COPY --from=downloader /tmp/ripgrep.deb /tmp/

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


# Update and install prerequisites
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    ca-certificates \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add the LLVM repository (proper key import + HTTPS)
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] https://apt.llvm.org/jammy/ llvm-toolchain-jammy-20 main" > /etc/apt/sources.list.d/llvm-toolchain-jammy-20.list

# Install apt dependencies - first line for penguin - second for fw2tar
RUN apt-get update && apt-get install -q -y \
    fakeroot genext2fs graphviz graphviz-dev libarchive13 libgcc-s1 liblinear4 liblua5.3-0 libpcap0.8 libpcre3 libssh2-1 libssl3 libstdc++6 libxml2 lua-lpeg nmap python3 python3-lxml python3-venv sudo telnet vim wget zlib1g pigz clang-20 lld-20 \
    android-sdk-libsparse-utils arj automake build-essential bzip2 cabextract cpio cramfsswap curl default-jdk e2fsprogs fakeroot gcc git gzip lhasa libarchive-dev libfontconfig1-dev libacl1-dev libcap-dev liblzma-dev liblzo2-dev liblz4-dev libbz2-dev libssl-dev libmagic1 locales lz4 lziprecover lzop mtd-utils openssh-client p7zip p7zip-full python3 python3-pip qtbase5-dev sleuthkit squashfs-tools srecord tar unar unrar unrar-free unyaffs unzip xz-utils zlib1g-dev zstd && \
    apt install -yy -f /tmp/pandare.deb -f /tmp/pandare-plugins.deb \
    -f /tmp/glow.deb -f /tmp/gum.deb -f /tmp/ripgrep.deb && \
    rm -rf /var/lib/apt/lists/* /tmp/*.deb

# Binwalk v3 runtime dependencies
RUN git clone --depth=1 https://github.com/ReFirmLabs/binwalk /binwalk && \
    cd /binwalk/dependencies && \
    sh -c ./ubuntu.sh

# If we want to run in a venv, we can use this. System site packages means
# we can still access the apt-installed python packages (e.g. guestfs) in our venv
#RUN python3 -m venv --system-site-packages /venv
#ENV PATH="/venv/bin:$PATH"
# install prebuilt python packages
COPY --from=python_builder /app/wheels /wheels

# Remove python_lzo 1.0 to resolve depdency collision with vmlinux-to-elf
RUN rm -rf /wheels/python_lzo*

RUN pip install --no-cache /wheels/* && rm -rf /wheels

RUN poetry config virtualenvs.create false

# VPN, libnvram, kernels, console
COPY --from=downloader /igloo_static/ /igloo_static/

# Copy nmap build into /usr/local/bin
COPY --from=nmap_builder /build/nmap /usr/local/

COPY --from=downloader /tmp/ltrace /igloo_static/ltrace

# Copy source and binaries from host
COPY --from=cross_builder /source/out /igloo_static/
COPY guest-utils /igloo_static/guest-utils
COPY --from=rust_builder /root/vhost-device/target/x86_64-unknown-linux-gnu/release/vhost-device-vsock /usr/local/bin/vhost-device-vsock

# Copy wrapper script into container so we can copy out - note we don't put it on guest path
COPY ./penguin /usr/local/src/penguin_wrapper
# And add install helpers which generate shell commands to install it on host
COPY ./src/resources/banner.sh ./src/resources/penguin_install ./src/resources/penguin_install.local /usr/local/bin/
# Warn on interactive shell sessions and provide instructions for install. Suppress with `docker run ... -e NOBANNER=1 ... bash`
RUN echo '[ ! -z "$TERM" ] && [ -z "$NOBANNER" ] && /usr/local/bin/banner.sh' >> /etc/bash.bashrc

# ====================== Finish setting up fw2tar ======================
COPY --from=rust_builder /usr/local/bin/binwalk /usr/local/bin/binwalk
COPY --from=rust_builder /usr/local/bin/fw2tar /usr/local/bin/fw2tar
COPY --from=fw2tar_dep_builder /tmp/fw2tar /tmp/fw2tar

# CramFS no longer in apt - needed by binwalk
COPY --from=fw2tar_dep_builder /cramfs /cramfs
RUN cd /cramfs && make && make install

# Clone unblob fork then install with poetry
COPY --from=fw2tar_dep_builder /unblob /unblob
RUN cd /unblob && poetry install --only main

# Explicitly install unblob deps - mostly captured above, but some of the .debs get updated and installed via curl
RUN sh -c /unblob/unblob/install-deps.sh

# We will run as other users (matching uid/gid to host), but binwalk has config files in /root/.config
# that need to be created and read at runtime.
RUN chmod -R 777 /root/

# Try to install custom fakeroot. This is optional - we have regular fakeroot. If we're building
# with host SSH keys, we can do this, otherwise we'll just skip it
# Setup ssh keys for github.com
COPY --from=fw2tar_dep_builder /fakeroot /fakeroot
RUN cd /fakeroot && make install -k || true

# Patch to fix unblob #767 that hasn't yet been upstreamed. Pip install didn't work. I don't understand poetry
#RUN pip install git+https://github.com/qkaiser/arpy.git
RUN curl "https://raw.githubusercontent.com/qkaiser/arpy/23faf88a88488c41fc4348ea2b70996803f84f40/arpy.py" -o /usr/local/lib/python3.10/dist-packages/arpy.py

# Copy wrapper script into container so we can copy out - note we don't put it on guest path
RUN cp /tmp/fw2tar/fw2tar /usr/local/src/fw2tar_wrapper
# And add install helpers which generate shell commands to install it on host
RUN cp /tmp/fw2tar/src/resources/fw2tar_install /tmp/fw2tar/src/resources/fw2tar_install.local /usr/local/bin/

RUN cp /tmp/fw2tar/src/fakeroot_fw2tar /usr/local/bin/
# ======================================================================

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

# Copy pyplugins into our the pyplugins directory. We might mount
# this from the host during development. In the long term we'll
# merge these into the main penguin module
COPY ./pyplugins/ /pyplugins

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
        if [ -f /tmp/local_packages/kernels-latest.tar.gz ]; then \
            rm -rf /igloo_static/kernels && \
            tar xvf /tmp/local_packages/kernels-latest.tar.gz -C /igloo_static/; \
        fi; \
        if [ -f /tmp/local_packages/pandare_22.04.deb ]; then \
            dpkg -i /tmp/local_packages/pandare_22.04.deb; \
        fi; \
        if [ -f /tmp/local_packages/pandare-plugins_22.04.deb ]; then \
            dpkg -i /tmp/local_packages/pandare-plugins_22.04.deb; \
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
        if [ -f /tmp/local_packages/plugins.tar.gz ]; then \
            tar xvf /tmp/local_packages/plugins.tar.gz -C /usr/local/lib/panda/panda/; \
        fi; \
        if [ -f /tmp/local_packages/pandare2-*.whl ]; then \
            pip install /tmp/local_packages/pandare2-*.whl; \
        fi; \
        if [ -f /tmp/local_packages/pandare2.tar.gz ]; then \
            tar xvf /tmp/local_packages/pandare2.tar.gz -C /usr/local/lib/python3.10/dist-packages/; \
        fi; \
        if [ -f /tmp/local_packages/guesthopper.tar.gz ]; then \
            rm -rf /igloo_static/guesthopper; \
            tar xzf /tmp/local_packages/guesthopper.tar.gz -C /igloo_static; \
        fi; \
        if [ -f /tmp/local_packages/igloo_driver.tar.gz ]; then \
            tar xzf /tmp/local_packages/igloo_driver.tar.gz -C /igloo_static; \
        fi; \
    fi
RUN mkdir /igloo_static/utils.source && \
    for file in /igloo_static/guest-utils/scripts/*; do \
        ln -s "$file" /igloo_static/utils.source/"$(basename "$file")".all; \
    done
RUN  cd /igloo_static &&  \
    mv loongarch/* loongarch64 && rm -rf loongarch && \
    mv ppc64/* powerpc64 && rm -rf ppc64 && \
    mv ppc/* powerpc && rm -rf ppc && \
    mv arm64/* aarch64/ && rm -rf arm64 && \
    ln -sf /igloo_static/armel/vpn /igloo_static/aarch64/vpn && \
    mkdir -p utils.bin && \
    for arch in "aarch64" "armel" "loongarch64" "mipsel" "mips64eb" "mips64el" "mipseb" "powerpc" "powerpcle" "powerpc64" "powerpc64le" "riscv32" "riscv64" "x86_64"; do \
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
