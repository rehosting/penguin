# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:jammy-20250619"
ARG USE_MIRROR=false
ARG DOWNLOAD_TOKEN="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"
ARG VPN_VERSION="1.0.24"
ARG BUSYBOX_VERSION="0.0.15"
ARG LINUX_VERSION="3.3.3-beta"
ARG LIBNVRAM_VERSION="0.0.22"
ARG CONSOLE_VERSION="1.0.7"
ARG GUESTHOPPER_VERSION="1.0.16"
ARG HYPERFS_VERSION="0.0.40"
ARG GLOW_VERSION="1.5.1"
ARG GUM_VERSION="0.14.5"
ARG LTRACE_PROTOTYPES_VERSION="0.7.91"
ARG LTRACE_PROTOTYPES_HASH="9db3bdee7cf3e11c87d8cc7673d4d25b"
ARG MUSL_VERSION="1.2.5"
ARG VHOST_DEVICE_VERSION="vhost-device-vsock-v0.2.0"
ARG FW2TAR_TAG="v2.0.1"
ARG PANDA_VERSION="pandav0.0.40"
ARG PANDANG_VERSION="0.0.26"
ARG RIPGREP_VERSION="14.1.1"

FROM rust:1.86 AS rust_builder
RUN git clone --depth 1 -q https://github.com/rust-vmm/vhost-device/ /root/vhost-device
ARG VHOST_DEVICE_VERSION
ENV PATH="/root/.cargo/bin:$PATH"
ENV CARGO_INSTALL_ROOT="/usr/local" 

RUN apt-get update && apt-get install -y -q build-essential libfontconfig1-dev liblzma-dev

RUN cargo install binwalk --target x86_64-unknown-linux-gnu --locked

ARG FW2TAR_TAG
ARG DOWNLOAD_TOKEN
RUN cargo install --target x86_64-unknown-linux-gnu \
    --tag ${FW2TAR_TAG} \
    --git https://${DOWNLOAD_TOKEN}:@github.com/rehosting/fw2tar.git

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cd /root/vhost-device/ && \
  git fetch --depth 1 origin tag $VHOST_DEVICE_VERSION && \
  git checkout $VHOST_DEVICE_VERSION && \
   cargo build --release --bin vhost-device-vsock --target x86_64-unknown-linux-gnu

### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing
FROM $BASE_IMAGE AS downloader
ARG USE_MIRROR
ARG APT_CACHE_DIR=/var/cache/apt/archives
COPY docker/mirrors.list /tmp/mirrors.list
RUN if [ "$USE_MIRROR" = "true" ]; then cp /tmp/mirrors.list /etc/apt/sources.list; fi
ENV DEBIAN_FRONTEND=noninteractive
ENV APT_CACHE_DIR=${APT_CACHE_DIR}
RUN apt-get update && \
    apt-get install -y --option=dir::cache::archives=${APT_CACHE_DIR} \
    bzip2 \
    ca-certificates \
    curl \
    jq \
    less \
    wget \
    make \
    git \
    xmlstarlet && \
    rm -rf /var/lib/apt/lists/*
COPY ./get_release.sh /get_release.sh
COPY ./package_cach[e] /package_cache

# Individual fetch stages for each package/resource
FROM downloader AS fetch_pandare
ARG PANDA_VERSION
RUN if [ -f /package_cache/pandare_22.04-${PANDA_VERSION}.deb ]; then \
      cp /package_cache/pandare_22.04-${PANDA_VERSION}.deb /tmp/pandare.deb; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/pandare.deb \
        https://github.com/panda-re/qemu/releases/download/${PANDA_VERSION}/pandare_22.04.deb; \
    fi

FROM downloader AS fetch_pandare_plugins
ARG PANDANG_VERSION
RUN if [ -f /package_cache/pandare-plugins_22.04-${PANDANG_VERSION}.deb ]; then \
      cp /package_cache/pandare-plugins_22.04-${PANDANG_VERSION}.deb /tmp/pandare-plugins.deb; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/pandare-plugins.deb \
        https://github.com/panda-re/panda-ng/releases/download/v${PANDANG_VERSION}/pandare-plugins_22.04.deb; \
    fi

FROM downloader AS fetch_pandare2
ARG PANDANG_VERSION
RUN if [ -f /package_cache/pandare2-${PANDANG_VERSION}-py3-none-any.whl ]; then \
      cp /package_cache/pandare2-${PANDANG_VERSION}-py3-none-any.whl /tmp/pandare2-${PANDANG_VERSION}-py3-none-any.whl; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/pandare2-${PANDANG_VERSION}-py3-none-any.whl \
        https://github.com/panda-re/panda-ng/releases/download/v${PANDANG_VERSION}/pandare2-${PANDANG_VERSION}-py3-none-any.whl; \
    fi

FROM downloader AS fetch_ripgrep
ARG RIPGREP_VERSION
RUN if [ -f /package_cache/ripgrep_${RIPGREP_VERSION}-1_amd64.deb ]; then \
      cp /package_cache/ripgrep_${RIPGREP_VERSION}-1_amd64.deb /tmp/ripgrep.deb; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/ripgrep.deb \
        https://github.com/BurntSushi/ripgrep/releases/download/${RIPGREP_VERSION}/ripgrep_${RIPGREP_VERSION}-1_amd64.deb; \
    fi

FROM downloader AS fetch_glow
ARG GLOW_VERSION
RUN if [ -f /package_cache/glow_${GLOW_VERSION}_amd64.deb ]; then \
      cp /package_cache/glow_${GLOW_VERSION}_amd64.deb /tmp/glow.deb; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/glow.deb \
        https://github.com/charmbracelet/glow/releases/download/v${GLOW_VERSION}/glow_${GLOW_VERSION}_amd64.deb; \
    fi

FROM downloader AS fetch_gum
ARG GUM_VERSION
RUN if [ -f /package_cache/gum_${GUM_VERSION}_amd64.deb ]; then \
      cp /package_cache/gum_${GUM_VERSION}_amd64.deb /tmp/gum.deb; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/gum.deb \
        https://github.com/charmbracelet/gum/releases/download/v${GUM_VERSION}/gum_${GUM_VERSION}_amd64.deb; \
    fi

FROM downloader AS fetch_kernels
ARG DOWNLOAD_TOKEN
ARG LINUX_VERSION
RUN if [ -f /package_cache/kernels-${LINUX_VERSION}.tar.gz ]; then \
      cp /package_cache/kernels-${LINUX_VERSION}.tar.gz /tmp/kernels.tar.gz; \
    else \
      /get_release.sh rehosting linux_builder ${LINUX_VERSION} ${DOWNLOAD_TOKEN} > /tmp/kernels.tar.gz; \
    fi

FROM downloader AS fetch_busybox
ARG DOWNLOAD_TOKEN
ARG BUSYBOX_VERSION
RUN if [ -f /package_cache/busybox-${BUSYBOX_VERSION}.tar.gz ]; then \
      cp /package_cache/busybox-${BUSYBOX_VERSION}.tar.gz /tmp/busybox.tar.gz; \
    else \
      /get_release.sh rehosting busybox ${BUSYBOX_VERSION} ${DOWNLOAD_TOKEN} > /tmp/busybox.tar.gz; \
    fi

FROM downloader AS fetch_console
ARG DOWNLOAD_TOKEN
ARG CONSOLE_VERSION
RUN if [ -f /package_cache/console-${CONSOLE_VERSION}.tar.gz ]; then \
      cp /package_cache/console-${CONSOLE_VERSION}.tar.gz /tmp/console.tar.gz; \
    else \
      /get_release.sh rehosting console ${CONSOLE_VERSION} ${DOWNLOAD_TOKEN} > /tmp/console.tar.gz; \
    fi

FROM downloader AS fetch_libnvram
ARG LIBNVRAM_VERSION
RUN curl -L -v --retry 5 --retry-delay 5 https://github.com/rehosting/libnvram/archive/refs/tags/v${LIBNVRAM_VERSION}.tar.gz -o /tmp/libnvram.tar.gz

FROM downloader AS fetch_musl
ARG MUSL_VERSION
RUN curl -L -v --retry 5 --retry-delay 5 https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz -o /tmp/musl.tar.gz

FROM downloader AS fetch_vpn
ARG DOWNLOAD_TOKEN
ARG VPN_VERSION
RUN if [ -f /package_cache/vpnguin-${VPN_VERSION}.tar.gz ]; then \
      cp /package_cache/vpnguin-${VPN_VERSION}.tar.gz /tmp/vpn.tar.gz; \
    else \
      /get_release.sh rehosting vpnguin ${VPN_VERSION} ${DOWNLOAD_TOKEN} > /tmp/vpn.tar.gz; \
    fi

FROM downloader AS fetch_hyperfs
ARG DOWNLOAD_TOKEN
ARG HYPERFS_VERSION
RUN if [ -f /package_cache/hyperfs-${HYPERFS_VERSION}.tar.gz ]; then \
      cp /package_cache/hyperfs-${HYPERFS_VERSION}.tar.gz /tmp/hyperfs.tar.gz; \
    else \
      /get_release.sh rehosting hyperfs ${HYPERFS_VERSION} ${DOWNLOAD_TOKEN} > /tmp/hyperfs.tar.gz; \
    fi

FROM downloader AS fetch_guesthopper
ARG DOWNLOAD_TOKEN
ARG GUESTHOPPER_VERSION
RUN if [ -f /package_cache/guesthopper-${GUESTHOPPER_VERSION}.tar.gz ]; then \
      cp /package_cache/guesthopper-${GUESTHOPPER_VERSION}.tar.gz /tmp/guesthopper.tar.gz; \
    else \
      /get_release.sh rehosting guesthopper ${GUESTHOPPER_VERSION} ${DOWNLOAD_TOKEN} > /tmp/guesthopper.tar.gz; \
    fi

FROM downloader AS fetch_loongarch_bios
RUN if [ -f /package_cache/bios-loong64-8.1.bin ]; then \
      cp /package_cache/bios-loong64-8.1.bin /tmp/bios-loong64-8.1.bin; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/bios-loong64-8.1.bin https://github.com/wtdcode/DebianOnQEMU/releases/download/v2024.01.05/bios-loong64-8.1.bin; \
    fi

FROM downloader AS fetch_ltrace_prototypes
ARG LTRACE_PROTOTYPES_VERSION
ARG LTRACE_PROTOTYPES_HASH
RUN if [ -f /package_cache/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2 ]; then \
      cp /package_cache/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2 /tmp/ltrace.tar.bz2; \
    else \
      curl -L -v --retry 5 --retry-delay 5 https://src.fedoraproject.org/repo/pkgs/ltrace/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2/${LTRACE_PROTOTYPES_HASH}/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2 -o /tmp/ltrace.tar.bz2; \
    fi

FROM downloader AS fetch_llvm
RUN if [ -f /package_cache/llvm.sh ]; then \
      cp /package_cache/llvm.sh /tmp/llvm.sh; \
    else \
      curl -L -v --retry 5 --retry-delay 5 -o /tmp/llvm.sh https://apt.llvm.org/llvm.sh; \
    fi

### Build fw2tar deps ahead of time ###
FROM downloader AS fw2tar_dep_builder
ARG USE_MIRROR
COPY docker/mirrors.list /tmp/mirrors.list
RUN if [ "$USE_MIRROR" = "true" ]; then cp /tmp/mirrors.list /etc/apt/sources.list; fi
ENV DEBIAN_FRONTEND=noninteractive

COPY ./dependencies/fw2tar.txt /tmp/fw2tar.txt
RUN apt-get update && apt-get install -y -q $(cat /tmp/fw2tar.txt)

ARG DOWNLOAD_TOKEN
RUN git clone --depth=1 https://github.com/davidribyrne/cramfs.git /cramfs && \
    cd /cramfs && make
RUN git clone --depth=1 https://github.com/rehosting/unblob.git /unblob

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
ARG SSH
RUN --mount=type=ssh git clone git@github.com:rehosting/fakeroot.git /fakeroot && \
    sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list && \
    apt-get update && apt-get build-dep -y fakeroot && \
    cd /fakeroot && ./bootstrap && ./configure && make || true

    ARG FW2TAR_TAG
RUN git clone --depth=1 -b ${FW2TAR_TAG} https://${DOWNLOAD_TOKEN}:@github.com/rehosting/fw2tar.git /tmp/fw2tar

# Create empty directory to copy if it doesn't exist
RUN mkdir /fakeroot || true

# Single combiner stage
FROM $BASE_IMAGE AS combiner
ARG APT_CACHE_DIR=/var/cache/apt/archives
ENV DEBIAN_FRONTEND=noninteractive
ENV APT_CACHE_DIR=${APT_CACHE_DIR}
RUN apt-get update && \
    apt-get install -y --option=dir::cache::archives=${APT_CACHE_DIR} \
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

COPY --from=fetch_kernels /tmp/kernels.tar.gz /tmp/
COPY --from=fetch_busybox /tmp/busybox.tar.gz /tmp/
COPY --from=fetch_console /tmp/console.tar.gz /tmp/
COPY --from=fetch_libnvram /tmp/libnvram.tar.gz /tmp/
COPY --from=fetch_musl /tmp/musl.tar.gz /tmp/
COPY --from=fetch_vpn /tmp/vpn.tar.gz /tmp/
COPY --from=fetch_hyperfs /tmp/hyperfs.tar.gz /tmp/
COPY --from=fetch_guesthopper /tmp/guesthopper.tar.gz /tmp/
COPY --from=fetch_loongarch_bios /tmp/bios-loong64-8.1.bin /tmp/
COPY --from=fetch_ltrace_prototypes /tmp/ltrace.tar.bz2 /tmp/

# 3) Get penguin resources
# Download kernels from CI. Populate /igloo_static/kernels
RUN tar xzf /tmp/kernels.tar.gz -C /igloo_static

# Populate /igloo_static/utils.bin/utils/busybox.*
RUN tar xzf /tmp/busybox.tar.gz -C /igloo_static/ && \
    mv /igloo_static/build/* /igloo_static/

# Get panda provided console from CI. Populate /igloo_static/console
RUN tar xzf /tmp/console.tar.gz -C /igloo_static


# Download libnvram. Populate /igloo_static/libnvram.
ARG LIBNVRAM_VERSION
RUN tar xzf /tmp/libnvram.tar.gz -C /igloo_static && \
    mv /igloo_static/libnvram-${LIBNVRAM_VERSION} /igloo_static/libnvram

# Build musl headers for each arch
RUN tar xzf /tmp/musl.tar.gz && \
    for arch in arm aarch64 mips mips64 mipsn32 powerpc powerpc64 riscv32 riscv64 loongarch64 x86_64 i386; do \
        make -C musl-* \
            ARCH=$arch \
            DESTDIR=/ \
            prefix=/igloo_static/musl-headers/$arch \
            install-headers; \
    done && \
    rm -rf musl-*

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
RUN tar xzf /tmp/vpn.tar.gz -C /igloo_static

RUN tar xzf /tmp/hyperfs.tar.gz -C / && \
  cp -r /result/utils/* /igloo_static/ && \
  mv /result/dylibs /igloo_static/dylibs && \
  rm -rf /result

# Download guesthopper from CI. Populate /igloo_static/guesthopper
RUN tar xzf /tmp/guesthopper.tar.gz -C /igloo_static

RUN mkdir -p /igloo_static/loongarch64 && \
    mv /tmp/bios-loong64-8.1.bin /igloo_static/loongarch64/bios-loong64-8.1.bin

# Download prototype files for ltrace.
#
# Download the tarball from Fedora, because ltrace.org doesn't store old
# versions and we want this container to build even when dependencies are
# outdated.
RUN mkdir -p /igloo_static/ltrace && \
  tar xjf /tmp/ltrace.tar.bz2 -C /igloo_static/ltrace --strip-components=1 && \
  mv /igloo_static/ltrace/etc/* /igloo_static/ltrace && \
  rm -rf /igloo_static/ltrace/etc

# Add libnvram ltrace prototype file
COPY ./src/resources/ltrace_nvram.conf /igloo_static/ltrace/lib_inject.so.conf


#### CROSS BUILDER: Build local guest-native tools ###
FROM ghcr.io/rehosting/embedded-toolchains:latest AS cross_builder
COPY ./guest-utils/native/ /source
WORKDIR /source
RUN curl -L -v --retry 5 --retry-delay 5 -o hypercall.h https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h
RUN make all

### Python Builder: Build all wheel files necessary###
FROM $BASE_IMAGE AS python_builder
COPY docker/mirrors.list /tmp/mirrors.list
ARG USE_MIRROR
RUN if [ "$USE_MIRROR" = "true" ]; then cp /tmp/mirrors.list /etc/apt/sources.list; fi
RUN apt-get update && apt-get install -y python3-pip git curl liblzo2-dev

ARG PANDANG_VERSION
COPY --from=fetch_pandare2 /tmp/pandare2-${PANDANG_VERSION}-py3-none-any.whl /tmp/

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

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

### MAIN CONTAINER ###
FROM downloader AS penguin
ARG USE_MIRROR
ARG PIP_CACHE_DIR=/root/.cache/pip
ARG APT_CACHE_DIR=/var/cache/apt/archives
# Environment setup
ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""
ENV PIP_CACHE_DIR=${PIP_CACHE_DIR}
ENV APT_CACHE_DIR=${APT_CACHE_DIR}

# Install unblob dependencies, curl, and fakeroot
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV HOME=/root

# Add rootshell helper command
RUN echo "#!/bin/sh\ntelnet localhost 4321" > /usr/local/bin/rootshell && chmod +x /usr/local/bin/rootshell

COPY --from=fetch_pandare /tmp/pandare.deb /tmp/
COPY --from=fetch_pandare_plugins /tmp/pandare-plugins.deb /tmp/
COPY --from=fetch_glow /tmp/glow.deb /tmp/
COPY --from=fetch_gum /tmp/gum.deb /tmp/
COPY --from=fetch_ripgrep /tmp/ripgrep.deb /tmp/
COPY ./dependencies/* /tmp

# We need pycparser>=2.21 for angr. If we try this later with the other pip commands,
# we'll fail because we get a distutils distribution of pycparser 2.19 that we can't
# uninstall somewhere in setting up other dependencies.

RUN apt-get update && \
    apt-get --no-install-recommends install -y python3-pip && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
      pip install --upgrade \
        pip \
        "pycparser>=2.21"


# Update and install prerequisites
RUN apt-get update && apt-get install -y \
    gnupg \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add the LLVM repository
COPY --from=fetch_llvm /tmp/llvm.sh /tmp/llvm.sh
RUN chmod +x /tmp/llvm.sh && \
    /tmp/llvm.sh 20

# Install apt dependencies - largely for binwalk, some for penguin, some for fw2tar
RUN apt-get update && apt-get install -q -y --option=dir::cache::archives=${APT_CACHE_DIR} $(cat /tmp/penguin.txt) $(cat /tmp/fw2tar.txt) && \
    apt-get install -yy --option=dir::cache::archives=${APT_CACHE_DIR} -f /tmp/pandare.deb -f /tmp/pandare-plugins.deb \
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
RUN rm /wheels/python_lzo*

RUN pip install --no-cache /wheels/*

RUN poetry config virtualenvs.create false

# VPN, libnvram, kernels, console
COPY --from=combiner /igloo_static/ /igloo_static/

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
RUN if [ -f /package_cache/arpy.py ]; then \
      cp /package_cache/arpy.py /usr/local/lib/python3.10/dist-packages/arpy.py; \
    else \
      curl "https://raw.githubusercontent.com/qkaiser/arpy/23faf88a88488c41fc4348ea2b70996803f84f40/arpy.py" -o /usr/local/lib/python3.10/dist-packages/arpy.py; \
    fi

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
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
    pip install -e /db

# Now copy in our module and install it
# penguin is editable so we can mount local copy for dev
COPY --from=version_generator /app/version.txt /pkg/penguin/version.txt
COPY ./src /pkg
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
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

# Supported packages filenames are listed in docs/dev.md

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
