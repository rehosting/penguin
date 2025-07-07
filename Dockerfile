# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:jammy-20250619"
ARG CLONE_TOKEN="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"
ARG DOWNLOAD_TOKEN=${CLONE_TOKEN}
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
ARG DEBIANONQEMU_VERSION="v2024.01.05"

FROM rust:1.86 AS rust_builder
RUN git clone --depth 1 -q https://github.com/rust-vmm/vhost-device/ /root/vhost-device
ARG VHOST_DEVICE_VERSION
ENV PATH="/root/.cargo/bin:$PATH"
ENV CARGO_INSTALL_ROOT="/usr/local" 

RUN apt-get update --allow-releaseinfo-change && apt-get install -y --fix-missing -q build-essential libfontconfig1-dev liblzma-dev

RUN cargo install binwalk --target x86_64-unknown-linux-gnu --locked

ARG FW2TAR_TAG
ARG CLONE_TOKEN
RUN cargo install --target x86_64-unknown-linux-gnu \
    --tag ${FW2TAR_TAG} \
    --git https://${CLONE_TOKEN}:@github.com/rehosting/fw2tar.git

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cd /root/vhost-device/ && \
  git fetch --depth 1 origin tag $VHOST_DEVICE_VERSION && \
  git checkout $VHOST_DEVICE_VERSION && \
   cargo build --release --bin vhost-device-vsock --target x86_64-unknown-linux-gnu

### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing

# --- FETCH BASE ---
FROM $BASE_IMAGE AS fetch_base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update --allow-releaseinfo-change && \
    apt-get install -y --fix-missing curl jq bzip2 ca-certificates less wget make xmlstarlet && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /out
COPY ./get_release.sh /get_release.sh

# --- FETCH KERNELS ---
FROM fetch_base AS fetch_kernels
ARG DOWNLOAD_TOKEN
ARG LINUX_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/kernels-latest.tar.gz ]; then cp /local_packages/kernels-latest.tar.gz /out/kernels-latest.tar.gz; else /get_release.sh /out/kernels-latest.tar.gz rehosting linux_builder v${LINUX_VERSION} ${DOWNLOAD_TOKEN} kernels-latest.tar.gz; fi
# --- FETCH BUSYBOX ---
FROM fetch_base AS fetch_busybox
ARG DOWNLOAD_TOKEN
ARG BUSYBOX_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/busybox-latest.tar.gz ]; then cp /local_packages/busybox-latest.tar.gz /out/busybox-latest.tar.gz; else /get_release.sh /out/busybox-latest.tar.gz rehosting busybox v${BUSYBOX_VERSION} ${DOWNLOAD_TOKEN} busybox-latest.tar.gz; fi
# --- FETCH CONSOLE ---
FROM fetch_base AS fetch_console
ARG DOWNLOAD_TOKEN
ARG CONSOLE_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/console.tar.gz ]; then cp /local_packages/console.tar.gz /out/console.tar.gz; else /get_release.sh /out/console.tar.gz rehosting console v${CONSOLE_VERSION} ${DOWNLOAD_TOKEN} console.tar.gz; fi
# --- FETCH LIBNVRAM ---
FROM fetch_base AS fetch_libnvram
ARG DOWNLOAD_TOKEN
ARG LIBNVRAM_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/libnvram-latest.tar.gz ]; then cp /local_packages/libnvram-latest.tar.gz /out/libnvram-latest.tar.gz; else /get_release.sh /out/libnvram-latest.tar.gz rehosting libnvram v${LIBNVRAM_VERSION} ${DOWNLOAD_TOKEN} source.tar.gz; fi
# --- FETCH VPN ---
FROM fetch_base AS fetch_vpn
ARG DOWNLOAD_TOKEN
ARG VPN_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/vpn.tar.gz ]; then cp /local_packages/vpn.tar.gz /out/vpn.tar.gz; else /get_release.sh /out/vpn.tar.gz rehosting vpnguin v${VPN_VERSION} ${DOWNLOAD_TOKEN} vpn.tar.gz; fi
# --- FETCH HYPERFS ---
FROM fetch_base AS fetch_hyperfs
ARG DOWNLOAD_TOKEN
ARG HYPERFS_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/hyperfs.tar.gz ]; then cp /local_packages/hyperfs.tar.gz /out/hyperfs.tar.gz; else /get_release.sh /out/hyperfs.tar.gz rehosting hyperfs v${HYPERFS_VERSION} ${DOWNLOAD_TOKEN} hyperfs.tar.gz; fi
# --- FETCH GUESTHOPPER ---
FROM fetch_base AS fetch_guesthopper
ARG DOWNLOAD_TOKEN
ARG GUESTHOPPER_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/guesthopper.tar.gz ]; then cp /local_packages/guesthopper.tar.gz /out/guesthopper.tar.gz; else /get_release.sh /out/guesthopper.tar.gz rehosting guesthopper v${GUESTHOPPER_VERSION} ${DOWNLOAD_TOKEN} guesthopper.tar.gz; fi
# --- FETCH LTRACE ---
FROM fetch_base AS fetch_ltrace
ARG LTRACE_PROTOTYPES_VERSION
ARG LTRACE_PROTOTYPES_HASH
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/ltrace-prototypes.tar.bz2 ]; then cp /local_packages/ltrace-prototypes.tar.bz2 /out/ltrace-prototypes.tar.bz2; else curl -sSL -o /out/ltrace-prototypes.tar.bz2 https://src.fedoraproject.org/repo/pkgs/ltrace/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2/${LTRACE_PROTOTYPES_HASH}/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2; fi
# --- FETCH PANDA ---
FROM fetch_base AS fetch_panda
ARG DOWNLOAD_TOKEN
ARG PANDA_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/pandare.deb ]; then cp /local_packages/pandare.deb /out/pandare.deb; else /get_release.sh /out/pandare.deb panda-re qemu ${PANDA_VERSION} ${DOWNLOAD_TOKEN} pandare_22.04.deb; fi
# --- FETCH PANDA PLUGINS ---
FROM fetch_base AS fetch_panda_plugins
ARG DOWNLOAD_TOKEN
ARG PANDANG_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/pandare-plugins.deb ]; then cp /local_packages/pandare-plugins.deb /out/pandare-plugins.deb; else /get_release.sh /out/pandare-plugins.deb panda-re panda-ng v${PANDANG_VERSION} ${DOWNLOAD_TOKEN} pandare-plugins_22.04.deb; fi
# --- FETCH RIPGREP ---
FROM fetch_base AS fetch_ripgrep
ARG DOWNLOAD_TOKEN
ARG RIPGREP_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/ripgrep.deb ]; then cp /local_packages/ripgrep.deb /out/ripgrep.deb; else /get_release.sh /out/ripgrep.deb BurntSushi ripgrep ${RIPGREP_VERSION} ${DOWNLOAD_TOKEN} ripgrep_${RIPGREP_VERSION}-1_amd64.deb; fi
# --- FETCH GLOW ---
FROM fetch_base AS fetch_glow
ARG DOWNLOAD_TOKEN
ARG GLOW_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/glow.deb ]; then cp /local_packages/glow.deb /out/glow.deb; else /get_release.sh /out/glow.deb charmbracelet glow v${GLOW_VERSION} ${DOWNLOAD_TOKEN} glow_${GLOW_VERSION}_amd64.deb; fi
# --- FETCH GUM ---
FROM fetch_base AS fetch_gum
ARG DOWNLOAD_TOKEN
ARG GUM_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/gum.deb ]; then cp /local_packages/gum.deb /out/gum.deb; else /get_release.sh /out/gum.deb charmbracelet gum v${GUM_VERSION} ${DOWNLOAD_TOKEN} gum_${GUM_VERSION}_amd64.deb; fi
# --- FETCH MUSL HEADERS ---
FROM fetch_base AS fetch_musl
ARG MUSL_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/musl-${MUSL_VERSION}.tar.gz ]; then \
    cp /local_packages/musl-${MUSL_VERSION}.tar.gz /musl.tar.gz; \
  else \
    wget -qO /musl.tar.gz https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz; \
  fi && \
  tar xzf /musl.tar.gz && \
  mkdir -p /out/musl-headers && \
  for arch in arm aarch64 mips mips64 mipsn32 powerpc powerpc64 riscv32 riscv64 loongarch64 x86_64 i386; do \
    make -C musl-* ARCH=$arch DESTDIR=/ prefix=/out/musl-headers/$arch install-headers; \
  done && \
  tar czf /out/musl-headers.tar.gz -C /out musl-headers && \
  rm -rf musl-* /out/musl-headers /musl.tar.gz /local_packages/musl-${MUSL_VERSION}.tar.gz
# --- FETCH DEBIANONQEMU BIOS ---
FROM fetch_base AS fetch_debianonqemu
ARG DOWNLOAD_TOKEN
ARG DEBIANONQEMU_VERSION
COPY ./local_packages /local_packages
RUN if [ -f /local_packages/bios-loong64-8.1.bin ]; then cp /local_packages/bios-loong64-8.1.bin /out/bios-loong64-8.1.bin; else /get_release.sh /out/bios-loong64-8.1.bin wtdcode DebianOnQEMU ${DEBIANONQEMU_VERSION} ${DOWNLOAD_TOKEN} bios-loong64-8.1.bin; fi

# --- FINAL DOWNLOADER ---
FROM $BASE_IMAGE AS downloader
ENV DEBIAN_FRONTEND=noninteractive
RUN mkdir -p /igloo_static/loongarch64 /tmp
COPY --from=fetch_kernels /out/kernels-latest.tar.gz /tmp/
COPY --from=fetch_busybox /out/busybox-latest.tar.gz /tmp/
COPY --from=fetch_console /out/console.tar.gz /tmp/
COPY --from=fetch_libnvram /out/libnvram-latest.tar.gz /tmp/
COPY --from=fetch_vpn /out/vpn.tar.gz /tmp/
COPY --from=fetch_hyperfs /out/hyperfs.tar.gz /tmp/
COPY --from=fetch_guesthopper /out/guesthopper.tar.gz /tmp/
COPY --from=fetch_ltrace /out/ltrace-prototypes.tar.bz2 /tmp/
COPY --from=fetch_musl /out/musl-headers.tar.gz /tmp/
COPY --from=fetch_debianonqemu /out/bios-loong64-8.1.bin /tmp/

# Extract and arrange all archives as in Dockerfile.old
RUN set -eux; \
    tar xzf /tmp/kernels-latest.tar.gz -C /igloo_static && rm /tmp/kernels-latest.tar.gz; \
    tar xzf /tmp/busybox-latest.tar.gz -C /igloo_static && rm /tmp/busybox-latest.tar.gz; \
    if [ -d /igloo_static/build ]; then mv /igloo_static/build/* /igloo_static/ && rmdir /igloo_static/build; fi; \
    tar xzf /tmp/console.tar.gz -C /igloo_static && rm /tmp/console.tar.gz; \
    tar xzf /tmp/libnvram-latest.tar.gz -C /igloo_static && rm /tmp/libnvram-latest.tar.gz; \
    if [ -d /igloo_static/libnvram-* ]; then mv /igloo_static/libnvram-* /igloo_static/libnvram; fi; \
    tar xzf /tmp/vpn.tar.gz -C /igloo_static && rm /tmp/vpn.tar.gz; \
    tar xzf /tmp/hyperfs.tar.gz -C / && rm /tmp/hyperfs.tar.gz; \
    if [ -d /result/utils ]; then cp -r /result/utils/* /igloo_static/; fi; \
    if [ -d /result/dylibs ]; then mv /result/dylibs /igloo_static/dylibs; fi; \
    rm -rf /result; \
    tar xzf /tmp/guesthopper.tar.gz -C /igloo_static && rm /tmp/guesthopper.tar.gz; \
    tar xzf /tmp/musl-headers.tar.gz -C /igloo_static && rm /tmp/musl-headers.tar.gz; \
    tar xjf /tmp/ltrace-prototypes.tar.bz2 -C /igloo_static && rm /tmp/ltrace-prototypes.tar.bz2; \
    if [ -d /igloo_static/ltrace-* ]; then mv /igloo_static/ltrace-*/etc /igloo_static/ltrace && rm -rf /igloo_static/ltrace-*; fi; \
    mv /tmp/bios-loong64-8.1.bin /igloo_static/loongarch64/bios-loong64-8.1.bin

# Add libnvram ltrace prototype file
COPY ./src/resources/ltrace_nvram.conf /igloo_static/ltrace/lib_inject.so.conf


#### CROSS BUILDER: Build send_hypercall ###
FROM ghcr.io/rehosting/embedded-toolchains:latest AS cross_builder
COPY ./guest-utils/native/ /source
WORKDIR /source
RUN wget -q https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h
RUN make all

### Python Builder: Build all wheel files necessary###
FROM $BASE_IMAGE AS python_builder
ARG PANDANG_VERSION
ARG DOWNLOAD_TOKEN

COPY ./get_release.sh /get_release.sh

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN apt-get update --allow-releaseinfo-change && apt-get install -y --fix-missing python3-pip git curl jq liblzo2-dev
RUN /get_release.sh /tmp/pandare2-${PANDANG_VERSION}-py3-none-any.whl panda-re panda-ng v${PANDANG_VERSION} ${DOWNLOAD_TOKEN} pandare2-${PANDANG_VERSION}-py3-none-any.whl
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

### Build fw2tar deps ahead of time ###
FROM $BASE_IMAGE AS fw2tar_dep_builder
ENV DEBIAN_FRONTEND=noninteractive

COPY ./dependencies/fw2tar.txt /tmp/fw2tar.txt
RUN apt-get update --allow-releaseinfo-change && apt-get install -y -q --fix-missing git $(cat /tmp/fw2tar.txt)

ARG CLONE_TOKEN
ARG FW2TAR_TAG
RUN git clone --depth=1 -b ${FW2TAR_TAG} https://${CLONE_TOKEN}:@github.com/rehosting/fw2tar.git /tmp/fw2tar
RUN git clone --depth=1 https://github.com/davidribyrne/cramfs.git /cramfs && \
    cd /cramfs && make
RUN git clone --depth=1 https://github.com/rehosting/unblob.git /unblob

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
ARG SSH
RUN --mount=type=ssh git clone git@github.com:rehosting/fakeroot.git /fakeroot && \
    sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list && \
    apt-get update --allow-releaseinfo-change && apt-get build-dep -y --fix-missing fakeroot && \
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

# We need pycparser>=2.21 for angr. If we try this later with the other pip commands,
# we'll fail because we get a distutils distribution of pycparser 2.19 that we can't
# uninstall somewhere in setting up other dependencies.

RUN apt-get update --allow-releaseinfo-change && \
    apt-get --no-install-recommends install -y --fix-missing python3-pip && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cache/pip \
      pip install --upgrade \
        pip \
        "pycparser>=2.21"

# Update and install prerequisites
RUN apt-get update --allow-releaseinfo-change && apt-get install -y --fix-missing \
    wget \
    gnupg \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add the LLVM repository
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 20

# Install apt dependencies - largely for binwalk, some for penguin, some for fw2tar
COPY --from=fetch_glow /out/glow.deb /tmp/glow.deb
COPY --from=fetch_gum /out/gum.deb /tmp/
COPY --from=fetch_panda /out/pandare.deb /tmp/
COPY --from=fetch_panda_plugins /out/pandare-plugins.deb /tmp/
COPY --from=fetch_ripgrep /out/ripgrep.deb /tmp/
COPY ./dependencies/* /tmp
RUN apt-get update --allow-releaseinfo-change && apt-get install -q -y --fix-missing $(cat /tmp/penguin.txt) $(cat /tmp/fw2tar.txt) && \
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
RUN rm /wheels/python_lzo*

RUN pip install --no-cache /wheels/*

RUN poetry config virtualenvs.create false

# VPN, libnvram, kernels, console
COPY --from=downloader /igloo_static/ /igloo_static/
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
