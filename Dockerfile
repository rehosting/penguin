# versions of the various dependencies.
ARG BASE_IMAGE="ubuntu:22.04"
ARG DOWNLOAD_TOKEN="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"
ARG BUSYBOX_VERSION="0.0.13"
ARG LINUX_VERSION="2.4.23"
ARG VPN_VERSION="1.0.24"
ARG LIBNVRAM_VERSION="0.0.18"
ARG CONSOLE_VERSION="1.0.7"
ARG HYPERFS_VERSION="0.0.39"
ARG GUESTHOPPER_VERSION="1.0.15"
ARG GLOW_VERSION="1.5.1"
ARG GUM_VERSION="0.14.5"
ARG LTRACE_PROTOTYPES_VERSION="0.7.91"
ARG LTRACE_PROTOTYPES_HASH="9db3bdee7cf3e11c87d8cc7673d4d25b"
ARG MUSL_VERSION="1.2.5"
ARG VHOST_DEVICE_VERSION="vhost-device-vsock-v0.2.0"
ARG FW2TAR_TAG="v1.1.1"
ARG PANDA_VERSION="pandav0.0.33"
ARG PANDANG_VERSION="0.0.18"
ARG RIPGREP_VERSION="14.1.1"

FROM rust AS vhost_builder
RUN git clone --depth 1 -q https://github.com/rust-vmm/vhost-device/ /root/vhost-device
ARG VHOST_DEVICE_VERSION
RUN cd /root/vhost-device/ && \
  git fetch --depth 1 origin tag $VHOST_DEVICE_VERSION && \
  git checkout $VHOST_DEVICE_VERSION && \
  RUSTFLAGS="-C target-feature=+crt-static" PATH="/root/.cargo/bin:${PATH}" cargo build --release --bin vhost-device-vsock --target x86_64-unknown-linux-gnu

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

# Build capstone v5 libraries for panda callstack_instr to improve arch support
FROM $BASE_IMAGE AS capstone_builder
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
FROM ghcr.io/rehosting/embedded-toolchains:latest AS cross_builder
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
FROM $BASE_IMAGE AS qemu_builder
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

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
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
      zstandard

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
RUN apt-get update && apt-get install -y -q git $(cat /tmp/fw2tar.txt)

ARG DOWNLOAD_TOKEN
ARG FW2TAR_TAG
RUN git clone --depth=1 -b ${FW2TAR_TAG} https://${DOWNLOAD_TOKEN}:@github.com/rehosting/fw2tar.git /tmp/fw2tar
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
COPY --from=capstone_builder /usr/lib/libcapstone* /usr/lib/
COPY ./dependencies/* /tmp

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
    wget \
    gnupg \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add the LLVM repository
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 20

# Install apt dependencies - largely for binwalk, some for penguin, some for fw2tar
RUN apt-get update && apt-get install -q -y $(cat /tmp/penguin.txt) $(cat /tmp/fw2tar.txt) && \
    apt install -yy -f /tmp/pandare.deb -f /tmp/pandare-plugins.deb \
    -f /tmp/glow.deb -f /tmp/gum.deb -f /tmp/ripgrep.deb && \
    rm -rf /var/lib/apt/lists/* /tmp/*.deb

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


# qemu-img
COPY --from=qemu_builder /src/build/qemu-img /usr/local/bin/qemu-img

# VPN, libnvram, kernels, console
COPY --from=downloader /igloo_static/ /igloo_static/

# Copy nmap build into /usr/local/bin
COPY --from=nmap_builder /build/nmap /usr/local/

COPY --from=downloader /tmp/ltrace /igloo_static/ltrace

# Copy source and binaries from host
COPY --from=cross_builder /out /igloo_static/
COPY guest-utils /igloo_static/guest-utils
COPY --from=vhost_builder /root/vhost-device/target/x86_64-unknown-linux-gnu/release/vhost-device-vsock /usr/local/bin/vhost-device-vsock

# Copy wrapper script into container so we can copy out - note we don't put it on guest path
COPY ./penguin /usr/local/src/penguin_wrapper
# And add install helpers which generate shell commands to install it on host
COPY ./src/resources/banner.sh ./src/resources/penguin_install ./src/resources/penguin_install.local /usr/local/bin/
# Warn on interactive shell sessions and provide instructions for install. Suppress with `docker run ... -e NOBANNER=1 ... bash`
RUN echo '[ ! -z "$TERM" ] && [ -z "$NOBANNER" ] && /usr/local/bin/banner.sh' >> /etc/bash.bashrc

# ====================== Finish setting up fw2tar ======================
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

RUN cp /tmp/fw2tar/src/fw2tar /usr/local/bin/
RUN ln -s /usr/local/bin/fw2tar /usr/local/bin/fakeroot_fw2tar
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
    fi
RUN mkdir /igloo_static/utils.source && \
    for file in /igloo_static/guest-utils/scripts/*; do \
        ln -s "$file" /igloo_static/utils.source/"$(basename "$file")".all; \
    done
RUN  cd /igloo_static && mv arm64/* aarch64/ && rm -rf arm64 && mkdir -p utils.bin && \
    for arch in "aarch64" "armel" "mipsel" "mips64eb" "mips64el" "mipseb" "powerpc" "powerpcle" "powerpc64" "powerpc64l;e" "riscv32" "riscv64" "x86_64"; do \
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