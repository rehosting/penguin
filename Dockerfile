### DOWNLOADER ###
# Fetch and extract our various dependencies. Roughly ordered on
# least-frequently changing to most-frequently changing

FROM ubuntu:20.04 as download_base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    xmlstarlet \
    wget

### DEB DOWNLOADER: get genext2fs and pandare debs ###
FROM download_base as deb_downloader
RUN wget -O /tmp/genext2fs.deb https://github.com/panda-re/genext2fs/releases/download/release_9bc57e232e8bb7a0e5c8ccf503b57b3b702b973a/genext2fs.deb && \
    wget -O /tmp/pandare.deb https://panda.re/secret/pandare_2004.deb

### DOWNLOADER: get zap, libguestfs, busybox, libnvram, console, vpn, kernels, and penguin plugins ###
FROM download_base as downloader
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
  wget -qO - https://github.com/panda-re/busybox/releases/download/release_25c906fe05766f7fc4765f4e6e719b717cc2d9b7/busybox-latest.tar.gz | \
  tar xzf - -C /igloo_static/ && \
  mv /igloo_static/build/ /igloo_static/utils.bin && \
  for file in /igloo_static/utils.bin/busybox.*-linux*; do mv "$file" "${file%-linux-*}"; done && \
  mv /igloo_static/utils.bin/busybox.arm /igloo_static/utils.bin/busybox.armel

# Download libnvram from CI. Populate /igloo_static/libnvram
RUN wget -qO - https://github.com/panda-re/libnvram/releases/download/release_7cf4b464578bbe9df2ef0adf2eae6d577fd8f788/libnvram-latest.tar.gz | \
  tar xzf - -C /igloo_static

# Download  console from CI. Populate /igloo_static/console
RUN wget -qO - https://github.com/panda-re/console/releases/download/release_389e179dde938633ff6a44144fe1e03570497479/console-latest.tar.gz | \
  tar xzf - -C /igloo_static && \
  mv /igloo_static/build /igloo_static/console && \
  mv /igloo_static/console/console-arm-linux-musleabi /igloo_static/console/console.armel && \
  mv /igloo_static/console/console-mipsel-linux-musl /igloo_static/console/console.mipsel && \
  mv /igloo_static/console/console-mipseb-linux-musl /igloo_static/console/console.mipseb && \
  mv /igloo_static/console/console-mips64eb-linux-musl /igloo_static/console/console.mips64eb

# Download 4.10_hc kernels from CI. Populate /igloo_static/kernels
RUN wget -qO - https://github.com/panda-re/linux_builder/releases/download/v1.6/kernels-latest.tar.gz | \
      tar xzf - -C /igloo_static

# Download VPN from CI pushed to panda.re. Populate /igloo_static/vpn
# XXX this dependency should be versioned!
RUN wget -qO - https://panda.re/igloo/vpn.tar.gz | \
  tar xzf - -C /

# Download custom panda plugins built from CI. Populate /panda_plugins
RUN mkdir /panda_plugins && \
  wget -qO - https://panda.re/igloo/penguin_plugins_v1.3.1.tar.gz | \
  tar xzf - -C /panda_plugins

RUN mkdir /static_deps && \
  wget -qO - https://panda.re/secret/utils4.tar.gz | \
  tar xzf - -C /static_deps

#### QEMU BUILDER: Build qemu-img ####
FROM ubuntu:20.04 as qemu_builder
ENV DEBIAN_FRONTEND=noninteractive
# Enable source repos
RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update && apt-get build-dep -y qemu-utils qemu && \
    apt-get install -q -y --no-install-recommends ninja-build git
RUN git clone --depth 1 https://github.com/panda-re/qemu.git /src
RUN mkdir /src/build && cd /src/build && ../configure --disable-user --disable-system --enable-tools \
    --disable-capstone --disable-guest-agent && \
  make -j$(nproc)

### MAIN CONTAINER ###
FROM ubuntu:20.04 as penguin
# Environment setup
ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""

# Add rootshell helper command
RUN echo "#!/bin/sh\ntelnet localhost 4321" > /usr/local/bin/rootshell && chmod +x /usr/local/bin/rootshell

COPY --from=deb_downloader /tmp/pandare.deb /tmp/genext2fs.deb /tmp/

# Install apt dependencies - largely for binwalk, some for pandata
RUN apt-get update && apt-get install -y \
    fakechroot \
    fakeroot \
    firefox \
    git \
    libarchive13 \
    libguestfs-tools \
    nmap \
    openjdk-11-jdk \
    python3 \
    python3-guestfs \
    python3-pip \
    telnet \
    vim \
    wget && \
    apt install -yy -f /tmp/pandare.deb /tmp/genext2fs.deb && \
    rm /tmp/pandare.deb /tmp/genext2fs.deb

# Python dependencies including binwalk and pypanda-plugins
# do not combine lzo and vmlinux-to-elf, they conflict
RUN python3 -m pip install \
      angr \
      beautifulsoup4 \
      coloredlogs \
      git+https://github.com/AndrewFasano/angr-targets.git@af_fixes \
      html5lib \
      http://panda.re/secret/pandare-0.1.2.0.tar.gz \
      lief  \
      lxml \
      lz4 \
      matplotlib \
      pandas \
      pyelftools \
      python-owasp-zap-v2.4 \
      python_hosts \
      pyyaml \
      jsonschema \
      setuptools \
      twisted

# ZAP setup
#COPY --from=downloader /zap /zap
#RUN /zap/zap.sh -cmd -silent -addonupdate -addoninstallall && \
#    cp /root/.ZAP/plugin/*.zap /zapplugin/ || :
#
## Install JAVA for ZAP
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

# Copy utils.source (scripts) and utils.bin (binaries) from host
# Files are named util.[arch] or util.all
COPY --from=downloader /static_deps/utils/* /igloo_static/utils.bin
COPY utils/* /igloo_static/utils.source/

WORKDIR /penguin

# Aliases for quick tests. m to make a config for the stride. r to run it. a for auto (config+run+explore)
RUN echo 'alias m="rm -rf /results/stride; penguin /fws/stride.tar.gz /results/stride/"' >> ~/.bashrc
RUN echo 'alias r="penguin --config /results/stride/config.yaml /results/stride/out"' >> ~/.bashrc
RUN echo 'alias a="rm -rf /results/stride_auto; penguin --niters 5 --singlecore /fws/stride.tar.gz /results/stride_auto/"' >> ~/.bashrc

# Now copy in our module and install it
# Editable so we can mount local copy for dev
COPY ./penguin /pkg
RUN python3 -m pip install -e /pkg

# Workaround for igloo #131
RUN pip install setuptools==67.7.2

# Copy pyplugins into our the pandata directory. We might mount
# this from the host during development. In the long term we'll
# merge these into the main penguin module
COPY ./pyplugins/ /pandata
