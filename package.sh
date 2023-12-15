#!/bin/bash

# This script should run in the pandadev container
# to create .so files for the relevant plugins and copy in all the pyplugins

# The repo is mounted at /app

# Our compiled plugins directory clobbers the plugin list
# to just have the ones we want

cp -r /app/compiled_plugins/* /panda/panda/plugins/
make -j$(nproc) -C /panda/build

SCRATCH=$(mktemp -d)

for f in /app/compiled_plugins/*; do
  if [ ! -d $f ]; then continue; fi
  plugin=$(basename $f)

  for archpath in /panda/build/*-softmmu; do
    arch=$(basename $archpath | sed 's/-softmmu//')
    plugin_path=/panda/build/${arch}-softmmu/panda/plugins/panda_${plugin}.so
    mkdir -p "$SCRATCH/compiled/$arch"

    if [ -e $plugin_path ]; then
      cp "$plugin_path" "$SCRATCH/compiled/$arch"
    fi
  done
done

# Copy
mkdir $SCRATCH/pyplugins
cp pyplugins/*.py $SCRATCH

# Archive
tar cvfz /app/penguin_plugins.tar.gz -C $SCRATCH .

