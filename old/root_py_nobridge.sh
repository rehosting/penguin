#!/bin/bash

set -eux
NAMESPACE=panda
. /home/andrew/git/panda/panda/python/venv/bin/activate

python $1
