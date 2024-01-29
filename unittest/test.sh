#!/bin/bash
set -euo pipefail

run_test() {
  local arch=$1
  local test_name=$2
  local assertion=$3

  if [ ! -d "$test_name" ]; then
    echo "Test $test_name does not exist"
    exit 1
  fi

  echo "Testing $test_name on architecture $arch..."
  # If docker run fails, print log and bail
  docker run --rm -it -v "$(pwd)":/tests pandare/igloo:penguin \
    /tests/_in_container_run.sh "$arch" "$test_name" > log.txt || (tail log.txt && exit 1)

  echo -n "$test_name: "
  if $assertion; then
    echo "PASS"
  else
    echo "FAIL"
    echo
    echo "Failure log:"
    tail -n10 log.txt
    echo
    echo "console log:"
    tail -n10 results/console.log
    echo
    echo
  fi
}

assert_env_unset() {
  cat results/shell_env.csv
  grep -q "('envvar', None)" results/shell_env.csv
}

assert_env_cmp() {
  grep -q 'target' results/env_cmp.txt
}

assert_ps_output() {
  grep -q '\[bioset\]' results/console.log
}

assert_pseudofiles_missing() {
  python3 -c "import yaml; \
              f = open('results/pseudofiles_failures.yaml'); \
              assert yaml.safe_load(f)['/dev/missing'] is not None"
}

assert_pseudofiles_ioctl() {
  python3 -c "import yaml; \
              f = open('results/pseudofiles_failures.yaml'); \
              data = yaml.safe_load(f); \
              assert 'ioctl' in data['/dev/missing'] and \
                      data['/dev/missing']['ioctl'][799]['count'] > 0"
}

mkdir -p results qcows

archs=("armel" "mipsel" "mipseb")
tests=("env_unset" "env_cmp" "pseudofile_missing" "pseudofile_ioctl")

# We can run a single architecture or a single test.
# For example:
#   ./test.sh armel
#   ./test.sh armel env_cmp

if [ $# -eq 2 ]; then
  archs=("$1")
  tests=("$2")
elif [ $# -eq 1 ]; then
  archs=("$1")
fi

for arch in "${archs[@]}"; do
  # For each test, check if it's in the list of tests to run
  if [[ ! " ${tests[@]} " =~ " env_unset " ]]; then
    echo "Skipping env_unset test for $arch"
  else
    run_test "$arch" "env_unset" assert_env_unset
  fi

  if [[ ! " ${tests[@]} " =~ " env_cmp " ]]; then
    echo "Skipping env_cmp test for $arch"
  else
    run_test "$arch" "env_cmp" assert_env_cmp
  fi

  if [[ ! " ${tests[@]} " =~ " pseudofile_missing " ]]; then
    echo "Skipping pseudofile_missing test for $arch"
  else
    run_test "$arch" "pseudofile_missing" assert_pseudofiles_missing
  fi

  if [[ ! " ${tests[@]} " =~ " pseudofile_ioctl " ]]; then
    echo "Skipping pseudofile_ioctl test for $arch"
  else
    run_test "$arch" "pseudofile_ioctl" assert_pseudofiles_ioctl
  fi

  if [[ ! " ${tests[@]} " =~ " hostfile " ]]; then
    echo "Skipping hostfile test for $arch"
  else
    run_test "$arch" "hostfile" assert_ps_output
  fi
done
