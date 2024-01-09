#!/bin/bash
set -euo pipefail

run_test() {
  local kernel_version=$1
  local arch=$2
  local test_name=$3
  local assertion=$4

  if [ ! -d "$test_name" ]; then
    echo "Test $test_name does not exist"
    exit 1
  fi

  echo "Testing $test_name on kernel version $kernel_version with architecture $arch..."
  # If docker run fails, print log and bail
  docker run --rm -t -v "$(pwd)":/tests pandare/igloo:penguin \
    /tests/_in_container_run.sh "$kernel_version" "$arch" "$test_name" > log.txt || (tail log.txt && exit 1)

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

assert_shared_dir() {
  grep -q 'Hello from guest!' results/shared/from_guest.txt
}

mkdir -p results qcows

kernel_versions=("4.10" "6.7")
archs=("armel" "mipsel" "mipseb")
tests=("env_unset" "env_cmp" "pseudofile_missing" "pseudofile_ioctl" "shared_dir")

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

for kernel_version in "${kernel_versions[@]}"; do
for arch in "${archs[@]}"; do
  # For each test, check if it's in the list of tests to run
  if [[ ! " ${tests[@]} " =~ " env_unset " ]]; then
    echo "Skipping env_unset test for $arch"
  else
    run_test "$kernel_version" "$arch" "env_unset" assert_env_unset
  fi

  if [[ ! " ${tests[@]} " =~ " env_cmp " ]]; then
    echo "Skipping env_cmp test for $arch"
  else
    run_test "$kernel_version" "$arch" "env_cmp" assert_env_cmp
  fi

  if [[ ! " ${tests[@]} " =~ " pseudofile_missing " ]]; then
    echo "Skipping pseudofile_missing test for $arch"
  else
    run_test "$kernel_version" "$arch" "pseudofile_missing" assert_pseudofiles_missing
  fi

  if [[ ! " ${tests[@]} " =~ " pseudofile_ioctl " ]]; then
    echo "Skipping pseudofile_ioctl test for $arch"
  else
    run_test "$kernel_version" "$arch" "pseudofile_ioctl" assert_pseudofiles_ioctl
  fi

  if [[ ! " ${tests[@]} " =~ " hostfile " ]]; then
    echo "Skipping hostfile test for $arch"
  else
    run_test "$kernel_version" "$arch" "hostfile" assert_ps_output
  fi

  if [[ ! " ${tests[@]} " =~ " shared_dir " ]]; then
    echo "Skipping shared_dir test for $arch"
  else
    run_test "$kernel_version" "$arch" "shared_dir" assert_shared_dir
  fi
done
done
