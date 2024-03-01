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
  docker run --rm -it -v "$(pwd)":/tests pandare/igloo:penguin \
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

assert_uboot_env_cmp() {
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

assert_all_good() {
  grep -q 'All good' results/console.log
}

assert_mtd_detect() {
  grep -q  'read' results/pseudofiles_proc_mtd.txt
}

assert_mtd_found() {
  grep -q "flash" results/env_mtd.txt && assert_all_good
}

assert_bash() {
  grep -q '/init,5,1,"echo ""Hello from $0 $@"""' results/bash_cov.csv && \
    grep -q '/init,6,1,for x in a b c d' results/bash_cov.csv && \
    grep -q '/init,7,1,echo $x' results/bash_cov.csv && \
    ! grep -q 'source' results/bash_cov.csv
}

mkdir -p results qcows

kernel_versions=("4.10" "6.7")
archs=("armel" "mipsel" "mipseb")
tests=("env_unset" "env_cmp" "uboot_env_cmp" "pseudofile_missing" "pseudofile_ioctl" "hostfile" "shared_dir" "proc_mtd" "proc_mtd_missing")

# We can run a single architecture or a single test.
# For example:
#   ./test.sh 4.10 armel
#   ./test.sh 4.10 armel env_cmp

if [ $# -eq 3 ]; then
  kernel_versions=("$1")
  archs=("$2")
  tests=("$3")
elif [ $# -eq 2 ]; then
  kernel_versions=("$1")
  archs=("$2")
elif [ $# -eq 1 ]; then
  kernel_versions=("$1")
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

  if [[ ! " ${tests[@]} " =~ " uboot_env_cmp " ]]; then
    echo "Skipping uboot_env_cmp test for $arch"
  else
    run_test "$kernel_version" "$arch" "uboot_env_cmp" assert_uboot_env_cmp
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

  if [[ ! " ${tests[@]} " =~ " pseudofile_devfs " ]]; then
    echo "Skipping pseudofile_devfs test for $arch"
  else
    run_test "$kernel_version" "$arch" "pseudofile_devfs" assert_ps_output
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

  if [[ ! " ${tests[@]} " =~ " proc_mtd " ]]; then
    echo "Skipping proc_mtd test for $arch"
  else
    run_test "$kernel_version" "$arch" "proc_mtd" assert_all_good
  fi

  if [[ ! " ${tests[@]} " =~ " proc_mtd_missing " ]]; then
    echo "Skipping proc_mtd_missing test for $arch"
  else
    run_test "$kernel_version" "$arch" "proc_mtd_missing" assert_mtd_detect
  fi

  # Disabled by default - never worked
  if [[ ! " ${tests[@]} " =~ " proc_mtd_dynamic " ]]; then
    echo "Skipping proc_mtd_dynamic test for $arch"
  else
    run_test "$kernel_version" "$arch" "proc_mtd_dynamic" assert_mtd_found
  fi

  if [[ ! " ${tests[@]} " =~ " pseudofile_sysfs " ]]; then
    echo "Skipping pseudofile_sysfs test for $arch"
  else
    run_test "$kernel_version" "$arch" "pseudofile_sysfs" assert_ps_output
  fi

  if [[ ! " ${tests[@]} " =~ " bash " ]]; then
    echo "Skipping bash test for $arch"
  else
    run_test "$kernel_version" "$arch" "bash" assert_bash
  fi

done
done
