#!/bin/bash
set -euo pipefail

run_test() {
  local kernel_version=$1
  local arch=$2
  local test_name=$3
  local assertion=$4
  local n_iters=${5:-20}

  if [ ! -d "$test_name" ]; then
    echo "Test $test_name does not exist"
    exit 1
  fi

  rm -rf results
  # Fake "static analysis" gives us 2 inits to consider
  mkdir -p results/base/
  echo -e 'igloo_init:\n- /init\n- /notinit' > results/base/env.yaml

  echo "Testing $test_name on architecture $arch..."
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
  fi
}


assert_pseudofiles() {
  # First check:  did we get multiple runs?
  # This function should return false on errors.
  if [ ! -e results/runs/2/config.yaml ]; then
    return 1; # Error
   fi
  # Next: find the output with the most coverage, did we run ps in it?
   if $(grep -q '/igloo/utils/busybox ps' $(dirname $(wc -l results/runs/*/output/coverage.csv  | head -n-1 | \
          sort -n | tail -n1 | col2))/console.log); then
     return 0
   else
    return 1; # error
   fi
}

assert_multirun_ranps() {
  # First check:  did we get multiple runs?
  # This function should return false on errors.
  if [ ! -e results/runs/2/config.yaml ]; then
    return 1; # Error
   fi
  # Next: find the output with the most coverage, did we run ps in it?
   if $(grep -q '/igloo/utils/busybox ps' $(dirname $(wc -l results/runs/*/output/coverage.csv  | head -n-1 | \
          sort -n | tail -n1 | col2))/console.log); then
     return 0
   else
    return 1; # error
   fi
}

assert_combined() {
  # First check:  did we get multiple runs?
  # This function should return false on errors.
  if [ ! -e results/runs/2/config.yaml ]; then
    return 1; # Error
   fi

   # Next: find the output with the most coverage
   best_cov=$(dirname $(wc -l results/runs/*/output/coverage.csv  | head -n-1 | sort -n | tail -n1 | col2))

   # Did we run PS
   if ! $(grep -q '/igloo/utils/busybox ps' ${best_cov}/console.log); then
    return 1; # error
   fi

   # Did config have 'envone: target', 'envtwo: magic' and 'igloo_init: /init' in env?
    if ! $(grep -q 'igloo_init: /init' ${best_cov}/core_config.yaml); then
      return 1; # error
    fi
    if ! $(grep -q 'envone: target' ${best_cov}/core_config.yaml); then
      return 1; # error
    fi
    if ! $(grep -q 'envtwo: magic' ${best_cov}/core_config.yaml); then
      return 1; # error
    fi
}

rm -rf qcows
mkdir -p qcows

archs=("armel" "mipsel" "mipseb")
tests=( "multiinit" "pseudofile" "env" "combined")

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

kernel_versions=("4.10" "6.7")
for kernel_version in "${kernel_versions[@]}"; do
for arch in "${archs[@]}"; do

  if [[ ! " ${tests[@]} " =~ " pseudofile " ]]; then
    echo "Skipping pseudofile test for $arch"
  else
    run_test "$kernel_version" "$arch" "pseudofile" assert_pseudofiles
  fi

  if [[ ! " ${tests[@]} " =~ " multiinit " ]]; then
    echo "Skipping multiinit test for $arch"
  else
    run_test "$kernel_version" "$arch" "multiinit" assert_multirun_ranps
  fi

  if [[ ! " ${tests[@]} " =~ " env " ]]; then
    echo "Skipping env test for $arch"
  else
    run_test "$kernel_version" "$arch" "env" assert_multirun_ranps
  fi

  if [[ ! " ${tests[@]} " =~ " combined " ]]; then
    echo "Skipping combined test for $arch"
  else
    run_test "$kernel_version" "$arch" "combined" assert_multirun_ranps 40
  fi

  if [[ ! " ${tests[@]} " =~ " search_min " ]]; then
    echo "Skipping search_min test for $arch"
  else
    run_test "$kernel_version" "$arch" "search_min" assert_combined 40
  fi

  if [[ ! " ${tests[@]} " =~ " search " ]]; then
    echo "Skipping search test for $arch"
  else
    run_test "$kernel_version" "$arch" "search" assert_combined 40
  fi
done
done
