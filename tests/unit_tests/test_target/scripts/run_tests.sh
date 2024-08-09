#!/igloo/utils/sh
for f in /tests/*; do
  TEST_NAME=$(/igloo/utils/busybox basename $f)
  TEST_RESULTS_DIR=/igloo/shared/tests/$TEST_NAME/
  /igloo/utils/busybox mkdir -p $TEST_RESULTS_DIR

  echo "Running test $TEST_NAME"
  STDERR=$TEST_RESULTS_DIR/stderr
  STDOUT=$TEST_RESULTS_DIR/stdout

  if $f > $STDOUT 2> $STDERR; then
    echo "$f PASS"
  else
    echo "$f FAIL"
  fi
done
exit 0