#!/usr/bin/env bash

set -euvx
set -o pipefail

TEST_INPUT=$1

TEST_NAME=$(basename $TEST_INPUT)

case "$TEST_NAME" in
    slip-*)
	TEST_PROG=./libslip-test;;
    queue-*)
	TEST_PROG=./queue-test;;
esac

$TEST_PROG < $TEST_INPUT
exit $?
