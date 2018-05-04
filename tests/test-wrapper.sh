#!/usr/bin/env bash

set -euvx
set -o pipefail

TEST_PROG=./libslip-test
TEST_INPUT=$1

$TEST_PROG < $TEST_INPUT
exit $?
