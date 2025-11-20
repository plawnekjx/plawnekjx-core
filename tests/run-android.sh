#!/bin/sh

remote_prefix=/data/android/plawnekjx/plawnekjx-core-tests

set -e

core_tests=$(dirname "$0")
cd "$core_tests/../"
make
cd build/tests
adb shell "mkdir -p $remote_prefix"
adb push plawnekjx-tests labrats ../lib/agent/plawnekjx-agent.so $remote_prefix
adb shell "su -c '$remote_prefix/plawnekjx-tests $@'"
