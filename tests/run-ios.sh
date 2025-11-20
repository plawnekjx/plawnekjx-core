#!/bin/sh

arch=arm64e

remote_host=iphone
remote_prefix=/usr/local/opt/plawnekjx-tests-$arch

core_tests=$(cd $(dirname "$0") && pwd)

make -C .. build/.core-ios-stamp-plawnekjx-ios-$arch

cd "$core_tests/../../build/tmp-ios-$arch/plawnekjx-core" || exit 1

. ../../plawnekjx-env-macos-x86_64.rc
ninja || exit 1

cd tests

ssh "$remote_host" "mkdir -p '$remote_prefix'"
rsync -rLz \
  plawnekjx-tests \
  labrats \
  ../lib/agent/plawnekjx-agent.dylib \
  ../../../plawnekjx-ios-arm64e/lib/plawnekjx-gadget.dylib \
  "$core_tests/test-gadget-standalone.js" \
  "$remote_host:$remote_prefix/" || exit 1

ssh "$remote_host" "$remote_prefix/plawnekjx-tests" "$@"
