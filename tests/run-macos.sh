#!/bin/sh

arch=x86_64

plawnekjx_tests=$(dirname "$0")
cd "$plawnekjx_tests/../../build/tmp-macos-$arch/plawnekjx-core" || exit 1
. ../../plawnekjx-env-macos-x86_64.rc
ninja || exit 1
tests/plawnekjx-tests "$@"
