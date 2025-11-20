#!/bin/sh

arch=x86_64

plawnekjx_tests=$(dirname "$0")
cd "$plawnekjx_tests/../../build/tmp_thin-linux-$arch/plawnekjx-core" || exit 1
. ../../plawnekjx_thin-env-linux-x86_64.rc
ninja || exit 1
tests/plawnekjx-tests "$@"
