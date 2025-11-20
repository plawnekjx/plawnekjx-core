#!/bin/bash

# This script is responsible for building Plawnekjx helpers for various Linux
# architectures. It can build helpers for a single specified architecture on the
# local machine, or for supported architectures in a container. The script uses
# Docker containers to ensure consistent build environments for each
# architecture.
#
# Note that the expectation is that when running the build for a specific
# architecture that it be run from inside the relevant container. This script is
# used by CI.

set -euo pipefail

CURRENT_FILE="${BASH_SOURCE[0]}"
HELPERS_DIR="$(cd "$(dirname "$CURRENT_FILE")" && pwd)"
PLAWNEKJX_CORE_DIR="$(cd "$HELPERS_DIR/../../.." && pwd)"
RELENG_DIR="$PLAWNEKJX_CORE_DIR/releng"
BUILD_DIR="$PLAWNEKJX_CORE_DIR/build"
RELATIVE_TO_PLAWNEKJX_CORE_DIR=$(realpath --relative-to="$PLAWNEKJX_CORE_DIR" "$CURRENT_FILE")

TMP_MESON_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_MESON_DIR"' EXIT

CONTAINER_REGISTRY="${CONTAINER_REGISTRY:-ghcr.io/plawnekjx}"

main () {
  if [ "$#" -eq 0 ]; then
    build_arches_in_container
    return
  fi

  if [ "$#" -gt 1 ]; then
    echo >&2 "Error: Too many arguments"
    usage
  fi

  build_arch "$1"
}

usage () {
  echo >&2 "Usage: $0 [<arch>]"
  echo >&2 "If no arch is specified, then all helpers will be built in the container."
  exit 1
}

ARCHS=(
  x86
  x86_64
  arm
  armbe8
  arm64
  arm64be
  arm64beilp32
  mips
  mipsel
  mips64
  mips64el
)

build_arch () {
  ARCH=$1
  if [ -z "$ARCH" ]; then
    usage
  fi
  if ! printf '%s\n' "${ARCHS[@]}" | grep -qx "$ARCH"; then
    echo >&2 "Error: Invalid architecture '$ARCH'"
    echo >&2 "Supported architectures: ${ARCHS[*]}"
    exit 1
  fi

  case "$ARCH" in
  arm | arm64)
    export PLAWNEKJX_HOST=android-$ARCH
    ;;
  *)
    export PLAWNEKJX_HOST=linux-$ARCH
    ;;
  esac

  EXTRA_FLAGS=()
  if [ "$PLAWNEKJX_HOST" == "linux-x86" ]; then
    EXTRA_FLAGS+=("--build=linux-x86")
    export CC="gcc -m32" CXX="g++ -m32" STRIP="strip"
  fi

  cd "$PLAWNEKJX_CORE_DIR"

  rm -rf "$BUILD_DIR"
  # Note that $XTOOLS_HOST is set by the container.
  ./configure --host="$XTOOLS_HOST" "${EXTRA_FLAGS[@]}"
  make -C src/linux/helpers
}

build_arches_in_container () {
  for ARCH in "${ARCHS[@]}"; do
    docker run -u "$(id -u):$(id -g)" \
      -w /plawnekjx-core \
      -i -t \
      -v "$PLAWNEKJX_CORE_DIR:/plawnekjx-core" \
      "$CONTAINER_REGISTRY/core-linux-helpers-$ARCH:latest" \
      "/plawnekjx-core/$RELATIVE_TO_PLAWNEKJX_CORE_DIR" "$ARCH"
  done
}

main "$@"
