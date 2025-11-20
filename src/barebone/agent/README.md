## Getting the C toolchain

    npm install -g xpm
    xpm install
    export PATH=$PWD/xpacks/.bin:$PATH

## How to build Gum

    ./configure \
        --host=aarch64-none-elf \
        --enable-gumjs \
        --with-devkits=gum,gumjs \
        --with-devkit-symbol-scope=original
    make
    export GUMJS_DEVKIT_DIR=$PWD/build/bindings/gumjs/devkit

## Building

    export PATH=$PWD/xpacks/.bin:$PATH
    export CC_aarch64_unknown_none=aarch64-none-elf-gcc
    export AR_aarch64_unknown_none=aarch64-none-elf-ar
    export RANLIB_aarch64_unknown_none=aarch64-none-elf-ranlib

## Development loop

    export PLAWNEKJX_BAREBONE_CONFIG=$PWD/etc/xnu.json
    cargo build --release && make -C ~/src/plawnekjx-python && killall -9 qemu-system-aarch64 && sleep 2 && plawnekjx -D barebone -p 0

## Speeding up loop

    ./configure \
        -- \
        -Dplawnekjx-core:compat=disabled \
        -Dplawnekjx-core:local_backend=disabled \
        -Dplawnekjx-core:fruity_backend=disabled \
        -Dplawnekjx-core:droidy_backend=disabled \
        -Dplawnekjx-core:socket_backend=disabled \
        -Dplawnekjx-core:compiler_backend=disabled \
        -Dplawnekjx-core:gadget=disabled \
        -Dplawnekjx-core:server=disabled \
        -Dplawnekjx-core:portal=disabled \
        -Dplawnekjx-core:inject=disabled \
        -Dplawnekjx-core:tests=enabled
