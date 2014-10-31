#!/bin/bash

# Linux build (Ubuntu 14.04)

make clean || echo clean

rm -f config.status
./autogen.sh || echo done

extracflags="-march=native -Ofast -Wall -D_REENTRANT -flto -fuse-linker-plugin -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

./configure --with-crypto --with-curl CFLAGS="$extracflags"

make -j 4
