./autogen.sh

CURL_PREFIX=/usr/local
SSL_PREFIX=/usr/local/ssl

# gcc 4.4
extracflags="-O3 -march=native -Wall -D_REENTRANT -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# gcc 4.8+
extracflags="$extracflags -Ofast -fuse-linker-plugin -ftlo -ftree-loop-if-convert-stores"

CFLAGS="-DCURL_STATICLIB -DOPENSSL_NO_ASM -DUSE_ASM $extracflags"

./configure --build=x86_64-w64-mingw32 --with-crypto=$SSL_PREFIX --with-curl=$CURL_PREFIX CFLAGS="$CFLAGS -Dsize_t=uint32_t"

make
