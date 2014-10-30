./autogen.sh

CURL_PREFIX=/usr/local
SSL_PREFIX=/usr/local/ssl

CFLAGS="-O3 -DCURL_STATICLIB -DOPENSSL_NO_ASM"

./configure --build=x86_64-w64-mingw32 --with-crypto=$SSL_PREFIX --with-curl=$CURL_PREFIX CFLAGS="$CFLAGS"
