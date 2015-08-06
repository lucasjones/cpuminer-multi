
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h \
		  miner.h \
		  compat.h \
		  cpu-miner.c \
		  util.c \
		  sha2.c \
		  scrypt.c \
		  keccak.c \
		  heavy.c \
		  quark.c \
		  skein.c \
		  ink.c \
		  blake.c \
		  cryptonight.c \
		  fresh.c \
		  x11.c \
		  x13.c \
		  x14.c \
		  x15.c \
		  sha3/sph_keccak.c \
		  sha3/sph_hefty1.c \
		  sha3/sph_groestl.c \
		  sha3/sph_skein.c \
		  sha3/sph_bmw.c \
		  sha3/sph_jh.c \
		  sha3/sph_shavite.c \
		  sha3/sph_blake.c \
		  sha3/sph_luffa.c \
		  sha3/sph_cubehash.c \
		  sha3/sph_simd.c \
		  sha3/sph_echo.c \
		  sha3/sph_hamsi.c \
		  sha3/sph_fugue.c \
		  sha3/sph_shabal.c \
		  sha3/sph_whirlpool.c \
		  crypto/oaes_lib.c \
		  crypto/c_keccak.c \
		  crypto/c_groestl.c \
		  crypto/c_blake256.c \
		  crypto/c_jh.c \
		  crypto/c_skein.c \
		  crypto/hash.c \
		  crypto/aesb.c
if USE_ASM
if ARCH_x86
minerd_SOURCES += sha2-x86.S scrypt-x86.S aesb-x86.S crypto/aesb-x86-impl.c
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S scrypt-x64.S aesb-x64.S
endif
if ARCH_ARM
minerd_SOURCES += sha2-arm.S scrypt-arm.S aesb-arm.S crypto/aesb-x86-impl.c
endif
endif

minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@
minerd_CFLAGS   = -Ofast -flto -fuse-linker-plugin
