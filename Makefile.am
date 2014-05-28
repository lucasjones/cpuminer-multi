
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

AUTOMAKE_OPTIONS= subdir-objects
ACLOCAL_AMFLAGS = -I .

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

AM_CPPFLAGS	= $(PTHREAD_FLAGS) $(JANSSON_INCLUDES)
AM_CFLAGS	= -O3 -Ofast -flto -fuse-linker-plugin -funroll-loops -fsplit-ivs-in-unroller -fvariable-expansion-in-unroller -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16

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
		  cryptonight_common.c \
		  x11.c \
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
		  crypto/oaes_lib.c \
		  crypto/c_keccak.c \
		  crypto/c_groestl.c \
		  crypto/c_blake256.c \
		  crypto/c_jh.c \
		  crypto/c_skein.c \
		  crypto/hash.c \
		  crypto/aesb.c
if ARCH_x86
minerd_SOURCES += sha2-x86.S scrypt-x86.S aesb-x86.S
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S scrypt-x64.S aesb-x64.S
endif
if USE_LOBOTOMIZED_AES
minerd_SOURCES += cryptonight_lobotomized.c
else
minerd_SOURCES += cryptonight_aesni.c aesni.S
AM_CFLAGS += -maes
endif

if ARCH_ARM
minerd_SOURCES += sha2-arm.S scrypt-arm.S
endif
minerd_LDFLAGS	= $(AM_LDFLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = $(AM_CPPFLAGS) @LIBCURL_CPPFLAGS@
minerd_CFLAGS   = $(AM_CFLAGS)

if HAVE_WINDOWS
minerd_CFLAGS += -Wl,--stack,10485760
endif
