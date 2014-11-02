
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= @PTHREAD_FLAGS@ -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES = \
  cpu-miner.c util.c \
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
  crypto/blake2s \
  crypto/oaes_lib.c \
  crypto/c_keccak.c \
  crypto/c_groestl.c \
  crypto/c_blake256.c \
  crypto/c_jh.c \
  crypto/c_skein.c \
  crypto/hash.c \
  crypto/aesb.c \
  blake.c \
  cryptonight.c \
  fresh.c \
  heavy.c \
  ink.c \
  keccak.c \
  pentablake.c \
  quark.c \
  neoscrypt.c \
  nist5.c \
  qubit.c \
  scrypt.c sha2.c \
  skein.c \
  s3.c \
  x11.c \
  x13.c \
  x14.c \
  x15.c

if USE_ASM
   minerd_SOURCES += neoscrypt_asm.S
if ARCH_x86
   minerd_SOURCES += sha2-x86.S scrypt-x86.S aesb-x86.S crypto/aesb-x86-impl.c
endif
if ARCH_x86_64
   minerd_SOURCES += sha2-x64.S scrypt-x64.S aesb-x64.S
endif
if ARCH_ARM
   minerd_SOURCES += sha2-arm.S scrypt-arm.S
endif
endif

if HAVE_WINDOWS
   minerd_SOURCES += compat/winansi.c
endif

minerd_LDFLAGS	= @LDFLAGS@
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@
minerd_CFLAGS   = -Wno-pointer-sign -Wno-pointer-to-int-cast

if HAVE_WINDOWS
minerd_CFLAGS += -Wl,--stack,10485760
endif

if HAVE_WINDOWS
# use to profile an object
# gprof_cflags = -pg -g3
# minerd_LDFLAGS += -pg
# minerd_CFLAGS += -fno-inline-functions -static

# copy/paste from generated Makefile
common_ccflags = $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(minerd_CPPFLAGS) $(CPPFLAGS) $(minerd_CFLAGS) $(CFLAGS)

# special CFLAGS (if you find a simpler way to do that tell me ;)
minerd-neoscrypt.o: neoscrypt.c
	@echo "CUSTOM ${@}: ${filter %.o,${^}} ${filter %.c,${^}}"
	$(CC) $(common_ccflags) -g -O3 $(gprof_cflags) -MT $@ -MD -MP -c -o $@ $<


endif
