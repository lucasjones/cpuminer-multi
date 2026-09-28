
EXTRA_DIST	= autogen.sh example-cfg.json README.md LICENSE Dockerfile \
		  sha3/aes_helper.c sha3/sph_hamsi_helper.c sha3/sph_x15_helper.c \
		  yespower/yespower-platform.c yespower/README.cpuminer

noinst_HEADERS	= compat.h elist.h miner.h neoscrypt-mix.h \
		  crypto/c_blake256.h crypto/c_groestl.h crypto/c_jh.h \
		  crypto/c_keccak.h crypto/c_skein.h crypto/groestl_tables.h \
		  crypto/hash-ops.h crypto/hash.h crypto/int-util.h \
		  crypto/skein_port.h \
		  sha3/sph_blake.h sha3/sph_bmw.h sha3/sph_cubehash.h \
		  sha3/sph_echo.h sha3/sph_fugue.h sha3/sph_groestl.h \
		  sha3/sph_hamsi.h sha3/sph_jh.h sha3/sph_keccak.h \
		  sha3/sph_luffa.h sha3/sph_shabal.h sha3/sph_shavite.h \
		  sha3/sph_simd.h sha3/sph_skein.h sha3/sph_types.h \
		  sha3/sph_whirlpool.h \
		  yespower/insecure_memzero.h yespower/sha256.h \
		  yespower/sysendian.h yespower/yespower.h

AM_CPPFLAGS	= $(JANSSON_CFLAGS) $(LIBCURL_CFLAGS)
AM_CFLAGS	= $(PTHREAD_FLAGS) -fno-strict-aliasing
AM_CXXFLAGS	= $(PTHREAD_FLAGS)

# All proof-of-work code lives in one library so that the miner and the
# test programs link exactly the same objects.
noinst_LIBRARIES = libalgos.a

libalgos_a_SOURCES = \
		  sha2.c \
		  scrypt.c \
		  keccak.c \
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
		  qubit.c \
		  odocrypt.c \
		  neoscrypt.c \
		  argon2d.c \
		  yescrypt.c \
		  rx.c \
		  verthash.c \
		  yespower/yespower-opt.c \
		  yespower/sha256.c \
		  cpu-features.c \
		  sha3/sph_keccak.c \
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
		  crypto/c_keccak.c \
		  crypto/c_groestl.c \
		  crypto/c_blake256.c \
		  crypto/c_jh.c \
		  crypto/c_skein.c \
		  crypto/hash.c \
		  crypto/aesb.c

if USE_ASM
if ARCH_x86
libalgos_a_SOURCES += sha2-x86.S scrypt-x86.S
endif
if ARCH_x86_64
libalgos_a_SOURCES += sha2-x64.S scrypt-x64.S
endif
if ARCH_ARM
libalgos_a_SOURCES += sha2-arm.S scrypt-arm.S
endif
endif

# RandomX (Monero): tevador's library, in C++ (see randomx/README.cpuminer).
# rx.c, in libalgos.a, is the miner's side of it.
EXTRA_DIST	+= randomx/LICENSE randomx/README.cpuminer \
		  randomx/asm/program_epilogue_linux.inc \
		  randomx/asm/program_epilogue_store.inc \
		  randomx/asm/program_epilogue_win64.inc \
		  randomx/asm/program_loop_load.inc \
		  randomx/asm/program_loop_store.inc \
		  randomx/asm/program_loop_store_hard_aes.inc \
		  randomx/asm/program_loop_store_soft_aes.inc \
		  randomx/asm/program_prologue_linux.inc \
		  randomx/asm/program_prologue_win64.inc \
		  randomx/asm/program_read_dataset.inc \
		  randomx/asm/program_read_dataset_sshash_fin.inc \
		  randomx/asm/program_read_dataset_sshash_init.inc \
		  randomx/asm/program_read_dataset_sshash_init_v2.inc \
		  randomx/asm/program_read_dataset_v2.inc \
		  randomx/asm/program_soft_aes_dec.inc \
		  randomx/asm/program_soft_aes_enc.inc \
		  randomx/asm/program_sshash_constants.inc \
		  randomx/asm/program_sshash_load.inc \
		  randomx/asm/program_sshash_prefetch.inc \
		  randomx/asm/program_xmm_constants.inc \
		  randomx/asm/randomx_reciprocal.inc

noinst_HEADERS	+= randomx/aes_hash.hpp randomx/aes_hash_rv64_vector.hpp \
		  randomx/aes_hash_rv64_zvkned.hpp randomx/allocator.hpp \
		  randomx/argon2.h randomx/argon2_core.h \
		  randomx/assembly_generator_x86.hpp randomx/blake2/blake2-impl.h \
		  randomx/blake2/blake2.h randomx/blake2/blamka-round-avx2.h \
		  randomx/blake2/blamka-round-ref.h randomx/blake2/blamka-round-ssse3.h \
		  randomx/blake2/endian.h randomx/blake2_generator.hpp \
		  randomx/bytecode_machine.hpp randomx/common.hpp \
		  randomx/configuration.h randomx/cpu.hpp randomx/dataset.hpp \
		  randomx/instruction.hpp randomx/instruction_weights.hpp \
		  randomx/intrin_portable.h randomx/jit_compiler.hpp \
		  randomx/jit_compiler_a64.hpp randomx/jit_compiler_a64_static.hpp \
		  randomx/jit_compiler_fallback.hpp randomx/jit_compiler_rv64.hpp \
		  randomx/jit_compiler_rv64_static.hpp \
		  randomx/jit_compiler_rv64_vector.h \
		  randomx/jit_compiler_rv64_vector_static.h \
		  randomx/jit_compiler_x86.hpp randomx/jit_compiler_x86_static.hpp \
		  randomx/program.hpp randomx/randomx.h randomx/reciprocal.h \
		  randomx/soft_aes.h randomx/superscalar.hpp \
		  randomx/superscalar_program.hpp randomx/virtual_machine.hpp \
		  randomx/virtual_memory.h randomx/vm_compiled.hpp \
		  randomx/vm_compiled_light.hpp randomx/vm_interpreted.hpp \
		  randomx/vm_interpreted_light.hpp

RANDOMX_LIBS	=
if USE_RANDOMX
noinst_LIBRARIES += librandomx.a
librandomx_a_SOURCES = \
		  randomx/aes_hash.cpp \
		  randomx/allocator.cpp \
		  randomx/argon2_core.c \
		  randomx/argon2_ref.c \
		  randomx/assembly_generator_x86.cpp \
		  randomx/blake2/blake2b.c \
		  randomx/blake2_generator.cpp \
		  randomx/bytecode_machine.cpp \
		  randomx/cpu.cpp \
		  randomx/dataset.cpp \
		  randomx/instruction.cpp \
		  randomx/instructions_portable.cpp \
		  randomx/randomx.cpp \
		  randomx/reciprocal.c \
		  randomx/soft_aes.cpp \
		  randomx/superscalar.cpp \
		  randomx/virtual_machine.cpp \
		  randomx/virtual_memory.c \
		  randomx/vm_compiled.cpp \
		  randomx/vm_compiled_light.cpp \
		  randomx/vm_interpreted.cpp \
		  randomx/vm_interpreted_light.cpp
librandomx_a_CPPFLAGS = $(RANDOMX_CPPFLAGS)
librandomx_a_CFLAGS = $(RANDOMX_FLAGS)
librandomx_a_CXXFLAGS = $(RANDOMX_FLAGS)
librandomx_a_CCASFLAGS = $(RANDOMX_FLAGS)
RANDOMX_LIBS	+= librandomx.a

# Argon2 (the cache) with SSSE3 or AVX2, used if the processor has them;
# without the flag these files only say they are not there
if RANDOMX_SSSE3
noinst_LIBRARIES += librandomx_ssse3.a
librandomx_ssse3_a_SOURCES = randomx/argon2_ssse3.c
librandomx_ssse3_a_CFLAGS = -mssse3
RANDOMX_LIBS	+= librandomx_ssse3.a
else
librandomx_a_SOURCES += randomx/argon2_ssse3.c
endif
if RANDOMX_AVX2
noinst_LIBRARIES += librandomx_avx2.a
librandomx_avx2_a_SOURCES = randomx/argon2_avx2.c
librandomx_avx2_a_CFLAGS = -mavx2
RANDOMX_LIBS	+= librandomx_avx2.a
else
librandomx_a_SOURCES += randomx/argon2_avx2.c
endif

if RANDOMX_JIT_X86
librandomx_a_SOURCES += randomx/jit_compiler_x86.cpp randomx/jit_compiler_x86_static.S
endif
if RANDOMX_JIT_A64
librandomx_a_SOURCES += randomx/jit_compiler_a64.cpp randomx/jit_compiler_a64_static.S
endif
if RANDOMX_JIT_RV64
librandomx_a_SOURCES += randomx/jit_compiler_rv64.cpp \
		  randomx/jit_compiler_rv64_static.S \
		  randomx/jit_compiler_rv64_vector.cpp randomx/cpu_rv64.S
# the vector code, used if the processor has the extensions
noinst_LIBRARIES += librandomx_rvv.a librandomx_zvkned.a
librandomx_rvv_a_SOURCES = randomx/aes_hash_rv64_vector.cpp
librandomx_rvv_a_CXXFLAGS = -march=rv64gcv
librandomx_zvkned_a_SOURCES = randomx/aes_hash_rv64_zvkned.cpp \
		  randomx/jit_compiler_rv64_vector_static.S
librandomx_zvkned_a_CXXFLAGS = -march=rv64gcv_zvkned
librandomx_zvkned_a_CCASFLAGS = -march=rv64gcv_zvkned
RANDOMX_LIBS	+= librandomx_rvv.a librandomx_zvkned.a
endif

# the rest of the library may need these objects' callers: search it again
RANDOMX_LIBS	+= librandomx.a
endif

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= cpu-miner.c util.c

minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= libalgos.a $(RANDOMX_LIBS) $(LIBCURL_LIBS) $(JANSSON_LIBS) $(PTHREAD_LIBS) $(WS2_LIBS)

# "make check": known-answer tests for every algorithm
check_PROGRAMS	= tests/kat
tests_kat_SOURCES = tests/kat.c
tests_kat_LDADD	= libalgos.a $(RANDOMX_LIBS) $(PTHREAD_LIBS)
TESTS		= tests/kat

# with RandomX in, the programs link with the C++ compiler (its runtime)
if USE_RANDOMX
minerd_LINK	= $(CXXLD) $(AM_CXXFLAGS) $(CXXFLAGS) $(minerd_LDFLAGS) $(LDFLAGS) -o $@
tests_kat_LINK	= $(CXXLD) $(AM_CXXFLAGS) $(CXXFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
else
minerd_LINK	= $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(minerd_LDFLAGS) $(LDFLAGS) -o $@
tests_kat_LINK	= $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
endif
