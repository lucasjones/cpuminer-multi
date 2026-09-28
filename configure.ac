AC_PREREQ([2.69])
AC_INIT([cpuminer-multi], [1.1.0],
	[https://github.com/Justinwold88/cpuminer-multi/issues],
	[cpuminer-multi],
	[https://github.com/Justinwold88/cpuminer-multi])
AC_CONFIG_SRCDIR([cpu-miner.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([cpuminer-config.h])

m4_ifndef([PKG_PROG_PKG_CONFIG],
	[m4_fatal([pkg.m4 is missing: install pkg-config (or pkgconf) and re-run ./autogen.sh])])

dnl Checks for programs
AC_PROG_CC
AC_PROG_CXX
AM_PROG_AS
AM_PROG_AR
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

dnl Checks for header files
AC_CHECK_HEADERS([sys/endian.h sys/param.h syslog.h])
# sys/sysctl.h requires sys/types.h on FreeBSD
# sys/sysctl.h requires sys/param.h on OpenBSD
AC_CHECK_HEADERS([sys/sysctl.h], [], [],
[#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

AC_CHECK_DECLS([be32dec, le32dec, be32enc, le32enc], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_FUNC_ALLOCA
AC_CHECK_FUNCS([getopt_long])

dnl Target CPU and OS (the machine the miner will run on is $host)
have_x86=false
have_x86_64=false
have_arm=false
have_aarch64=false
case $host_cpu in
  i?86)
    have_x86=true
    ;;
  x86_64|amd64)
    have_x86_64=true
    ;;
  aarch64|arm64)
    have_aarch64=true
    ;;
  arm*)
    have_arm=true
    ;;
esac

have_win32=false
PTHREAD_FLAGS="-pthread"
WS2_LIBS=""
case $host_os in
  mingw*|cygwin*|msys*)
    have_win32=true
    PTHREAD_FLAGS=""
    WS2_LIBS="-lws2_32"
    ;;
esac

AC_ARG_ENABLE([assembly],
  AS_HELP_STRING([--disable-assembly], [disable assembly-language routines]))
if test "x$enable_assembly" != xno; then
  AC_DEFINE([USE_ASM], [1], [Define to 1 if assembly routines are wanted.])
fi

if test "x$enable_assembly" != xno && test "x$have_x86_64" = xtrue
then
  AC_MSG_CHECKING(whether we can compile AVX code)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vmovdqa %ymm0, %ymm1");])],
    AC_DEFINE(USE_AVX, 1, [Define to 1 if AVX assembly is available.])
    AC_MSG_RESULT(yes)
    AC_MSG_CHECKING(whether we can compile XOP code)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vprotd \$7, %xmm0, %xmm1");])],
      AC_DEFINE(USE_XOP, 1, [Define to 1 if XOP assembly is available.])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
      AC_MSG_WARN([The assembler does not support the XOP instruction set.])
    )
    AC_MSG_CHECKING(whether we can compile AVX2 code)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vpaddd %ymm0, %ymm1, %ymm2");])],
      AC_DEFINE(USE_AVX2, 1, [Define to 1 if AVX2 assembly is available.])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
      AC_MSG_WARN([The assembler does not support the AVX2 instruction set.])
    )
  ,
    AC_MSG_RESULT(no)
    AC_MSG_WARN([The assembler does not support the AVX instruction set.])
  )
fi

if test "x$enable_assembly" != xno && test "x$have_x86" = xtrue; then
  dnl The 32-bit x86 assembly is not position independent: in a PIE (the
  dnl default with most compilers now) it needs text relocations, which
  dnl some linkers refuse.
  AC_MSG_CHECKING([whether the linker accepts -no-pie])
  save_LDFLAGS=$LDFLAGS
  LDFLAGS="$LDFLAGS -no-pie"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no]); LDFLAGS=$save_LDFLAGS])
fi

dnl RandomX (Monero) is tevador's library (randomx/), which is C++: it needs a
dnl C++11 compiler, which nothing else does. Without one it is left out.
AC_ARG_ENABLE([randomx],
  AS_HELP_STRING([--disable-randomx],
    [leave out RandomX (Monero), which needs a C++11 compiler]))
use_randomx=no
randomx_jit=none
randomx_ssse3=no
randomx_avx2=no
RANDOMX_CPPFLAGS=
RANDOMX_FLAGS=
if test "x$enable_randomx" != xno; then
  AC_LANG_PUSH([C++])
  m4_define([rx_cxx11_program], [AC_LANG_PROGRAM([[#include <array>
#include <cstdint>
#include <new>
constexpr int one() { return 1; }
static_assert(sizeof(std::uint64_t) == 8, "64-bit integers");]],
[[std::array<int, 2> a{{one(), 2}};
try { throw std::bad_alloc(); } catch (std::exception &) { return a[0] - 1; }
return a[1];]])])
  AC_MSG_CHECKING([whether $CXX builds C++11 programs])
  AC_LINK_IFELSE([rx_cxx11_program], [use_randomx=yes],
    [save_CXX=$CXX
     CXX="$CXX -std=gnu++11"
     AC_LINK_IFELSE([rx_cxx11_program], [use_randomx=yes], [CXX=$save_CXX])])
  AC_MSG_RESULT([$use_randomx])
  if test $use_randomx = no; then
    AC_MSG_WARN([no C++11 compiler: RandomX (Monero) is left out])
  fi

  dnl The JIT compilers (x86-64, ARMv8, RISC-V), and the flags that enable
  dnl the instructions the library picks at run time: hardware AES, and on
  dnl x86-64 SSSE3 and AVX2 for the Argon2 fill of the cache.
  if test $use_randomx = yes; then
    save_CXXFLAGS=$CXXFLAGS
    case $host_cpu in
      x86_64|amd64)
        randomx_jit=x86
        AC_MSG_CHECKING([whether $CXX compiles AES-NI code with -maes])
        CXXFLAGS="$save_CXXFLAGS -maes"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <wmmintrin.h>]],
          [[__m128i x = _mm_setzero_si128();
x = _mm_aesenc_si128(x, x);
return _mm_cvtsi128_si32(x);]])],
          [RANDOMX_FLAGS=-maes; AC_MSG_RESULT([yes])],
          [AC_MSG_RESULT([no]); AC_MSG_WARN([RandomX will use software AES])])
        AC_LANG_PUSH([C])
        save_CFLAGS=$CFLAGS
        AC_MSG_CHECKING([whether $CC compiles SSSE3 code with -mssse3])
        CFLAGS="$save_CFLAGS -mssse3"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <tmmintrin.h>]],
          [[__m128i x = _mm_setzero_si128();
x = _mm_shuffle_epi8(x, x);
return _mm_cvtsi128_si32(x);]])],
          [randomx_ssse3=yes])
        AC_MSG_RESULT([$randomx_ssse3])
        AC_MSG_CHECKING([whether $CC compiles AVX2 code with -mavx2])
        CFLAGS="$save_CFLAGS -mavx2"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <immintrin.h>]],
          [[__m256i x = _mm256_setzero_si256();
x = _mm256_add_epi64(x, x);
return _mm256_extract_epi32(x, 0);]])],
          [randomx_avx2=yes])
        AC_MSG_RESULT([$randomx_avx2])
        CFLAGS=$save_CFLAGS
        AC_LANG_POP([C])
        ;;
      aarch64|arm64)
        randomx_jit=a64
        AC_MSG_CHECKING([whether $CXX compiles ARMv8 AES code with -march=armv8-a+crypto])
        CXXFLAGS="$save_CXXFLAGS -march=armv8-a+crypto"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <arm_neon.h>]],
          [[uint8x16_t x = vdupq_n_u8(0);
x = vaeseq_u8(x, x);
return vgetq_lane_u8(x, 0);]])],
          [RANDOMX_FLAGS=-march=armv8-a+crypto; AC_MSG_RESULT([yes])],
          [AC_MSG_RESULT([no]); AC_MSG_WARN([RandomX will use software AES])])
        dnl the library finds hardware AES through getauxval(AT_HWCAP)
        AC_CHECK_HEADER([asm/hwcap.h], [RANDOMX_CPPFLAGS=-DHAVE_HWCAP])
        ;;
      riscv64)
        dnl the library always carries its vector and vector-AES code here,
        dnl and uses it if the processor has the extensions
        randomx_jit=rv64
        AC_MSG_CHECKING([whether $CXX compiles RISC-V vector AES code])
        CXXFLAGS="$save_CXXFLAGS -march=rv64gcv_zvkned"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <riscv_vector.h>]],
          [[vuint32m1_t x = __riscv_vmv_v_x_u32m1(0, 4);
x = __riscv_vaesem_vv_u32m1(x, x, 4);
return (int) __riscv_vmv_x_s_u32m1_u32(x);]])],
          [AC_MSG_RESULT([yes])],
          [AC_MSG_RESULT([no])
           use_randomx=no
           AC_MSG_WARN([RandomX on RISC-V needs GCC 14 or Clang 17 or newer: it is left out])])
        ;;
      riscv*)
        use_randomx=no
        AC_MSG_WARN([RandomX needs a 64-bit RISC-V processor: it is left out])
        ;;
    esac
    CXXFLAGS=$save_CXXFLAGS
  fi
  AC_LANG_POP([C++])
  if test $use_randomx = no && test "x$enable_randomx" = xyes; then
    AC_MSG_ERROR([RandomX cannot be built here (see the messages above); configure with --disable-randomx])
  fi
fi
if test $use_randomx = yes; then
  AC_DEFINE([USE_RANDOMX], [1], [Define to 1 if RandomX is built.])
fi

AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthread",
  AC_CHECK_LIB([pthreadGC2], [pthread_create], PTHREAD_LIBS="-lpthreadGC2",
    AC_CHECK_LIB([pthreadGC1], [pthread_create], PTHREAD_LIBS="-lpthreadGC1",
      AC_CHECK_LIB([pthreadGC], [pthread_create], PTHREAD_LIBS="-lpthreadGC"
))))

PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.15.2], [],
  [dnl no pkg-config file: e.g. the libcurl that comes with macOS
   AC_CHECK_HEADER([curl/curl.h], [],
     [AC_MSG_ERROR([libcurl not found: install its development package (Debian/Ubuntu: libcurl4-openssl-dev, Fedora: libcurl-devel, MSYS2: mingw-w64-ucrt-x86_64-curl)])])
   AC_CHECK_LIB([curl], [curl_easy_init], [LIBCURL_LIBS=-lcurl],
     [AC_MSG_ERROR([libcurl not found: install its development package (Debian/Ubuntu: libcurl4-openssl-dev, Fedora: libcurl-devel, MSYS2: mingw-w64-ucrt-x86_64-curl)])])])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.7], [],
  [AC_MSG_ERROR([jansson 2.7 or newer not found: install its development package (Debian/Ubuntu: libjansson-dev, Fedora: jansson-devel, macOS: brew install jansson, MSYS2: mingw-w64-ucrt-x86_64-jansson)])])

AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([USE_ASM], [test x$enable_assembly != xno])
AM_CONDITIONAL([ARCH_x86], [test x$have_x86 = xtrue])
AM_CONDITIONAL([ARCH_x86_64], [test x$have_x86_64 = xtrue])
AM_CONDITIONAL([ARCH_ARM], [test x$have_arm = xtrue])
AM_CONDITIONAL([ARCH_AARCH64], [test x$have_aarch64 = xtrue])
AM_CONDITIONAL([USE_RANDOMX], [test $use_randomx = yes])
AM_CONDITIONAL([RANDOMX_JIT_X86], [test $use_randomx = yes && test $randomx_jit = x86])
AM_CONDITIONAL([RANDOMX_JIT_A64], [test $use_randomx = yes && test $randomx_jit = a64])
AM_CONDITIONAL([RANDOMX_JIT_RV64], [test $use_randomx = yes && test $randomx_jit = rv64])
AM_CONDITIONAL([RANDOMX_SSSE3], [test $use_randomx = yes && test $randomx_ssse3 = yes])
AM_CONDITIONAL([RANDOMX_AVX2], [test $use_randomx = yes && test $randomx_avx2 = yes])

AC_SUBST(RANDOMX_CPPFLAGS)
AC_SUBST(RANDOMX_FLAGS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(WS2_LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
