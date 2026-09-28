/*
 * NeoScrypt, the proof of work of Feathercoin and other coins:
 * NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20, between two passes
 * of FastKDF with BLAKE2s (profile 0 of John Doering's reference code).
 *
 * Written from the reference implementation (Copyright (c) 2009 Colin
 * Percival, 2011 ArtForz, 2012 Andrew Moon, 2012 Samuel Neves, 2014-2016
 * John Doering; BSD 2-clause license) as Feathercoin Core ships it, to
 * hash 4 headers at a time with GCC vector extensions: FastKDF's BLAKE2s
 * with one header per lane, and Salsa20/ChaCha20 with one row of a block
 * per vector, two independent blocks at a time (see neoscrypt-mix.h), in
 * SSE2, AVX2 or AVX-512 on x86 as the processor allows, NEON on ARM, and
 * plain code elsewhere.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NEO_N		128	/* scrypt's N: 128 blocks of 256 bytes */
#define KDF_BUF		256	/* FastKDF's buffer size */
#define KDF_ROUNDS	32

typedef uint32_t neo_v4 __attribute__((vector_size(16)));

#define NEO_SPLAT4(x) ((neo_v4) { (x), (x), (x), (x) })

/* ------------------------------------------------------------------ */
/*
 * FastKDF, a buffered key derivation function with BLAKE2s as its PRF,
 * on 4 inputs at once: lane k of every vector belongs to input k.
 */

static const uint32_t blake2s_iv[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

#define B2S_ROTR(v, n) ((v) >> (n) | (v) << (32 - (n)))

#define B2S_G(a, b, c, d, x, y) do { \
	a += b + (x); d = B2S_ROTR(d ^ a, 16); \
	c += d; b = B2S_ROTR(b ^ c, 12); \
	a += b + (y); d = B2S_ROTR(d ^ a, 8); \
	c += d; b = B2S_ROTR(b ^ c, 7); \
} while (0)

#define B2S_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) do { \
	B2S_G(v0, v4, v8, v12, m[s0], m[s1]); \
	B2S_G(v1, v5, v9, v13, m[s2], m[s3]); \
	B2S_G(v2, v6, v10, v14, m[s4], m[s5]); \
	B2S_G(v3, v7, v11, v15, m[s6], m[s7]); \
	B2S_G(v0, v5, v10, v15, m[s8], m[s9]); \
	B2S_G(v1, v6, v11, v12, m[s10], m[s11]); \
	B2S_G(v2, v7, v8, v13, m[s12], m[s13]); \
	B2S_G(v3, v4, v9, v14, m[s14], m[s15]); \
} while (0)

/* BLAKE2s compression, the rounds written out with the message schedule
 * as constants */
static void blake2s_compress_x4(neo_v4 h[8], const neo_v4 m[16], uint32_t t,
		uint32_t f)
{
	neo_v4 v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
	neo_v4 v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
	neo_v4 v8 = NEO_SPLAT4(blake2s_iv[0]), v9 = NEO_SPLAT4(blake2s_iv[1]);
	neo_v4 v10 = NEO_SPLAT4(blake2s_iv[2]), v11 = NEO_SPLAT4(blake2s_iv[3]);
	neo_v4 v12 = NEO_SPLAT4(blake2s_iv[4] ^ t), v13 = NEO_SPLAT4(blake2s_iv[5]);
	neo_v4 v14 = NEO_SPLAT4(blake2s_iv[6] ^ f), v15 = NEO_SPLAT4(blake2s_iv[7]);

	B2S_ROUND( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
	B2S_ROUND(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);
	B2S_ROUND(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4);
	B2S_ROUND( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8);
	B2S_ROUND( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13);
	B2S_ROUND( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9);
	B2S_ROUND(12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11);
	B2S_ROUND(13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10);
	B2S_ROUND( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5);
	B2S_ROUND(10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0);

	h[0] ^= v0 ^ v8;  h[1] ^= v1 ^ v9;  h[2] ^= v2 ^ v10; h[3] ^= v3 ^ v11;
	h[4] ^= v4 ^ v12; h[5] ^= v5 ^ v13; h[6] ^= v6 ^ v14; h[7] ^= v7 ^ v15;
}

/* word w of the 4 inputs at p[k] + off[k] */
#define NEO_GATHER4(p, off, w) ((neo_v4) { \
	le32dec((p)[0] + (off)[0] + 4 * (w)), le32dec((p)[1] + (off)[1] + 4 * (w)), \
	le32dec((p)[2] + (off)[2] + 4 * (w)), le32dec((p)[3] + (off)[3] + 4 * (w)) })

/* 80-byte password buffer: the password repeated to 256 bytes, then its
 * first 64 bytes again (so PRF inputs may run past the end) */
static void fastkdf_password(uint8_t a[KDF_BUF + 64], const uint8_t *password)
{
	memcpy(a, password, 80);
	memcpy(a + 80, password, 80);
	memcpy(a + 160, password, 80);
	memcpy(a + 240, password, 16);
	memcpy(a + KDF_BUF, password, 64);
}

/*
 * FastKDF of 4 inputs: password buffers from fastkdf_password(), salts of
 * salt_len bytes (80 or 256), out_len bytes of output (256 or 32).
 */
static void fastkdf_x4(uint8_t *const out[4], size_t out_len,
		uint8_t (*a)[KDF_BUF + 64], const uint8_t *const salt[4],
		size_t salt_len)
{
	const uint8_t *pa[4] = { a[0], a[1], a[2], a[3] };
	uint8_t b[4][KDF_BUF + 32];
	const uint8_t *pb[4] = { b[0], b[1], b[2], b[3] };
	unsigned bufptr[4] = { 0, 0, 0, 0 };
	neo_v4 h[8], m[16], sum, t;
	int i, k, w;
	size_t n;

	/* the salt buffers: the salt repeated, then its first 32 bytes */
	for (k = 0; k < 4; k++) {
		for (n = 0; n + salt_len <= KDF_BUF; n += salt_len)
			memcpy(b[k] + n, salt[k], salt_len);
		memcpy(b[k] + n, salt[k], KDF_BUF - n);
		memcpy(b[k] + KDF_BUF, salt[k], 32);
	}

	for (i = 0; i < KDF_ROUNDS; i++) {
		/* BLAKE2s-256 of the 64 bytes at a + bufptr keyed with the 32
		 * bytes at b + bufptr: a key block, then the input */
		for (w = 0; w < 8; w++) {
			h[w] = NEO_SPLAT4(blake2s_iv[w]);
			m[w] = NEO_GATHER4(pb, bufptr, w);
			m[8 + w] = NEO_SPLAT4(0);
		}
		h[0] ^= NEO_SPLAT4(0x01012020);	/* 32-byte digest and key */
		blake2s_compress_x4(h, m, 64, 0);
		for (w = 0; w < 16; w++)
			m[w] = NEO_GATHER4(pa, bufptr, w);
		blake2s_compress_x4(h, m, 128, 0xffffffff);

		/* the next position: the sum of the 32 bytes of output */
		sum = NEO_SPLAT4(0);
		for (w = 0; w < 8; w++) {
			t = (h[w] & NEO_SPLAT4(0x00ff00ff))
				+ (h[w] >> 8 & NEO_SPLAT4(0x00ff00ff));
			sum += (t & NEO_SPLAT4(0xffff)) + (t >> 16);
		}
		/* XOR the output into the salt buffer there, keeping the 32
		 * bytes after the buffer a copy of its start */
		for (k = 0; k < 4; k++) {
			unsigned p = sum[k] & (KDF_BUF - 1);
			uint8_t *d = b[k] + p;

			for (w = 0; w < 8; w++)
				le32enc(d + 4 * w, le32dec(d + 4 * w) ^ h[w][k]);
			if (p < 32)
				memcpy(b[k] + KDF_BUF + p, d, 32 - p);
			else if (p > KDF_BUF - 32)
				memcpy(b[k], b[k] + KDF_BUF, p - (KDF_BUF - 32));
			bufptr[k] = p;
		}
	}

	/* the salt buffer from bufptr on, wrapping around, XOR the password
	 * buffer */
	for (k = 0; k < 4; k++)
		for (n = 0; n < out_len; n++)
			out[k][n] = b[k][(bufptr[k] + n) & (KDF_BUF - 1)] ^ a[k][n];
}

/* ------------------------------------------------------------------ */
/* Salsa20/20 and ChaCha20/20: one variant of the code per instruction set */

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 12)
#define NEO_SHUFFLE4(v, a, b, c, d) __builtin_shufflevector(v, v, a, b, c, d)
#else
#define NEO_SHUFFLE4(v, a, b, c, d) __builtin_shuffle(v, (neo_v4) { a, b, c, d })
#endif

/* lane i gets lane (i + n) % 4 */
#define NEO_ROT4(v, n) NEO_SHUFFLE4(v, (n) & 3, ((n) + 1) & 3, ((n) + 2) & 3, ((n) + 3) & 3)

/* rotating 32-bit lanes by 16 bits: swapping their 16-bit halves (one or
 * two instructions instead of three) */
typedef uint16_t neo_u16x8 __attribute__((vector_size(16)));
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 12)
#define NEO_ROTL16_4(v) ((neo_v4) __builtin_shufflevector((neo_u16x8) (v), \
	(neo_u16x8) (v), 1, 0, 3, 2, 5, 4, 7, 6))
#else
#define NEO_ROTL16_4(v) ((neo_v4) __builtin_shuffle((neo_u16x8) (v), \
	(neo_u16x8) { 1, 0, 3, 2, 5, 4, 7, 6 }))
#endif

#if defined(__SSE2__) || defined(__ARM_NEON) || defined(__ARM_NEON__) || \
	defined(__aarch64__)
/* the vector code, as the compiler makes it by default: SSE2 on x86-64,
 * NEON on arm64 (and on 32-bit ARM with -mfpu=neon) */
#define NEO_VT		neo_v4
#define NEO_W		1
#define NEO_ATTR
#define NEO_NAME(f)	f##_generic
#define NEO_ROT		NEO_ROT4
#define NEO_ROTL16	NEO_ROTL16_4
#include "neoscrypt-mix.h"
#undef NEO_VT
#undef NEO_W
#undef NEO_ATTR
#undef NEO_NAME
#undef NEO_ROT
#else
/*
 * No vector instructions: plain code, one hash at a time (the compiler
 * would make the vector code twice as slow).
 */
#define NEO_SCALAR 1

#define NEO_R(x, n) ((x) << (n) | (x) >> (32 - (n)))

static void salsa20_20(uint32_t b[16])
{
	uint32_t x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3];
	uint32_t x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7];
	uint32_t x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11];
	uint32_t x12 = b[12], x13 = b[13], x14 = b[14], x15 = b[15];
	int i;

#define SALSA_QR(a, b, c, d) do { \
	b ^= NEO_R(a + d, 7); c ^= NEO_R(b + a, 9); \
	d ^= NEO_R(c + b, 13); a ^= NEO_R(d + c, 18); \
} while (0)
	for (i = 0; i < 10; i++) {
		SALSA_QR(x0, x4, x8, x12);
		SALSA_QR(x5, x9, x13, x1);
		SALSA_QR(x10, x14, x2, x6);
		SALSA_QR(x15, x3, x7, x11);
		SALSA_QR(x0, x1, x2, x3);
		SALSA_QR(x5, x6, x7, x4);
		SALSA_QR(x10, x11, x8, x9);
		SALSA_QR(x15, x12, x13, x14);
	}
#undef SALSA_QR
	b[0] += x0; b[1] += x1; b[2] += x2; b[3] += x3;
	b[4] += x4; b[5] += x5; b[6] += x6; b[7] += x7;
	b[8] += x8; b[9] += x9; b[10] += x10; b[11] += x11;
	b[12] += x12; b[13] += x13; b[14] += x14; b[15] += x15;
}

static void chacha20_20(uint32_t b[16])
{
	uint32_t x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3];
	uint32_t x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7];
	uint32_t x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11];
	uint32_t x12 = b[12], x13 = b[13], x14 = b[14], x15 = b[15];
	int i;

#define CHACHA_QR(a, b, c, d) do { \
	a += b; d = NEO_R(d ^ a, 16); c += d; b = NEO_R(b ^ c, 12); \
	a += b; d = NEO_R(d ^ a, 8); c += d; b = NEO_R(b ^ c, 7); \
} while (0)
	for (i = 0; i < 10; i++) {
		CHACHA_QR(x0, x4, x8, x12);
		CHACHA_QR(x1, x5, x9, x13);
		CHACHA_QR(x2, x6, x10, x14);
		CHACHA_QR(x3, x7, x11, x15);
		CHACHA_QR(x0, x5, x10, x15);
		CHACHA_QR(x1, x6, x11, x12);
		CHACHA_QR(x2, x7, x8, x13);
		CHACHA_QR(x3, x4, x9, x14);
	}
#undef CHACHA_QR
	b[0] += x0; b[1] += x1; b[2] += x2; b[3] += x3;
	b[4] += x4; b[5] += x5; b[6] += x6; b[7] += x7;
	b[8] += x8; b[9] += x9; b[10] += x10; b[11] += x11;
	b[12] += x12; b[13] += x13; b[14] += x14; b[15] += x15;
}
#undef NEO_R

/* NeoScrypt's block mix with r = 2, then scrypt's SMix with N = 128 */
#define NEO_SMIX_SCALAR(x, v, core) do { \
	int i_, k_, pass_; \
	for (pass_ = 0; pass_ < 2; pass_++) \
		for (i_ = 0; i_ < NEO_N; i_++) { \
			if (pass_ == 0) \
				memcpy((v) + 64 * i_, x, 256); \
			else { \
				const uint32_t *vj_ = (v) + 64 * (x[48] & (NEO_N - 1)); \
				for (k_ = 0; k_ < 64; k_++) x[k_] ^= vj_[k_]; \
			} \
			for (k_ = 0; k_ < 16; k_++) x[k_] ^= x[48 + k_]; \
			core(x); \
			for (k_ = 0; k_ < 16; k_++) x[16 + k_] ^= x[k_]; \
			core(x + 16); \
			for (k_ = 0; k_ < 16; k_++) x[32 + k_] ^= x[16 + k_]; \
			core(x + 32); \
			for (k_ = 0; k_ < 16; k_++) x[48 + k_] ^= x[32 + k_]; \
			core(x + 48); \
			for (k_ = 0; k_ < 16; k_++) { \
				uint32_t t_ = x[16 + k_]; \
				x[16 + k_] = x[32 + k_]; \
				x[32 + k_] = t_; \
			} \
		} \
} while (0)

static void neo_mix_scalar(uint8_t buf[256], uint32_t *v)
{
	uint32_t x[64], z[64];
	int k;

	for (k = 0; k < 64; k++)
		x[k] = z[k] = le32dec(buf + 4 * k);
	NEO_SMIX_SCALAR(z, v, chacha20_20);
	NEO_SMIX_SCALAR(x, v, salsa20_20);
	for (k = 0; k < 64; k++)
		le32enc(buf + 4 * k, x[k] ^ z[k]);
}
#endif

#if defined(__i386__) && !defined(__SSE2__) && \
	(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
/* 32-bit x86: SSE2 when the processor has it */
#define NEO_SSE2 1
#define NEO_VT		neo_v4
#define NEO_W		1
#define NEO_ATTR	__attribute__((target("sse2")))
#define NEO_NAME(f)	f##_sse2
#define NEO_ROT		NEO_ROT4
#define NEO_ROTL16	NEO_ROTL16_4
#include "neoscrypt-mix.h"
#undef NEO_VT
#undef NEO_W
#undef NEO_ATTR
#undef NEO_NAME
#undef NEO_ROT
#endif

#if defined(__x86_64__) && \
	(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
/* x86-64 with AVX2: 2 hashes per 256-bit vector, 4 at a time; the same
 * code for AVX-512VL gets one-instruction rotations (vprold) */
#define NEO_AVX2 1
typedef uint32_t neo_v8 __attribute__((vector_size(32)));

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 12)
#define NEO_SHUFFLE8(a, b, ...) __builtin_shufflevector(a, b, __VA_ARGS__)
#else
#define NEO_SHUFFLE8(a, b, ...) __builtin_shuffle(a, b, (neo_v8) { __VA_ARGS__ })
#endif
#define NEO_ROT8(v, n) NEO_SHUFFLE8(v, v, (n) & 3, ((n) + 1) & 3, ((n) + 2) & 3, \
	((n) + 3) & 3, 4 + ((n) & 3), 4 + (((n) + 1) & 3), 4 + (((n) + 2) & 3), \
	4 + (((n) + 3) & 3))
/* lanes 0-3 of a, 4-7 of b */
#define NEO_BLEND(a, b) NEO_SHUFFLE8(a, b, 0, 1, 2, 3, 12, 13, 14, 15)

/* rotations by 16 and 8 bits as byte shuffles (vpshufb) */
typedef uint8_t neo_u8x32 __attribute__((vector_size(32)));
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 12)
#define NEO_BYTES8(v, ...) ((neo_v8) __builtin_shufflevector((neo_u8x32) (v), \
	(neo_u8x32) (v), __VA_ARGS__))
#else
#define NEO_BYTES8(v, ...) ((neo_v8) __builtin_shuffle((neo_u8x32) (v), \
	(neo_u8x32) { __VA_ARGS__ }))
#endif
#define NEO_ROTL16_8(v) NEO_BYTES8(v, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, \
	14, 15, 12, 13, 18, 19, 16, 17, 22, 23, 20, 21, 26, 27, 24, 25, \
	30, 31, 28, 29)
#define NEO_ROTL8_8(v) NEO_BYTES8(v, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, \
	15, 12, 13, 14, 19, 16, 17, 18, 23, 20, 21, 22, 27, 24, 25, 26, \
	31, 28, 29, 30)

#define NEO_VT		neo_v8
#define NEO_W		2
#define NEO_ATTR	__attribute__((target("avx2")))
#define NEO_NAME(f)	f##_avx2
#define NEO_ROT		NEO_ROT8
#define NEO_ROTL16	NEO_ROTL16_8
#define NEO_ROTL8	NEO_ROTL8_8
#include "neoscrypt-mix.h"
#undef NEO_ATTR
#undef NEO_NAME
#define NEO_ATTR	__attribute__((target("avx2,avx512f,avx512vl")))
#define NEO_NAME(f)	f##_avx512
#include "neoscrypt-mix.h"
#undef NEO_VT
#undef NEO_W
#undef NEO_ATTR
#undef NEO_NAME
#undef NEO_ROT
#endif

/* ------------------------------------------------------------------ */
/* choosing the code for this processor */

enum { NEO_IMPL_GENERIC, NEO_IMPL_SSE2, NEO_IMPL_AVX2, NEO_IMPL_AVX512 };

static bool neo_supported(int impl)
{
	switch (impl) {
	case NEO_IMPL_GENERIC:
		return true;
#ifdef NEO_SSE2
	case NEO_IMPL_SSE2:
		return cpu_has_sse2();
#endif
#ifdef NEO_AVX2
	case NEO_IMPL_AVX2:
		return cpu_has_avx2();
	case NEO_IMPL_AVX512:
		return cpu_has_avx512vl();
#endif
	default:
		return false;
	}
}

/* -1: not chosen yet */
static _Atomic int neo_impl = -1;

static int neo_current(void)
{
	int impl = neo_impl;

	if (unlikely(impl < 0)) {
		for (impl = NEO_IMPL_AVX512; !neo_supported(impl); impl--)
			;
		neo_impl = impl;
	}
	return impl;
}

/* For the tests: use implementation impl (0: portable; 1: SSE2 on 32-bit
 * x86; 2: AVX2; 3: AVX-512VL) if possible, the best one if impl < 0.
 * Returns the one in use. */
int neoscrypt_use_impl(int impl)
{
	if (impl < 0 || !neo_supported(impl)) {
		neo_impl = -1;
		impl = neo_current();
		return impl;
	}
	neo_impl = impl;
	return impl;
}

/* the instruction set the code in use was made for */
const char *neoscrypt_impl_name(void)
{
	switch (neo_current()) {
	case NEO_IMPL_AVX512:
		return "AVX-512";
	case NEO_IMPL_AVX2:
		return "AVX2";
	case NEO_IMPL_SSE2:
		return "SSE2";
	default:
#if defined(NEO_SCALAR)
		return "portable C";
#elif defined(__SSE2__)
		return "SSE2";
#else
		return "NEON";
#endif
	}
}

/* 128 KiB of scratch per thread, for 4 hashes' V arrays */
#define NEO_SCRATCH (2 * NEO_N * 16 * 32)

static void *neo_thread_scratch(void)
{
	static __thread void *raw;
	static __thread void *aligned;

	if (unlikely(!aligned)) {
		raw = malloc(NEO_SCRATCH + 64);
		if (!raw) {
			applog(LOG_ERR, "NeoScrypt: out of memory");
			return NULL;
		}
		aligned = (void *) (((uintptr_t) raw + 63) & ~(uintptr_t) 63);
	}
	return aligned;
}

/* the Salsa20/ChaCha20 part for 4 hashes */
static void neo_mix(int impl, uint8_t (*buf)[256], void *v)
{
	switch (impl) {
#ifdef NEO_AVX2
	case NEO_IMPL_AVX512:
		neo_mix_avx512(buf, v);
		break;
	case NEO_IMPL_AVX2:
		neo_mix_avx2(buf, v);
		break;
#endif
#ifdef NEO_SSE2
	case NEO_IMPL_SSE2:
		neo_mix_sse2(buf, v);
		neo_mix_sse2(buf + 2, v);
		break;
#endif
	default:
#ifdef NEO_SCALAR
		neo_mix_scalar(buf[0], v);
		neo_mix_scalar(buf[1], v);
		neo_mix_scalar(buf[2], v);
		neo_mix_scalar(buf[3], v);
#else
		neo_mix_generic(buf, v);
		neo_mix_generic(buf + 2, v);
#endif
		break;
	}
}

/* ------------------------------------------------------------------ */

/* NeoScrypt of 4 block headers */
static void neoscrypt_x4(uint8_t (*out)[32], uint8_t (*header)[80], void *v)
{
	uint8_t a[4][KDF_BUF + 64], buf[4][256];
	const uint8_t *salt[4];
	uint8_t *dst[4];
	int k;

	for (k = 0; k < 4; k++) {
		fastkdf_password(a[k], header[k]);
		salt[k] = header[k];
		dst[k] = buf[k];
	}
	fastkdf_x4(dst, 256, a, salt, 80);
	/* ChaCha20 first, Salsa20 second, and the XOR of both */
	neo_mix(neo_current(), buf, v);
	for (k = 0; k < 4; k++) {
		salt[k] = buf[k];
		dst[k] = out[k];
	}
	fastkdf_x4(dst, 32, a, salt, 256);
}

void neoscrypt_hash(void *output, const void *input)
{
	uint8_t header[4][80], out[4][32];
	void *v = neo_thread_scratch();
	int k;

	if (!v) {
		memset(output, 0xff, 32);
		return;
	}
	for (k = 0; k < 4; k++)
		memcpy(header[k], input, 80);
	neoscrypt_x4(out, header, v);
	memcpy(output, out[0], 32);
}

int scanhash_neoscrypt(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint8_t header[4][80], out[4][32];
	uint32_t n = first_nonce, hash[8];
	void *v = neo_thread_scratch();
	int h, k;

	*hashes_done = 0;
	if (!v)
		return 0;
	/* pdata holds the header as big-endian words */
	for (k = 0; k < 19; k++)
		be32enc(header[0] + 4 * k, pdata[k]);
	for (h = 1; h < 4; h++)
		memcpy(header[h], header[0], 76);

	do {
		for (h = 0; h < 4; h++)
			be32enc(header[h] + 76, n + h);
		neoscrypt_x4(out, header, v);
		for (h = 0; h < 4; h++) {
			hash[7] = le32dec(out[h] + 28);
			if (hash[7] > Htarg)
				continue;
			for (k = 0; k < 7; k++)
				hash[k] = le32dec(out[h] + 4 * k);
			if (fulltest(hash, ptarget)) {
				pdata[19] = n + h;
				*hashes_done = n + h - first_nonce + 1;
				return 1;
			}
		}
		n += 4;
	} while (n - 1 < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce;
	pdata[19] = n - 1;
	return 0;
}
