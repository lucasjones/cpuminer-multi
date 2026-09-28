/*
 * Argon2d (RFC 9106) as a proof of work: the 80-byte block header is both
 * the password and the salt, with no secret and no associated data, and
 * the 32-byte tag is the hash. The variants differ in their costs:
 *
 *   argon2d4096   Myriad, Unitus          t=1  m=4096 KiB  p=1  v1.3
 *   argon2d500    Dynamic                 t=2  m=500 KiB   p=8  v1.0
 *   argon2d250    Credits                 t=1  m=250 KiB   p=4  v1.0
 *   argon2d16000  Alterdot                t=1  m=16000 KiB p=1  v1.0
 *
 * Written from RFC 9106 and the reference implementation (Daniel Dinu,
 * Dmitry Khovratovich, Jean-Philippe Aumasson and Samuel Neves; CC0 or
 * Apache 2.0), which the coins ship. The compression function is plain
 * 64-bit code, or works on 4 words at a time with AVX2 or AVX-512 when the
 * processor has them.
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

#define ARGON2_BLOCK_SIZE	1024
#define ARGON2_QWORDS		(ARGON2_BLOCK_SIZE / 8)
#define ARGON2_SYNC_POINTS	4
#define ARGON2_PREHASH		64	/* H0's length */

struct argon2d_params {
	uint32_t t_cost, m_cost, lanes, version;
};

static const struct argon2d_params argon2d_variants[] = {
	[ARGON2D_4096] =  { 1, 4096, 1, 0x13 },
	[ARGON2D_500] =   { 2, 500, 8, 0x10 },
	[ARGON2D_250] =   { 1, 250, 4, 0x10 },
	[ARGON2D_16000] = { 1, 16000, 1, 0x10 },
};

typedef struct {
	uint64_t v[ARGON2_QWORDS];
} __attribute__((aligned(64))) argon2_block;

/* ------------------------------------------------------------------ */
/* BLAKE2b, for the first and last steps */

static const uint64_t blake2b_iv[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t blake2b_sigma[12][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

struct blake2b_state {
	uint64_t h[8];
	uint64_t t;		/* bytes hashed, never more than 2^64 here */
	uint8_t buf[128];
	size_t buflen;
	size_t outlen;
};

static inline uint64_t rotr64(uint64_t x, unsigned n)
{
	return x >> n | x << (64 - n);
}

static inline uint64_t le64dec_(const uint8_t *p)
{
	return (uint64_t) le32dec(p) | (uint64_t) le32dec(p + 4) << 32;
}

static inline void le64enc_(uint8_t *p, uint64_t x)
{
	le32enc(p, (uint32_t) x);
	le32enc(p + 4, (uint32_t) (x >> 32));
}

static void blake2b_compress(struct blake2b_state *s, const uint8_t *block,
		bool last)
{
	uint64_t m[16], v[16];
	int i, r;

	for (i = 0; i < 16; i++)
		m[i] = le64dec_(block + 8 * i);
	for (i = 0; i < 8; i++) {
		v[i] = s->h[i];
		v[i + 8] = blake2b_iv[i];
	}
	v[12] ^= s->t;
	if (last)
		v[14] = ~v[14];

#define B2B_G(a, b, c, d, x, y) do { \
	v[a] += v[b] + (x); v[d] = rotr64(v[d] ^ v[a], 32); \
	v[c] += v[d]; v[b] = rotr64(v[b] ^ v[c], 24); \
	v[a] += v[b] + (y); v[d] = rotr64(v[d] ^ v[a], 16); \
	v[c] += v[d]; v[b] = rotr64(v[b] ^ v[c], 63); \
} while (0)
	for (r = 0; r < 12; r++) {
		const uint8_t *s_ = blake2b_sigma[r];

		B2B_G(0, 4, 8, 12, m[s_[0]], m[s_[1]]);
		B2B_G(1, 5, 9, 13, m[s_[2]], m[s_[3]]);
		B2B_G(2, 6, 10, 14, m[s_[4]], m[s_[5]]);
		B2B_G(3, 7, 11, 15, m[s_[6]], m[s_[7]]);
		B2B_G(0, 5, 10, 15, m[s_[8]], m[s_[9]]);
		B2B_G(1, 6, 11, 12, m[s_[10]], m[s_[11]]);
		B2B_G(2, 7, 8, 13, m[s_[12]], m[s_[13]]);
		B2B_G(3, 4, 9, 14, m[s_[14]], m[s_[15]]);
	}
#undef B2B_G
	for (i = 0; i < 8; i++)
		s->h[i] ^= v[i] ^ v[i + 8];
}

/* unkeyed BLAKE2b with an outlen-byte digest */
static void blake2b_init(struct blake2b_state *s, size_t outlen)
{
	int i;

	for (i = 0; i < 8; i++)
		s->h[i] = blake2b_iv[i];
	s->h[0] ^= 0x01010000 ^ outlen;
	s->t = 0;
	s->buflen = 0;
	s->outlen = outlen;
}

static void blake2b_update(struct blake2b_state *s, const void *data, size_t len)
{
	const uint8_t *in = data;

	while (len > 0) {
		size_t n;

		/* keep the last block for blake2b_final() */
		if (s->buflen == 128) {
			s->t += 128;
			blake2b_compress(s, s->buf, false);
			s->buflen = 0;
		}
		n = 128 - s->buflen < len ? 128 - s->buflen : len;
		memcpy(s->buf + s->buflen, in, n);
		s->buflen += n;
		in += n;
		len -= n;
	}
}

static void blake2b_final(struct blake2b_state *s, uint8_t *out)
{
	uint8_t h[64];
	int i;

	s->t += s->buflen;
	memset(s->buf + s->buflen, 0, 128 - s->buflen);
	blake2b_compress(s, s->buf, true);
	for (i = 0; i < 8; i++)
		le64enc_(h + 8 * i, s->h[i]);
	memcpy(out, h, s->outlen);
}

static void blake2b(uint8_t *out, size_t outlen, const void *in, size_t inlen)
{
	struct blake2b_state s;

	blake2b_init(&s, outlen);
	blake2b_update(&s, in, inlen);
	blake2b_final(&s, out);
}

/* H', Argon2's variable-length hash */
static void blake2b_long(uint8_t *out, size_t outlen, const void *in, size_t inlen)
{
	struct blake2b_state s;
	uint8_t len[4], v[64];

	le32enc(len, (uint32_t) outlen);
	if (outlen <= 64) {
		blake2b_init(&s, outlen);
		blake2b_update(&s, len, 4);
		blake2b_update(&s, in, inlen);
		blake2b_final(&s, out);
		return;
	}
	blake2b_init(&s, 64);
	blake2b_update(&s, len, 4);
	blake2b_update(&s, in, inlen);
	blake2b_final(&s, v);
	memcpy(out, v, 32);
	out += 32;
	outlen -= 32;
	while (outlen > 64) {
		blake2b(v, 64, v, 64);
		memcpy(out, v, 32);
		out += 32;
		outlen -= 32;
	}
	blake2b(v, outlen, v, 64);
	memcpy(out, v, outlen);
}

/* ------------------------------------------------------------------ */
/*
 * The compression function G: next = P(prev ^ ref) ^ prev ^ ref, XOR the
 * old next when with_xor (Argon2 1.3 after the first pass), where P runs
 * BLAKE2's round, with multiplications (BlaMka), over the 8 rows of 16
 * words of the 1 KiB block, then over its 8 columns.
 */

typedef void (*argon2_fill_fn)(const argon2_block *prev, const argon2_block *ref,
		argon2_block *next, bool with_xor);

/* x + y + 2 * lo(x) * lo(y) */
static inline uint64_t blamka(uint64_t x, uint64_t y)
{
	return x + y + 2 * ((x & 0xffffffff) * (y & 0xffffffff));
}

#define A2_GB(a, b, c, d) do { \
	a = blamka(a, b); d = rotr64(d ^ a, 32); \
	c = blamka(c, d); b = rotr64(b ^ c, 24); \
	a = blamka(a, b); d = rotr64(d ^ a, 16); \
	c = blamka(c, d); b = rotr64(b ^ c, 63); \
} while (0)

#define A2_ROUND(v, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15) do { \
	A2_GB(v[i0], v[i4], v[i8], v[i12]); \
	A2_GB(v[i1], v[i5], v[i9], v[i13]); \
	A2_GB(v[i2], v[i6], v[i10], v[i14]); \
	A2_GB(v[i3], v[i7], v[i11], v[i15]); \
	A2_GB(v[i0], v[i5], v[i10], v[i15]); \
	A2_GB(v[i1], v[i6], v[i11], v[i12]); \
	A2_GB(v[i2], v[i7], v[i8], v[i13]); \
	A2_GB(v[i3], v[i4], v[i9], v[i14]); \
} while (0)

/* plain 64-bit code: as fast as SSE2, which has no 64-bit rotations */
static void argon2_fill_scalar(const argon2_block *prev, const argon2_block *ref,
		argon2_block *next, bool with_xor)
{
	uint64_t r[ARGON2_QWORDS], t[ARGON2_QWORDS];
	int i;

	for (i = 0; i < ARGON2_QWORDS; i++) {
		r[i] = t[i] = prev->v[i] ^ ref->v[i];
		if (with_xor)
			t[i] ^= next->v[i];
	}
	for (i = 0; i < 8; i++)
		A2_ROUND(r, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3,
			 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
			 16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11,
			 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
	for (i = 0; i < 8; i++)
		A2_ROUND(r, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17,
			 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49,
			 2 * i + 64, 2 * i + 65, 2 * i + 80, 2 * i + 81,
			 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);
	for (i = 0; i < ARGON2_QWORDS; i++)
		next->v[i] = t[i] ^ r[i];
}

#if defined(__x86_64__) && \
	(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
/*
 * AVX2: 4 words per vector, and two independent rows (or column pairs) at
 * a time, in the reference implementation's arrangement. (AVX-512VL's
 * rotation instructions make it no faster: the 24 and 16-bit rotations
 * are byte shuffles already.)
 */
#define A2_AVX2 1
#include <immintrin.h>

typedef uint64_t a2_v4 __attribute__((vector_size(32)));
typedef uint32_t a2_v8u32 __attribute__((vector_size(32)));
typedef uint8_t a2_v32u8 __attribute__((vector_size(32)));

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 12)
#define A2_SHUF4(a, b, i, j, k, l) __builtin_shufflevector(a, b, i, j, k, l)
#define A2_SHUF8(v, ...) ((a2_v4) __builtin_shufflevector((a2_v8u32) (v), \
	(a2_v8u32) (v), __VA_ARGS__))
#define A2_BYTES(v, ...) ((a2_v4) __builtin_shufflevector((a2_v32u8) (v), \
	(a2_v32u8) (v), __VA_ARGS__))
#else
#define A2_SHUF4(a, b, i, j, k, l) __builtin_shuffle(a, b, (a2_v4) { i, j, k, l })
#define A2_SHUF8(v, ...) ((a2_v4) __builtin_shuffle((a2_v8u32) (v), \
	(a2_v8u32) { __VA_ARGS__ }))
#define A2_BYTES(v, ...) ((a2_v4) __builtin_shuffle((a2_v32u8) (v), \
	(a2_v32u8) { __VA_ARGS__ }))
#endif

#define A2_BLAMKA4(x, y) ((x) + (y) + 2 * (a2_v4) _mm256_mul_epu32((__m256i) (x), (__m256i) (y)))
#define A2_ROTR32_4(x) A2_SHUF8(x, 1, 0, 3, 2, 5, 4, 7, 6)
/* by 24 and 16 bits: byte shuffles (vpshufb) */
#define A2_ROTR24_4(x) A2_BYTES(x, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, \
	19, 20, 21, 22, 23, 16, 17, 18, 27, 28, 29, 30, 31, 24, 25, 26)
#define A2_ROTR16_4(x) A2_BYTES(x, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, \
	18, 19, 20, 21, 22, 23, 16, 17, 26, 27, 28, 29, 30, 31, 24, 25)
#define A2_ROTR63_4(x) ((x) >> 63 | ((x) + (x)))

/* BLAKE2's G on the 4 lanes of A0..D0 and of A1..D1 */
#define A2_G_4(A0, A1, B0, B1, C0, C1, D0, D1, R24, R16) do { \
	A0 = A2_BLAMKA4(A0, B0); A1 = A2_BLAMKA4(A1, B1); \
	D0 = A2_ROTR32_4(D0 ^ A0); D1 = A2_ROTR32_4(D1 ^ A1); \
	C0 = A2_BLAMKA4(C0, D0); C1 = A2_BLAMKA4(C1, D1); \
	B0 = R24(B0 ^ C0); B1 = R24(B1 ^ C1); \
	A0 = A2_BLAMKA4(A0, B0); A1 = A2_BLAMKA4(A1, B1); \
	D0 = R16(D0 ^ A0); D1 = R16(D1 ^ A1); \
	C0 = A2_BLAMKA4(C0, D0); C1 = A2_BLAMKA4(C1, D1); \
	B0 = A2_ROTR63_4(B0 ^ C0); B1 = A2_ROTR63_4(B1 ^ C1); \
} while (0)

/* two rows: A..D0 and A..D1 each hold one row's 16 words; the diagonals
 * come from rotating rows b, c, d by 1, 2, 3 words */
#define A2_ROUND_ROWS(A0, A1, B0, B1, C0, C1, D0, D1, R24, R16) do { \
	A2_G_4(A0, A1, B0, B1, C0, C1, D0, D1, R24, R16); \
	B0 = A2_SHUF4(B0, B0, 1, 2, 3, 0); B1 = A2_SHUF4(B1, B1, 1, 2, 3, 0); \
	C0 = A2_SHUF4(C0, C0, 2, 3, 0, 1); C1 = A2_SHUF4(C1, C1, 2, 3, 0, 1); \
	D0 = A2_SHUF4(D0, D0, 3, 0, 1, 2); D1 = A2_SHUF4(D1, D1, 3, 0, 1, 2); \
	A2_G_4(A0, A1, B0, B1, C0, C1, D0, D1, R24, R16); \
	B0 = A2_SHUF4(B0, B0, 3, 0, 1, 2); B1 = A2_SHUF4(B1, B1, 3, 0, 1, 2); \
	C0 = A2_SHUF4(C0, C0, 2, 3, 0, 1); C1 = A2_SHUF4(C1, C1, 2, 3, 0, 1); \
	D0 = A2_SHUF4(D0, D0, 1, 2, 3, 0); D1 = A2_SHUF4(D1, D1, 1, 2, 3, 0); \
} while (0)

/* two column pairs: lanes 0-1 of every vector belong to one BLAKE2 state,
 * lanes 2-3 to the other; row a is (A0, A1) and so on */
#define A2_ROUND_COLS(A0, A1, B0, B1, C0, C1, D0, D1, R24, R16) do { \
	a2_v4 t0_, t1_; \
	A2_G_4(A0, A1, B0, B1, C0, C1, D0, D1, R24, R16); \
	t0_ = A2_SHUF4(B0, B1, 1, 4, 3, 6); t1_ = A2_SHUF4(B1, B0, 1, 4, 3, 6); B0 = t0_; B1 = t1_; \
	t0_ = A2_SHUF4(D1, D0, 1, 4, 3, 6); t1_ = A2_SHUF4(D0, D1, 1, 4, 3, 6); D0 = t0_; D1 = t1_; \
	A2_G_4(A0, A1, B0, B1, C1, C0, D0, D1, R24, R16); \
	t0_ = A2_SHUF4(B1, B0, 1, 4, 3, 6); t1_ = A2_SHUF4(B0, B1, 1, 4, 3, 6); B0 = t0_; B1 = t1_; \
	t0_ = A2_SHUF4(D0, D1, 1, 4, 3, 6); t1_ = A2_SHUF4(D1, D0, 1, 4, 3, 6); D0 = t0_; D1 = t1_; \
} while (0)

static __attribute__((target("avx2"))) void argon2_fill_avx2(
		const argon2_block *prev, const argon2_block *ref,
		argon2_block *next, bool with_xor)
{
	a2_v4 s[32], xy[32], r;
	int i;

	for (i = 0; i < 32; i++) {
		memcpy(&s[i], prev->v + 4 * i, 32);
		memcpy(&r, ref->v + 4 * i, 32);
		s[i] ^= r;
		xy[i] = s[i];
		if (with_xor) {
			memcpy(&r, next->v + 4 * i, 32);
			xy[i] ^= r;
		}
	}
	/* rows 2i and 2i + 1: vectors 8i .. 8i + 3 and 8i + 4 .. 8i + 7 */
	for (i = 0; i < 4; i++)
		A2_ROUND_ROWS(s[8 * i], s[8 * i + 4], s[8 * i + 1], s[8 * i + 5],
			      s[8 * i + 2], s[8 * i + 6], s[8 * i + 3], s[8 * i + 7],
			      A2_ROTR24_4, A2_ROTR16_4);
	/* columns 4i .. 4i + 3 */
	for (i = 0; i < 4; i++)
		A2_ROUND_COLS(s[i], s[4 + i], s[8 + i], s[12 + i],
			      s[16 + i], s[20 + i], s[24 + i], s[28 + i],
			      A2_ROTR24_4, A2_ROTR16_4);
	for (i = 0; i < 32; i++) {
		s[i] ^= xy[i];
		memcpy(next->v + 4 * i, &s[i], 32);
	}
}
#endif

/* -1: not chosen yet; 0: plain code; 1: AVX2 */
static _Atomic int a2_impl = -1;

static bool a2_supported(int impl)
{
	switch (impl) {
	case 0:
		return true;
#ifdef A2_AVX2
	case 1:
		return cpu_has_avx2();
#endif
	default:
		return false;
	}
}

static argon2_fill_fn a2_fill_fn(void)
{
	int impl = a2_impl;

	if (unlikely(impl < 0)) {
		for (impl = 1; !a2_supported(impl); impl--)
			;
		a2_impl = impl;
	}
#ifdef A2_AVX2
	if (impl == 1)
		return argon2_fill_avx2;
#endif
	return argon2_fill_scalar;
}

/* For the tests: use implementation impl (0: plain code, 1: AVX2) if
 * possible, the best one if impl < 0. Returns the one in use. */
int argon2d_use_impl(int impl)
{
	if (impl < 0 || !a2_supported(impl))
		impl = -1;
	a2_impl = impl;
	a2_fill_fn();
	return a2_impl;
}

const char *argon2d_impl_name(void)
{
	a2_fill_fn();
	return a2_impl == 1 ? "AVX2" : "plain 64-bit code";
}

/* ------------------------------------------------------------------ */

struct argon2_instance {
	argon2_block *memory;
	uint32_t passes, lanes, lane_length, segment_length, version;
};

/* where the reference block of a block is, among those allowed */
static uint32_t index_alpha(const struct argon2_instance *in, uint32_t pass,
		uint32_t slice, uint32_t index, uint32_t pseudo_rand, bool same_lane)
{
	uint32_t area, start = 0;
	uint64_t rel;

	if (pass == 0) {
		if (slice == 0)
			area = index - 1;	/* all but the previous block */
		else if (same_lane)
			area = slice * in->segment_length + index - 1;
		else
			area = slice * in->segment_length - (index == 0);
	} else {
		if (same_lane)
			area = in->lane_length - in->segment_length + index - 1;
		else
			area = in->lane_length - in->segment_length - (index == 0);
		if (slice != ARGON2_SYNC_POINTS - 1)
			start = (slice + 1) * in->segment_length;
	}
	rel = pseudo_rand;
	rel = rel * rel >> 32;
	rel = area - 1 - (area * rel >> 32);
	return (uint32_t) ((start + rel) % in->lane_length);
}

static void fill_segment(const struct argon2_instance *in, uint32_t pass,
		uint32_t slice, uint32_t lane, argon2_fill_fn fill)
{
	uint32_t start = pass == 0 && slice == 0 ? 2 : 0;	/* blocks 0, 1 are made from H0 */
	uint32_t curr = lane * in->lane_length + slice * in->segment_length + start;
	uint32_t prev = curr % in->lane_length == 0 ? curr + in->lane_length - 1 : curr - 1;
	uint32_t i;

	for (i = start; i < in->segment_length; i++, curr++, prev++) {
		uint64_t pseudo_rand;
		uint32_t ref_lane, ref_index;

		/* after the first block of a lane, prev is back in the lane */
		if (curr % in->lane_length == 1)
			prev = curr - 1;
		/* Argon2d: the previous block chooses the reference block */
		pseudo_rand = in->memory[prev].v[0];
		ref_lane = (uint32_t) ((pseudo_rand >> 32) % in->lanes);
		if (pass == 0 && slice == 0)
			ref_lane = lane;
		ref_index = index_alpha(in, pass, slice, i, (uint32_t) pseudo_rand,
				ref_lane == lane);
		fill(in->memory + prev, in->memory + in->lane_length * ref_lane + ref_index,
		     in->memory + curr, in->version != 0x10 && pass != 0);
	}
}

/* Argon2d's inputs besides the costs */
struct argon2d_input {
	const void *pwd, *salt, *secret, *ad;
	uint32_t pwdlen, saltlen, secretlen, adlen, outlen;
};

/* the Argon2d tag; memory: at least m_cost KiB, 64-byte aligned */
static void argon2d_core(uint8_t *out, const struct argon2d_input *x,
		const struct argon2d_params *p, argon2_block *memory)
{
	struct argon2_instance in;
	struct blake2b_state s;
	uint8_t h0[ARGON2_PREHASH + 8], word[4], block[ARGON2_BLOCK_SIZE];
	uint32_t blocks, pass, slice, lane, k;
	argon2_fill_fn fill = a2_fill_fn();
	argon2_block last;

	/* the memory: a multiple of 4 * lanes blocks, at least 8 per lane */
	blocks = p->m_cost;
	if (blocks < 2 * ARGON2_SYNC_POINTS * p->lanes)
		blocks = 2 * ARGON2_SYNC_POINTS * p->lanes;
	in.segment_length = blocks / (p->lanes * ARGON2_SYNC_POINTS);
	in.lane_length = in.segment_length * ARGON2_SYNC_POINTS;
	in.lanes = p->lanes;
	in.passes = p->t_cost;
	in.version = p->version;
	in.memory = memory;

	/* H0: the parameters and the inputs */
	blake2b_init(&s, ARGON2_PREHASH);
#define A2_WORD(v) do { le32enc(word, (v)); blake2b_update(&s, word, 4); } while (0)
	A2_WORD(p->lanes);
	A2_WORD(x->outlen);
	A2_WORD(p->m_cost);
	A2_WORD(p->t_cost);
	A2_WORD(p->version);
	A2_WORD(0);		/* Argon2d */
	A2_WORD(x->pwdlen);
	blake2b_update(&s, x->pwd, x->pwdlen);
	A2_WORD(x->saltlen);
	blake2b_update(&s, x->salt, x->saltlen);
	A2_WORD(x->secretlen);
	blake2b_update(&s, x->secret, x->secretlen);
	A2_WORD(x->adlen);
	blake2b_update(&s, x->ad, x->adlen);
#undef A2_WORD
	blake2b_final(&s, h0);

	/* the first two blocks of each lane */
	for (lane = 0; lane < p->lanes; lane++)
		for (k = 0; k < 2; k++) {
			argon2_block *b = &memory[lane * in.lane_length + k];

			le32enc(h0 + ARGON2_PREHASH, k);
			le32enc(h0 + ARGON2_PREHASH + 4, lane);
			blake2b_long(block, ARGON2_BLOCK_SIZE, h0, sizeof(h0));
			for (blocks = 0; blocks < ARGON2_QWORDS; blocks++)
				b->v[blocks] = le64dec_(block + 8 * blocks);
		}

	for (pass = 0; pass < in.passes; pass++)
		for (slice = 0; slice < ARGON2_SYNC_POINTS; slice++)
			for (lane = 0; lane < in.lanes; lane++)
				fill_segment(&in, pass, slice, lane, fill);

	/* the XOR of the lanes' last blocks, hashed */
	last = memory[in.lane_length - 1];
	for (lane = 1; lane < in.lanes; lane++)
		for (k = 0; k < ARGON2_QWORDS; k++)
			last.v[k] ^= memory[lane * in.lane_length + in.lane_length - 1].v[k];
	for (k = 0; k < ARGON2_QWORDS; k++)
		le64enc_(block + 8 * k, last.v[k]);
	blake2b_long(out, x->outlen, block, ARGON2_BLOCK_SIZE);
}

/* proof of work: the 80-byte header as password and salt, 32-byte tag */
static void argon2d_hash_mem(uint8_t out[32], const uint8_t *header,
		const struct argon2d_params *p, argon2_block *memory)
{
	const struct argon2d_input x = {
		header, header, NULL, NULL, 80, 80, 0, 0, 32
	};

	argon2d_core(out, &x, p, memory);
}

/* this thread's memory, enough for p, grown as needed */
static argon2_block *argon2_thread_memory(const struct argon2d_params *p)
{
	static __thread void *raw;
	static __thread argon2_block *mem;
	static __thread uint32_t size;
	uint32_t blocks = p->m_cost;

	if (blocks < 2 * ARGON2_SYNC_POINTS * p->lanes)
		blocks = 2 * ARGON2_SYNC_POINTS * p->lanes;

	if (unlikely(blocks > size)) {
		free(raw);
		raw = malloc((size_t) blocks * ARGON2_BLOCK_SIZE + 64);
		if (!raw) {
			size = 0;
			mem = NULL;
			applog(LOG_ERR, "Argon2d: cannot allocate %u KiB", blocks);
			return NULL;
		}
		mem = (argon2_block *) (((uintptr_t) raw + 63) & ~(uintptr_t) 63);
		size = blocks;
	}
	return mem;
}

/* For the tests: Argon2d with every input (RFC 9106's test vectors) */
int argon2d_raw(void *out, uint32_t outlen, const void *pwd, uint32_t pwdlen,
	const void *salt, uint32_t saltlen, const void *secret, uint32_t secretlen,
	const void *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost,
	uint32_t lanes, uint32_t version)
{
	const struct argon2d_params p = { t_cost, m_cost, lanes, version };
	const struct argon2d_input x = {
		pwd, salt, secret, ad, pwdlen, saltlen, secretlen, adlen, outlen
	};
	argon2_block *mem = argon2_thread_memory(&p);

	if (!mem)
		return -1;
	argon2d_core(out, &x, &p, mem);
	return 0;
}

void argon2d_hash(void *output, const void *input, int variant)
{
	const struct argon2d_params *p = &argon2d_variants[variant];
	argon2_block *mem = argon2_thread_memory(p);

	if (!mem) {
		memset(output, 0xff, 32);
		return;
	}
	argon2d_hash_mem(output, input, p, mem);
}

int scanhash_argon2d(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	int variant, uint32_t max_nonce, uint64_t *hashes_done)
{
	const struct argon2d_params *p = &argon2d_variants[variant];
	argon2_block *mem = argon2_thread_memory(p);
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint8_t header[80], out[32];
	uint32_t hash[8];
	int k;

	if (!mem) {
		*hashes_done = 0;
		return 0;
	}
	/* pdata holds the header as big-endian words */
	for (k = 0; k < 19; k++)
		be32enc(header + 4 * k, pdata[k]);

	do {
		pdata[19] = ++n;
		be32enc(header + 76, n);
		argon2d_hash_mem(out, header, p, mem);
		hash[7] = le32dec(out + 28);
		if (hash[7] <= Htarg) {
			for (k = 0; k < 7; k++)
				hash[k] = le32dec(out + 4 * k);
			if (fulltest(hash, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
