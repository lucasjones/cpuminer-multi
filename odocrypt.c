/*
 * Odocrypt, the proof of work of one of DigiByte's five mining algorithms:
 * an 80-byte block cipher whose design (s-boxes, p-boxes, rotations, round
 * keys) comes from a key, the block time rounded down to a whole number of
 * "shape change" periods (10 days on the main network), followed by 12
 * rounds of the Keccak-p[800] permutation.
 *
 * Ported to C from DigiByte Core's crypto/odocrypt.cpp and hashodo.h
 * (Copyright (c) 2009-2018 The DigiByte developers, MIT license), and the
 * Keccak team's KeccakP-800-reference.c (public domain).
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

#define ODO_ROUNDS		84
#define ODO_WORDS		10	/* the 80-byte state, as 64-bit words */
#define ODO_SMALL_SBOX_BITS	6	/* for FPGA logic elements */
#define ODO_LARGE_SBOX_BITS	10	/* for FPGA RAM blocks */
#define ODO_SMALL_SBOXES	(ODO_WORDS * 64 / (ODO_SMALL_SBOX_BITS + ODO_LARGE_SBOX_BITS))
#define ODO_LARGE_SBOXES	ODO_WORDS
#define ODO_PBOX_SUBROUNDS	6
#define ODO_ROTATIONS		6

struct odo_pbox {
	uint64_t mask[ODO_PBOX_SUBROUNDS][ODO_WORDS / 2];
	unsigned rotation[ODO_PBOX_SUBROUNDS - 1][ODO_WORDS / 2];
};

/* the cipher for one key */
struct odo_ctx {
	uint8_t sbox1[ODO_SMALL_SBOXES][1 << ODO_SMALL_SBOX_BITS];
	uint16_t sbox2[ODO_LARGE_SBOXES][1 << ODO_LARGE_SBOX_BITS];
	struct odo_pbox pbox[2];
	unsigned rotations[ODO_ROTATIONS];
	uint16_t round_key[ODO_ROUNDS];
	uint32_t key;
	bool valid;
};

/*
 * The generator the design comes from: the 1st, 3rd, 6th, 10th, ... output
 * of a Knuth linear congruential generator, so that every seed gives its
 * own sequence (not the same one from another starting point).
 */
struct odo_random {
	uint64_t current, multiplicand, addend;
};

static uint32_t odo_next_int(struct odo_random *r)
{
	r->addend += r->multiplicand * 1442695040888963407ULL;
	r->multiplicand *= 6364136223846793005ULL;
	r->current = r->current * r->multiplicand + r->addend;
	return (uint32_t) (r->current >> 32);
}

static uint64_t odo_next_long(struct odo_random *r)
{
	uint64_t hi = odo_next_int(r);

	return hi << 32 | odo_next_int(r);
}

/* in [0, n) */
static unsigned odo_next(struct odo_random *r, unsigned n)
{
	return (unsigned) (((uint64_t) odo_next_int(r) * n) >> 32);
}

/* a random permutation of 0 .. n-1 */
static void odo_permutation(struct odo_random *r, unsigned *a, unsigned n)
{
	unsigned i, j, t;

	for (i = 0; i < n; i++)
		a[i] = i;
	for (i = 1; i < n; i++) {
		j = odo_next(r, i + 1);
		t = a[i];
		a[i] = a[j];
		a[j] = t;
	}
}

static void odo_init(struct odo_ctx *ctx, uint32_t key)
{
	struct odo_random r = { key, 1, 0 };
	unsigned perm[1 << ODO_LARGE_SBOX_BITS], sum = 0;
	int i, j, k;

	for (i = 0; i < ODO_SMALL_SBOXES; i++) {
		odo_permutation(&r, perm, 1 << ODO_SMALL_SBOX_BITS);
		for (k = 0; k < 1 << ODO_SMALL_SBOX_BITS; k++)
			ctx->sbox1[i][k] = (uint8_t) perm[k];
	}
	for (i = 0; i < ODO_LARGE_SBOXES; i++) {
		odo_permutation(&r, perm, 1 << ODO_LARGE_SBOX_BITS);
		for (k = 0; k < 1 << ODO_LARGE_SBOX_BITS; k++)
			ctx->sbox2[i][k] = (uint16_t) perm[k];
	}
	for (i = 0; i < 2; i++) {
		struct odo_pbox *p = &ctx->pbox[i];

		for (j = 0; j < ODO_PBOX_SUBROUNDS; j++)
			for (k = 0; k < ODO_WORDS / 2; k++)
				p->mask[j][k] = odo_next_long(&r);
		for (j = 0; j < ODO_PBOX_SUBROUNDS - 1; j++)
			for (k = 0; k < ODO_WORDS / 2; k++)
				p->rotation[j][k] = odo_next(&r, 63) + 1;
	}
	/* rotations: distinct, non-zero, with an odd sum */
	odo_permutation(&r, perm, 63);
	for (j = 0; j < ODO_ROTATIONS - 1; j++) {
		ctx->rotations[j] = perm[j] + 1;
		sum += ctx->rotations[j];
	}
	for (j = ODO_ROTATIONS - 1; (perm[j] + 1 + sum) % 2 == 0; j++)
		;
	ctx->rotations[ODO_ROTATIONS - 1] = perm[j] + 1;
	for (i = 0; i < ODO_ROUNDS; i++)
		ctx->round_key[i] = (uint16_t) odo_next(&r, 1 << ODO_WORDS);
	ctx->key = key;
	ctx->valid = true;
}

static inline uint64_t rol64(uint64_t x, unsigned r)
{
	return x << (r & 63) | x >> (-r & 63);
}

/*
 * The rounds work on the state in ten local variables, with every loop
 * written out: compilers then keep it in registers even at -O2 (loops over
 * an array ran at 40% of the speed).
 */

/* swap the bits of a and b where m has a 1 */
#define ODO_SWAP(a, b, m) do { \
	uint64_t swp_ = (m) & ((a) ^ (b)); \
	(a) ^= swp_; \
	(b) ^= swp_; \
} while (0)

#define ODO_SWAPS(m) do { \
	ODO_SWAP(s0, s1, (m)[0]); ODO_SWAP(s2, s3, (m)[1]); \
	ODO_SWAP(s4, s5, (m)[2]); ODO_SWAP(s6, s7, (m)[3]); \
	ODO_SWAP(s8, s9, (m)[4]); \
} while (0)

/* move word i to 3 * i mod 10, then rotate the even words */
#define ODO_SHUFFLE_ROTATE(r) do { \
	t0 = s0; t1 = s7; t2 = s4; t3 = s1; t4 = s8; \
	t5 = s5; t6 = s2; t7 = s9; t8 = s6; t9 = s3; \
	s0 = rol64(t0, (r)[0]); s1 = t1; s2 = rol64(t2, (r)[1]); s3 = t3; \
	s4 = rol64(t4, (r)[2]); s5 = t5; s6 = rol64(t6, (r)[3]); s7 = t7; \
	s8 = rol64(t8, (r)[4]); s9 = t9; \
} while (0)

/* a p-box: 5 times swaps, shuffle and rotations, then swaps */
#define ODO_PBOX(p) do { \
	ODO_SWAPS((p)->mask[0]); ODO_SHUFFLE_ROTATE((p)->rotation[0]); \
	ODO_SWAPS((p)->mask[1]); ODO_SHUFFLE_ROTATE((p)->rotation[1]); \
	ODO_SWAPS((p)->mask[2]); ODO_SHUFFLE_ROTATE((p)->rotation[2]); \
	ODO_SWAPS((p)->mask[3]); ODO_SHUFFLE_ROTATE((p)->rotation[3]); \
	ODO_SWAPS((p)->mask[4]); ODO_SHUFFLE_ROTATE((p)->rotation[4]); \
	ODO_SWAPS((p)->mask[5]); \
} while (0)

/* word i: 6-bit s-box, 10-bit s-box, 4 times */
#define ODO_SBOX(w, i) do { \
	const uint8_t (*sb1_)[1 << ODO_SMALL_SBOX_BITS] = ctx->sbox1 + 4 * (i); \
	const uint16_t *sb2_ = ctx->sbox2[i]; \
	(w) = (uint64_t) sb1_[0][(w) & 0x3f] \
		| (uint64_t) sb2_[(w) >> 6 & 0x3ff] << 6 \
		| (uint64_t) sb1_[1][(w) >> 16 & 0x3f] << 16 \
		| (uint64_t) sb2_[(w) >> 22 & 0x3ff] << 22 \
		| (uint64_t) sb1_[2][(w) >> 32 & 0x3f] << 32 \
		| (uint64_t) sb2_[(w) >> 38 & 0x3ff] << 38 \
		| (uint64_t) sb1_[3][(w) >> 48 & 0x3f] << 48 \
		| (uint64_t) sb2_[(w) >> 54 & 0x3ff] << 54; \
} while (0)

/* linear mix: the next word and 6 rotations of the word itself */
#define ODO_MIX(w) (rol64(w, r0) ^ rol64(w, r1) ^ rol64(w, r2) \
	^ rol64(w, r3) ^ rol64(w, r4) ^ rol64(w, r5))

static void odo_encrypt(uint64_t s[ODO_WORDS], const struct odo_ctx *ctx)
{
	uint64_t s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3], s4 = s[4];
	uint64_t s5 = s[5], s6 = s[6], s7 = s[7], s8 = s[8], s9 = s[9];
	uint64_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, total;
	const unsigned r0 = ctx->rotations[0], r1 = ctx->rotations[1];
	const unsigned r2 = ctx->rotations[2], r3 = ctx->rotations[3];
	const unsigned r4 = ctx->rotations[4], r5 = ctx->rotations[5];
	int round;

	/* pre-mix: after this, 95% of the bits depend on a bit of the nonce */
	total = s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6 ^ s7 ^ s8 ^ s9;
	total ^= total >> 32;
	s0 ^= total; s1 ^= total; s2 ^= total; s3 ^= total; s4 ^= total;
	s5 ^= total; s6 ^= total; s7 ^= total; s8 ^= total; s9 ^= total;

	for (round = 0; round < ODO_ROUNDS; round++) {
		const unsigned rk = ctx->round_key[round];

		ODO_PBOX(&ctx->pbox[0]);
		ODO_SBOX(s0, 0); ODO_SBOX(s1, 1); ODO_SBOX(s2, 2); ODO_SBOX(s3, 3);
		ODO_SBOX(s4, 4); ODO_SBOX(s5, 5); ODO_SBOX(s6, 6); ODO_SBOX(s7, 7);
		ODO_SBOX(s8, 8); ODO_SBOX(s9, 9);
		ODO_PBOX(&ctx->pbox[1]);
		t0 = s1 ^ ODO_MIX(s0); t1 = s2 ^ ODO_MIX(s1);
		t2 = s3 ^ ODO_MIX(s2); t3 = s4 ^ ODO_MIX(s3);
		t4 = s5 ^ ODO_MIX(s4); t5 = s6 ^ ODO_MIX(s5);
		t6 = s7 ^ ODO_MIX(s6); t7 = s8 ^ ODO_MIX(s7);
		t8 = s9 ^ ODO_MIX(s8); t9 = s0 ^ ODO_MIX(s9);
		/* the round key: one bit per word */
		s0 = t0 ^ (rk & 1); s1 = t1 ^ (rk >> 1 & 1);
		s2 = t2 ^ (rk >> 2 & 1); s3 = t3 ^ (rk >> 3 & 1);
		s4 = t4 ^ (rk >> 4 & 1); s5 = t5 ^ (rk >> 5 & 1);
		s6 = t6 ^ (rk >> 6 & 1); s7 = t7 ^ (rk >> 7 & 1);
		s8 = t8 ^ (rk >> 8 & 1); s9 = t9 ^ (rk >> 9 & 1);
	}
	s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3; s[4] = s4;
	s[5] = s5; s[6] = s6; s[7] = s7; s[8] = s8; s[9] = s9;
}

/* Keccak-p[800] with 12 rounds: the last 12 of Keccak-f[800]'s 22 */
static void keccak_p800_12(uint32_t a[25])
{
	static const uint32_t rc[12] = {
		0x80008009, 0x8000000a, 0x8000808b, 0x0000008b,
		0x00008089, 0x00008003, 0x00008002, 0x00000080,
		0x0000800a, 0x8000000a, 0x80008081, 0x00008080,
	};
	/* rho offsets, and the pi step's lane order */
	static const unsigned char rho[25] = {
		 0,  1, 30, 28, 27,  4, 12,  6, 23, 20,  3, 10, 11,
		25,  7,  9, 13, 15, 21,  8, 18,  2, 29, 24, 14,
	};
	uint32_t c[5], d, b[25];
	int round, x, y;

	for (round = 0; round < 12; round++) {
		/* theta */
		for (x = 0; x < 5; x++)
			c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		for (x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ (c[(x + 1) % 5] << 1 | c[(x + 1) % 5] >> 31);
			for (y = 0; y < 25; y += 5)
				a[x + y] ^= d;
		}
		/* rho and pi: lane (x, y) goes to (y, 2x + 3y) */
		for (y = 0; y < 5; y++)
			for (x = 0; x < 5; x++) {
				uint32_t v = a[x + 5 * y];
				unsigned r = rho[x + 5 * y];

				b[y + 5 * ((2 * x + 3 * y) % 5)] =
					r ? v << r | v >> (32 - r) : v;
			}
		/* chi */
		for (y = 0; y < 25; y += 5)
			for (x = 0; x < 5; x++)
				a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
		/* iota */
		a[0] ^= rc[round];
	}
}

/*
 * The hash of an 80-byte header, as the 32-bit words of a 256-bit number,
 * least significant first: the cipher's 80 bytes, a 1 and zeros make the
 * 100-byte Keccak state, whose first 32 bytes are the hash.
 */
static void odo_hash_words(uint32_t hash[8], const unsigned char *header,
		const struct odo_ctx *ctx)
{
	uint64_t s[ODO_WORDS];
	uint32_t a[25];
	int i;

	for (i = 0; i < ODO_WORDS; i++)
		s[i] = (uint64_t) le32dec(header + 8 * i)
			| (uint64_t) le32dec(header + 8 * i + 4) << 32;
	odo_encrypt(s, ctx);
	for (i = 0; i < ODO_WORDS; i++) {
		a[2 * i] = (uint32_t) s[i];
		a[2 * i + 1] = (uint32_t) (s[i] >> 32);
	}
	a[20] = 1;
	a[21] = a[22] = a[23] = a[24] = 0;
	keccak_p800_12(a);
	memcpy(hash, a, 32);
}

/* this thread's cipher, for key */
static const struct odo_ctx *odo_thread_ctx(uint32_t key)
{
	static __thread struct odo_ctx *ctx;

	if (unlikely(!ctx)) {
		ctx = malloc(sizeof(*ctx));
		if (!ctx) {
			applog(LOG_ERR, "Odocrypt: out of memory");
			return NULL;
		}
		ctx->valid = false;
	}
	if (!ctx->valid || ctx->key != key)
		odo_init(ctx, key);
	return ctx;
}

/* the cipher alone, on 80 bytes (for its test vectors) */
void odo_encrypt_block(void *output, const void *input, uint32_t key)
{
	const struct odo_ctx *ctx = odo_thread_ctx(key);
	const unsigned char *in = input;
	unsigned char *out = output;
	uint64_t s[ODO_WORDS];
	int i;

	if (!ctx) {
		memset(output, 0, 80);
		return;
	}
	for (i = 0; i < ODO_WORDS; i++)
		s[i] = (uint64_t) le32dec(in + 8 * i)
			| (uint64_t) le32dec(in + 8 * i + 4) << 32;
	odo_encrypt(s, ctx);
	for (i = 0; i < ODO_WORDS; i++) {
		le32enc(out + 8 * i, (uint32_t) s[i]);
		le32enc(out + 8 * i + 4, (uint32_t) (s[i] >> 32));
	}
}

uint32_t odo_key(uint32_t ntime, uint32_t interval)
{
	return ntime - ntime % interval;
}

void odo_hash(void *output, const void *input, uint32_t key)
{
	const struct odo_ctx *ctx = odo_thread_ctx(key);
	uint32_t hash[8];
	int i;

	if (!ctx) {
		memset(output, 0xff, 32);
		return;
	}
	odo_hash_words(hash, input, ctx);
	for (i = 0; i < 8; i++)
		le32enc((unsigned char *) output + 4 * i, hash[i]);
}

/* the main network's key for the block time in the header */
void odohash(void *output, const void *input)
{
	uint32_t ntime = le32dec((const unsigned char *) input + 68);

	odo_hash(output, input, odo_key(ntime, ODO_INTERVAL_MAINNET));
}

int scanhash_odo(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t key, uint32_t max_nonce, uint64_t *hashes_done)
{
	const struct odo_ctx *ctx = odo_thread_ctx(key);
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	unsigned char header[80];
	uint32_t hash[8];
	int k;

	if (!ctx) {
		*hashes_done = 0;
		return 0;
	}
	/* pdata holds the header as big-endian words */
	for (k = 0; k < 19; k++)
		be32enc(header + 4 * k, pdata[k]);

	do {
		pdata[19] = ++n;
		be32enc(header + 76, n);
		odo_hash_words(hash, header, ctx);
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
