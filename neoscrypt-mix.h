/*
 * NeoScrypt's Salsa20/ChaCha20 part for 2 * NEO_W hashes at a time: two
 * independent chains (the processor works on one while the other waits
 * for its results), each a vector type NEO_VT holding NEO_W hashes, 4
 * lanes (one row of a 64-byte block) per hash.
 *
 * Included by neoscrypt.c once per instruction set, with:
 *   NEO_VT          the vector type (4 * NEO_W lanes of uint32_t)
 *   NEO_W           hashes per vector (1 or 2)
 *   NEO_ATTR        function attributes (the instruction set)
 *   NEO_NAME(f)     f with this variant's suffix
 *   NEO_ROT(v, n)   v with the lanes of each group of 4 rotated
 *                   (lane i gets lane (i + n) % 4, n = 1, 2 or 3)
 *   NEO_ROTL16(v), NEO_ROTL8(v)  optional: faster 32-bit rotations
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define NEO_ROTL(v, n) ((v) << (n) | (v) >> (32 - (n)))
#ifndef NEO_ROTL16
#define NEO_ROTL16(v) NEO_ROTL(v, 16)
#endif
#ifndef NEO_ROTL8
#define NEO_ROTL8(v) NEO_ROTL(v, 8)
#endif

/* Salsa20/20 on one block of each chain, in diagonal word order */
static inline NEO_ATTR void NEO_NAME(salsa_x2)(NEO_VT *a, NEO_VT *b)
{
	NEO_VT x0 = a[0], x1 = a[1], x2 = a[2], x3 = a[3];
	NEO_VT y0 = b[0], y1 = b[1], y2 = b[2], y3 = b[3];
	int i;

	for (i = 0; i < 10; i++) {
		/* columns */
		x1 ^= NEO_ROTL(x0 + x3, 7);	y1 ^= NEO_ROTL(y0 + y3, 7);
		x2 ^= NEO_ROTL(x1 + x0, 9);	y2 ^= NEO_ROTL(y1 + y0, 9);
		x3 ^= NEO_ROTL(x2 + x1, 13);	y3 ^= NEO_ROTL(y2 + y1, 13);
		x0 ^= NEO_ROTL(x3 + x2, 18);	y0 ^= NEO_ROTL(y3 + y2, 18);
		x1 = NEO_ROT(x1, 3);		y1 = NEO_ROT(y1, 3);
		x2 = NEO_ROT(x2, 2);		y2 = NEO_ROT(y2, 2);
		x3 = NEO_ROT(x3, 1);		y3 = NEO_ROT(y3, 1);
		/* rows */
		x3 ^= NEO_ROTL(x0 + x1, 7);	y3 ^= NEO_ROTL(y0 + y1, 7);
		x2 ^= NEO_ROTL(x3 + x0, 9);	y2 ^= NEO_ROTL(y3 + y0, 9);
		x1 ^= NEO_ROTL(x2 + x3, 13);	y1 ^= NEO_ROTL(y2 + y3, 13);
		x0 ^= NEO_ROTL(x1 + x2, 18);	y0 ^= NEO_ROTL(y1 + y2, 18);
		x1 = NEO_ROT(x1, 1);		y1 = NEO_ROT(y1, 1);
		x2 = NEO_ROT(x2, 2);		y2 = NEO_ROT(y2, 2);
		x3 = NEO_ROT(x3, 3);		y3 = NEO_ROT(y3, 3);
	}
	a[0] += x0; a[1] += x1; a[2] += x2; a[3] += x3;
	b[0] += y0; b[1] += y1; b[2] += y2; b[3] += y3;
}

/* ChaCha20/20 on one block of each chain, in natural word order */
static inline NEO_ATTR void NEO_NAME(chacha_x2)(NEO_VT *a, NEO_VT *b)
{
	NEO_VT x0 = a[0], x1 = a[1], x2 = a[2], x3 = a[3];
	NEO_VT y0 = b[0], y1 = b[1], y2 = b[2], y3 = b[3];
	int i;

	for (i = 0; i < 10; i++) {
		/* columns */
		x0 += x1; x3 = NEO_ROTL16(x3 ^ x0);	y0 += y1; y3 = NEO_ROTL16(y3 ^ y0);
		x2 += x3; x1 = NEO_ROTL(x1 ^ x2, 12);	y2 += y3; y1 = NEO_ROTL(y1 ^ y2, 12);
		x0 += x1; x3 = NEO_ROTL8(x3 ^ x0);	y0 += y1; y3 = NEO_ROTL8(y3 ^ y0);
		x2 += x3; x1 = NEO_ROTL(x1 ^ x2, 7);	y2 += y3; y1 = NEO_ROTL(y1 ^ y2, 7);
		x1 = NEO_ROT(x1, 1);			y1 = NEO_ROT(y1, 1);
		x2 = NEO_ROT(x2, 2);			y2 = NEO_ROT(y2, 2);
		x3 = NEO_ROT(x3, 3);			y3 = NEO_ROT(y3, 3);
		/* diagonals */
		x0 += x1; x3 = NEO_ROTL16(x3 ^ x0);	y0 += y1; y3 = NEO_ROTL16(y3 ^ y0);
		x2 += x3; x1 = NEO_ROTL(x1 ^ x2, 12);	y2 += y3; y1 = NEO_ROTL(y1 ^ y2, 12);
		x0 += x1; x3 = NEO_ROTL8(x3 ^ x0);	y0 += y1; y3 = NEO_ROTL8(y3 ^ y0);
		x2 += x3; x1 = NEO_ROTL(x1 ^ x2, 7);	y2 += y3; y1 = NEO_ROTL(y1 ^ y2, 7);
		x1 = NEO_ROT(x1, 3);			y1 = NEO_ROT(y1, 3);
		x2 = NEO_ROT(x2, 2);			y2 = NEO_ROT(y2, 2);
		x3 = NEO_ROT(x3, 1);			y3 = NEO_ROT(y3, 1);
	}
	a[0] += x0; a[1] += x1; a[2] += x2; a[3] += x3;
	b[0] += y0; b[1] += y1; b[2] += y2; b[3] += y3;
}

/*
 * The block mix with r = 2 on both chains: each 64-byte block, XOR the
 * previous one (the first: the last), goes through the core; then the
 * middle two blocks swap places.
 */
#define NEO_BLKMIX(x, y, core) do { \
	int k_; \
	for (k_ = 0; k_ < 4; k_++) { x[k_] ^= x[12 + k_]; y[k_] ^= y[12 + k_]; } \
	core(x, y); \
	for (k_ = 0; k_ < 4; k_++) { x[4 + k_] ^= x[k_]; y[4 + k_] ^= y[k_]; } \
	core(x + 4, y + 4); \
	for (k_ = 0; k_ < 4; k_++) { x[8 + k_] ^= x[4 + k_]; y[8 + k_] ^= y[4 + k_]; } \
	core(x + 8, y + 8); \
	for (k_ = 0; k_ < 4; k_++) { x[12 + k_] ^= x[8 + k_]; y[12 + k_] ^= y[8 + k_]; } \
	core(x + 12, y + 12); \
	for (k_ = 0; k_ < 4; k_++) { \
		NEO_VT t_ = x[4 + k_]; x[4 + k_] = x[8 + k_]; x[8 + k_] = t_; \
		t_ = y[4 + k_]; y[4 + k_] = y[8 + k_]; y[8 + k_] = t_; \
	} \
} while (0)

/* the V entry each hash of the vector picks, j[w] for hash w */
#if NEO_W == 1
#define NEO_PICK(v, j, k) ((v)[16 * (j)[0] + (k)])
#else
#define NEO_PICK(v, j, k) NEO_BLEND((v)[16 * (j)[0] + (k)], (v)[16 * (j)[1] + (k)])
#endif

/*
 * scrypt's SMix with N = 128 on both chains, v holding 2 * 128 blocks:
 * a hash's index into v is the first word of its last 64-byte block,
 * lane 0 of its group in vector 12 (in both word orders).
 */
#define NEO_SMIX(x, y, v, core) do { \
	NEO_VT *vx_ = (v), *vy_ = (v) + 16 * NEO_N; \
	unsigned jx_[NEO_W], jy_[NEO_W]; \
	int i_, k_, w_; \
	for (i_ = 0; i_ < NEO_N; i_++) { \
		memcpy(vx_ + 16 * i_, x, 16 * sizeof(NEO_VT)); \
		memcpy(vy_ + 16 * i_, y, 16 * sizeof(NEO_VT)); \
		NEO_BLKMIX(x, y, core); \
	} \
	for (i_ = 0; i_ < NEO_N; i_++) { \
		for (w_ = 0; w_ < NEO_W; w_++) { \
			jx_[w_] = x[12][4 * w_] & (NEO_N - 1); \
			jy_[w_] = y[12][4 * w_] & (NEO_N - 1); \
		} \
		for (k_ = 0; k_ < 16; k_++) { \
			x[k_] ^= NEO_PICK(vx_, jx_, k_); \
			y[k_] ^= NEO_PICK(vy_, jy_, k_); \
		} \
		NEO_BLKMIX(x, y, core); \
	} \
} while (0)

/* buf[h] (256 bytes) into lanes: hash h is chain h / NEO_W, group
 * h % NEO_W; diagonal: Salsa20's word order */
static NEO_ATTR void NEO_NAME(neo_load)(NEO_VT *x, NEO_VT *y,
		uint8_t (*buf)[256], bool diagonal)
{
	int h, k, i;

	for (h = 0; h < 2 * NEO_W; h++) {
		NEO_VT *d = h < NEO_W ? x : y;
		int g = 4 * (h % NEO_W);

		for (k = 0; k < 64; k++) {
			i = diagonal ? (k & ~15) | (5 * k % 16) : k;
			d[k / 4][g + k % 4] = le32dec(buf[h] + 4 * i);
		}
	}
}

/* XOR the lanes into buf[] */
static NEO_ATTR void NEO_NAME(neo_xor_store)(uint8_t (*buf)[256],
		const NEO_VT *x, const NEO_VT *y, bool diagonal)
{
	int h, k, i;

	for (h = 0; h < 2 * NEO_W; h++) {
		const NEO_VT *s = h < NEO_W ? x : y;
		int g = 4 * (h % NEO_W);

		for (k = 0; k < 64; k++) {
			i = diagonal ? (k & ~15) | (5 * k % 16) : k;
			le32enc(buf[h] + 4 * i, le32dec(buf[h] + 4 * i) ^ s[k / 4][g + k % 4]);
		}
	}
}

/*
 * For 2 * NEO_W hashes: buf[h], FastKDF's output, becomes the XOR of its
 * ChaCha20 SMix and its Salsa20 SMix. v: 2 * 128 * 16 vectors of scratch.
 */
static NEO_ATTR void NEO_NAME(neo_mix)(uint8_t (*buf)[256], NEO_VT *v)
{
	NEO_VT x[16], y[16], z[16], u[16];
	int h;

	NEO_NAME(neo_load)(z, u, buf, false);
	NEO_NAME(neo_load)(x, y, buf, true);
	NEO_SMIX(z, u, v, NEO_NAME(chacha_x2));
	NEO_SMIX(x, y, v, NEO_NAME(salsa_x2));
	for (h = 0; h < 2 * NEO_W; h++)
		memset(buf[h], 0, 256);
	NEO_NAME(neo_xor_store)(buf, z, u, false);
	NEO_NAME(neo_xor_store)(buf, x, y, true);
}

#undef NEO_ROTL
#undef NEO_ROTL16
#undef NEO_ROTL8
#undef NEO_BLKMIX
#undef NEO_PICK
#undef NEO_SMIX
