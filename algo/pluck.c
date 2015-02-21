/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2014 pooler, 2015 Jordan Earls
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdlib.h>
#include <string.h>

#define BLOCK_HEADER_SIZE 80

// windows
#ifndef htobe32
#define htobe32(x)  ((uint32_t)htonl((uint32_t)(x)))
#endif

// note, this is 64 bits
#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

#ifdef _MSC_VER
//#include "scryptjane/scrypt-jane-portable-x86.h"
#endif

#if defined(_MSC_VER) && defined(_M_X64)
#define _VECTOR __vectorcall
#include <intrin.h>
//#include <emmintrin.h> //SSE2
//#include <pmmintrin.h> //SSE3
//#include <tmmintrin.h> //SSSE3
//#include <smmintrin.h> //SSE4.1
//#include <nmmintrin.h> //SSE4.2
//#include <ammintrin.h> //SSE4A
//#include <wmmintrin.h> //AES
//#include <immintrin.h> //AVX
#define OPT_COMPATIBLE
#elif defined(__GNUC__) && defined(__x86_64__)
#include <x86intrin.h>
#define _VECTOR
#endif

#ifdef OPT_COMPATIBLE
static void _VECTOR xor_salsa8(__m128i B[4], const __m128i Bx[4])
{
	__m128i X0, X1, X2, X3;

	X0 = B[0] = _mm_xor_si128(B[0], Bx[0]);
	X1 = B[1] = _mm_xor_si128(B[1], Bx[1]);
	X2 = B[2] = _mm_xor_si128(B[2], Bx[2]);
	X3 = B[3] = _mm_xor_si128(B[3], Bx[3]);

	for (int i = 0; i < 4; i++) {
		/* Operate on columns. */
		X1.m128i_u32[0] ^= ROTL(X0.m128i_u32[0] + X3.m128i_u32[0], 7);  X2.m128i_u32[1] ^= ROTL(X1.m128i_u32[1] + X0.m128i_u32[1], 7);
		X3.m128i_u32[2] ^= ROTL(X2.m128i_u32[2] + X1.m128i_u32[2], 7);  X0.m128i_u32[3] ^= ROTL(X3.m128i_u32[3] + X2.m128i_u32[3], 7);
		X2.m128i_u32[0] ^= ROTL(X1.m128i_u32[0] + X0.m128i_u32[0], 9);  X3.m128i_u32[1] ^= ROTL(X2.m128i_u32[1] + X1.m128i_u32[1], 9);
		X0.m128i_u32[2] ^= ROTL(X3.m128i_u32[2] + X2.m128i_u32[2], 9);  X1.m128i_u32[3] ^= ROTL(X0.m128i_u32[3] + X3.m128i_u32[3], 9);

		X3.m128i_u32[0] ^= ROTL(X2.m128i_u32[0] + X1.m128i_u32[0], 13);  X0.m128i_u32[1] ^= ROTL(X3.m128i_u32[1] + X2.m128i_u32[1], 13);
		X1.m128i_u32[2] ^= ROTL(X0.m128i_u32[2] + X3.m128i_u32[2], 13);  X2.m128i_u32[3] ^= ROTL(X1.m128i_u32[3] + X0.m128i_u32[3], 13);
		X0.m128i_u32[0] ^= ROTL(X3.m128i_u32[0] + X2.m128i_u32[0], 18);  X1.m128i_u32[1] ^= ROTL(X0.m128i_u32[1] + X3.m128i_u32[1], 18);
		X2.m128i_u32[2] ^= ROTL(X1.m128i_u32[2] + X0.m128i_u32[2], 18);  X3.m128i_u32[3] ^= ROTL(X2.m128i_u32[3] + X1.m128i_u32[3], 18);

		/* Operate on rows. */
		X0.m128i_u32[1] ^= ROTL(X0.m128i_u32[0] + X0.m128i_u32[3], 7);  X1.m128i_u32[2] ^= ROTL(X1.m128i_u32[1] + X1.m128i_u32[0], 7);
		X2.m128i_u32[3] ^= ROTL(X2.m128i_u32[2] + X2.m128i_u32[1], 7);  X3.m128i_u32[0] ^= ROTL(X3.m128i_u32[3] + X3.m128i_u32[2], 7);
		X0.m128i_u32[2] ^= ROTL(X0.m128i_u32[1] + X0.m128i_u32[0], 9);  X1.m128i_u32[3] ^= ROTL(X1.m128i_u32[2] + X1.m128i_u32[1], 9);
		X2.m128i_u32[0] ^= ROTL(X2.m128i_u32[3] + X2.m128i_u32[2], 9);  X3.m128i_u32[1] ^= ROTL(X3.m128i_u32[0] + X3.m128i_u32[3], 9);

		X0.m128i_u32[3] ^= ROTL(X0.m128i_u32[2] + X0.m128i_u32[1], 13);  X1.m128i_u32[0] ^= ROTL(X1.m128i_u32[3] + X1.m128i_u32[2], 13);
		X2.m128i_u32[1] ^= ROTL(X2.m128i_u32[0] + X2.m128i_u32[3], 13);  X3.m128i_u32[2] ^= ROTL(X3.m128i_u32[1] + X3.m128i_u32[0], 13);
		X0.m128i_u32[0] ^= ROTL(X0.m128i_u32[3] + X0.m128i_u32[2], 18);  X1.m128i_u32[1] ^= ROTL(X1.m128i_u32[0] + X1.m128i_u32[3], 18);
		X2.m128i_u32[2] ^= ROTL(X2.m128i_u32[1] + X2.m128i_u32[0], 18);  X3.m128i_u32[3] ^= ROTL(X3.m128i_u32[2] + X3.m128i_u32[1], 18);
	}

	B[0] = _mm_add_epi32(B[0], X0);
	B[1] = _mm_add_epi32(B[1], X1);
	B[2] = _mm_add_epi32(B[2], X2);
	B[3] = _mm_add_epi32(B[3], X3);
}

#else

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
		x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

		x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
		x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

		x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
		x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

		x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
		x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

		x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

#endif

//computes a single sha256 hash
static void sha256_hash(unsigned char *hash, const unsigned char *data, int len)
{
	uint32_t _ALIGN(64) S[16];
	uint32_t _ALIGN(64) T[16];
	int i, r;

	sha256_init(S);
	for (r = len; r > -9; r -= 64) {
		if (r < 64)
			memset(T, 0, 64);
		memcpy(T, data + len - r, r > 64 ? 64 : (r < 0 ? 0 : r));
		if (r >= 0 && r < 64)
			((unsigned char *)T)[r] = 0x80;
		for (i = 0; i < 16; i++)
			T[i] = be32dec(T + i);
		if (r < 56)
			T[15] = 8 * len;
		sha256_transform(S, T, 0);
	}
	for (i = 0; i < 8; i++)
		be32enc((uint32_t *)hash + i, S[i]);
}

//hash exactly 64 bytes (ie, sha256 block size)
static void sha256_hash512(unsigned char *hash, const unsigned char *data)
{
	uint32_t _ALIGN(64) S[16];
	uint32_t _ALIGN(64) T[16];
	int i;
	sha256_init(S);

	memcpy(T, data, 64);
	for (i = 0; i < 16; i++)
		T[i] = be32dec(T + i);
	sha256_transform(S, T, 0);

	memset(T, 0, 64);
	//memcpy(T, data + 64, 0);
	((unsigned char *)T)[0] = 0x80;
	for (i = 0; i < 16; i++)
		T[i] = be32dec(T + i);
		T[15] = 8 * 64;
	sha256_transform(S, T, 0);

	for (i = 0; i < 8; i++)
		be32enc((uint32_t *)hash + i, S[i]);
}

void pluck_hash(uint32_t *hash, const uint32_t *data, uchar *hashbuffer, const int N)
{
	int size = N * 1024;
	memset(hashbuffer, 0, 64);
	sha256_hash(hashbuffer, (void*) data, BLOCK_HEADER_SIZE);

	for(int i = 64; i < size - 32; i += 32)
	{
		//i-4 because we use integers for all references against this, and we don't want to go 3 bytes over the defined area
		//we could use size here, but then it's probable to use 0 as the value in most cases
		int randmax = i - 4;
		uint32_t joint[16], randbuffer[16], randseed[16];

		//setup randbuffer to be an array of random indexes
		memcpy(randseed, hashbuffer + i - 64, 64);

		if(i > 128) memcpy(randbuffer, hashbuffer + i - 128, 64);
		else memset(randbuffer, 0, 64);

		xor_salsa8((void*) randbuffer, (void*) randseed);
		memcpy(joint, hashbuffer + i - 32, 32);

		//use the last hash value as the seed
		for (int j = 32; j < 64; j += 4)
		{
			//every other time, change to next random index
			//randmax - 32 as otherwise we go beyond memory that's already been written to
			uint32_t rand = randbuffer[(j - 32) >> 2] % (randmax - 32);
			joint[j >> 2] = *((uint32_t *)(hashbuffer + rand));
		}

		sha256_hash512(hashbuffer + i, (unsigned char *) joint);

		//setup randbuffer to be an array of random indexes
		//use last hash value and previous hash value(post-mixing)
		memcpy(randseed, hashbuffer + i - 32, 64);

		if(i > 128) memcpy(randbuffer, hashbuffer + i - 128, 64);
		else memset(randbuffer, 0, 64);

		xor_salsa8((void*) randbuffer, (void*) randseed);

		//use the last hash value as the seed
		for (int j = 0; j < 32; j += 2)
		{
			uint32_t rand = randbuffer[j >> 1] % randmax;
			*((uint32_t *)(hashbuffer + rand)) = *((uint32_t *)(hashbuffer + j + randmax));
		}
	}

	//note: off-by-one error is likely here...
	for(int i = size - 64 - 1; i >= 64; i -= 64)
		sha256_hash512(hashbuffer + i - 64, hashbuffer + i);

	memcpy(hash, hashbuffer, 32);
}

int scanhash_pluck(int thr_id, uint32_t *pdata,
	unsigned char *scratchbuf, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done, int N)
{
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t _ALIGN(64) hash[8];
	const uint32_t first_nonce = pdata[19];
	volatile uint8_t *restart = &(work_restart[thr_id].restart);
	uint32_t n = first_nonce;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0ffff;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	const uint32_t Htarg = ptarget[7];
	do {
		be32enc(&endiandata[19], n);
		pluck_hash(hash, endiandata, scratchbuf, N);

		if (hash[7] <= Htarg && fulltest(hash, ptarget))
		{
			*hashes_done = n - first_nonce + 1;
			pdata[19] = htobe32(endiandata[19]);
			return 1;
		}
		n++;
	} while (n < max_nonce && !(*restart));

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
