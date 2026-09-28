/*
 * Qubit, the proof of work of one of DigiByte's five mining algorithms
 * (and Myriad's until 2016): Luffa-512, CubeHash-512, SHAvite-512,
 * SIMD-512 and ECHO-512 in turn, keeping the first 256 bits.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

/* everything after Luffa, from Luffa's context */
static void qubit_from_luffa(void *output, sph_luffa512_context *ctx_luffa)
{
	sph_cubehash512_context ctx_cubehash;
	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;
	uint32_t hash[16];

	sph_luffa512_close(ctx_luffa, hash);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, hash, 64);
	sph_cubehash512_close(&ctx_cubehash, hash);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hash, 64);
	sph_shavite512_close(&ctx_shavite, hash);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hash, 64);
	sph_simd512_close(&ctx_simd, hash);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hash, 64);
	sph_echo512_close(&ctx_echo, hash);

	memcpy(output, hash, 32);
}

void qubithash(void *output, const void *input)
{
	sph_luffa512_context ctx_luffa;

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, input, 80);
	qubit_from_luffa(output, &ctx_luffa);
}

int scanhash_qubit(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[20];
	sph_luffa512_context ctx_mid, ctx;
	int k;

	/* the hash function takes the header in big-endian word order */
	for (k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	/* Luffa works in 32-byte blocks: the two before the nonce are the
	 * same for the whole scan, so they are processed once */
	sph_luffa512_init(&ctx_mid);
	sph_luffa512(&ctx_mid, endiandata, 76);

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		ctx = ctx_mid;
		sph_luffa512(&ctx, &endiandata[19], 4);
		qubit_from_luffa(hash64, &ctx);
		if (hash64[7] <= Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
