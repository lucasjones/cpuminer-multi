#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_groestl.h"

// static __thread sph_groestl512_context ctx;

void groestlhash(void *output, const void *input)
{
	uint32_t _ALIGN(32) hash[16];
	sph_groestl512_context ctx;

	// memset(&hash[0], 0, sizeof(hash));

	sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, input, 80);
	sph_groestl512_close(&ctx, hash);

	//sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, hash, 64);
	sph_groestl512_close(&ctx, hash);

	memcpy(output, hash, 32);
}

int scanhash_groestl(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], ((uint32_t*)pdata)[k]);

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		groestlhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
