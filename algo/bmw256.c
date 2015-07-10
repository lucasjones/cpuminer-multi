#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_bmw.h"

void bmwhash(void *output, const void *input)
{
	uint32_t hash[16];
	sph_bmw256_context ctx;

	sph_bmw256_init(&ctx);
	sph_bmw256(&ctx, input, 80);
	sph_bmw256_close(&ctx, hash);

	memcpy(output, hash, 32);
}

int scanhash_bmw(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	};

	do {
		be32enc(&endiandata[19], n);
		bmwhash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
