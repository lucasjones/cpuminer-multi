#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_shavite.h"

void inkhash(void *state, const void *input)
{
    sph_shavite512_context	 ctx_shavite;
    uint32_t hash[16];
	
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512 (&ctx_shavite, (const void*) input, 80);
    sph_shavite512_close(&ctx_shavite, (void*) hash);
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, (const void*) hash, 64);
    sph_shavite512_close(&ctx_shavite, (void*) hash);

    memcpy(state, hash, 32);

}

int scanhash_ink(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[20];
	int k;

	/* the hash function takes the header in big-endian word order */
	for (k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		inkhash(hash64, endiandata);
		if (hash64[7] <= Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
