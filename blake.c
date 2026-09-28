#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake256_context 	blake1;
} blakehash_context_holder;

static blakehash_context_holder base_contexts;

void init_blakehash_contexts()
{
    sph_blake256_init(&base_contexts.blake1);
}

void blakehash(void *state, const void *input)
{
    blakehash_context_holder ctx;
//an array of uint32
    uint32_t hashA[8];
	

//do one memcopy to get fresh contexts, its faster even with a larger block then issuing 9 memcopies
    memcpy(&ctx, &base_contexts, sizeof(base_contexts));

    sph_blake256 (&ctx.blake1, input, 80);
    sph_blake256_close (&ctx.blake1, hashA);	 //0
    memcpy(state, hashA, 32);

}

int scanhash_blake(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[20];
	sph_blake256_context ctx_mid, ctx;
	int k;

	/* the hash function takes the header in big-endian word order */
	for (k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	/* Only the nonce changes: hash the 76 bytes before it once. That
	 * compresses the first 64-byte block, half the work of each hash. */
	sph_blake256_init(&ctx_mid);
	sph_blake256(&ctx_mid, endiandata, 76);

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		ctx = ctx_mid;
		sph_blake256(&ctx, &endiandata[19], 4);
		sph_blake256_close(&ctx, hash64);
		if (hash64[7] <= Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
