#include "miner.h"

#include "sha3/sph_blake.h"

#include <string.h>
#include <stdint.h>
#include <memory.h>

/* Move init out of loop, so init once externally,
 * and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake256_context 	blake1;
} blakehash_context_holder;
static blakehash_context_holder base_contexts;
static bool ctx_init_made = false;

void init_blakehash_contexts(void)
{
	sph_blake256_init(&base_contexts.blake1);
	ctx_init_made = true;
}

extern void blakehash(void *state, const void *input)
{
	blakehash_context_holder ctx;

	uint32_t hashA[16];

	// do one memcopy to get fresh contexts,
	// its faster even with a larger block then issuing 9 memcopies
	if (!ctx_init_made)
		init_blakehash_contexts();
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	sph_blake256(&ctx.blake1, input, 80);
	sph_blake256_close (&ctx.blake1, hashA);
	memcpy(state, hashA, 32);
}

extern int scanhash_blake(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];
#ifdef WIN32
	uint32_t __declspec(align(32)) hash64[8];
#else
	uint32_t hash64[8] __attribute__((aligned(32)));
#endif
	uint32_t endiandata[32];

	for (int kk=0; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	}

	if (ptarget[7]==0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			blakehash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFFF)==0) &&
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else if (ptarget[7]<=0xF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			blakehash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFF0)==0) &&
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else if (ptarget[7]<=0xFF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			blakehash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) &&
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else if (ptarget[7]<=0xFFF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			blakehash(hash64, endiandata);
			if (((hash64[7]&0xFFFFF000)==0) &&
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);

	}
	else if (ptarget[7]<=0xFFFF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			blakehash(hash64, endiandata);
			if (((hash64[7]&0xFFFF0000)==0) &&
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);

	}
	else
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			blakehash(hash64, endiandata);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}


	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
