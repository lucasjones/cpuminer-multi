#include "miner.h"

#define BLAKE32_ROUNDS 8
#include "sha3/sph_blake.h"

void blakecoin_init(void *cc);
void blakecoin(void *cc, const void *data, size_t len);
void blakecoin_close(void *cc, void *dst);

#include <string.h>
#include <stdint.h>
#include <memory.h>

/* Move init out of loop, so init once externally,
 * and then use one single memcpy */
static sph_blake256_context blake_mid;
static bool ctx_midstate_done = false;

static void init_blake_hash(void)
{
	blakecoin_init(&blake_mid);
	ctx_midstate_done = true;
}

void blakecoinhash(void *state, const void *input)
{
	sph_blake256_context ctx;

	uint8_t hash[64];
	uint8_t *ending = (uint8_t*) input;
	ending += 64;

	// do one memcopy to get a fresh context
	if (!ctx_midstate_done) {
		init_blake_hash();
		blakecoin(&blake_mid, input, 64);
	}
	memcpy(&ctx, &blake_mid, sizeof(blake_mid));

	blakecoin(&ctx, ending, 16);
	blakecoin_close(&ctx, hash);

	memcpy(state, hash, 32);
}

int scanhash_blakecoin(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
					uint32_t max_nonce, uint64_t *hashes_done)
{
	const uint32_t first_nonce = pdata[19];
	uint32_t HTarget = ptarget[7];

	uint32_t _ALIGN(32) hash64[8];
	uint32_t _ALIGN(32) endiandata[20];

	uint32_t n = first_nonce;

	ctx_midstate_done = false;

	if (opt_benchmark)
		HTarget = 0x7f;

	// we need big endian data...
	for (int kk=0; kk < 19; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

#ifdef DEBUG_ALGO
	applog(LOG_DEBUG,"[%d] Target=%08x %08x", thr_id, ptarget[6], ptarget[7]);
#endif

	do {
		be32enc(&endiandata[19], n);
		blakecoinhash(hash64, endiandata);
#ifndef DEBUG_ALGO
		if (hash64[7] <= HTarget && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return true;
		}
#else
		if (!(n % 0x1000) && !thr_id) printf(".");
		if (hash64[7] == 0) {
			printf("[%d]",thr_id);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		}
#endif
		n++; pdata[19] = n;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
