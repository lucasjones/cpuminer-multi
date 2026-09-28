#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_skein.h"

void skeinhash(void *state, const void *input)
{
    sph_skein512_context ctx_skein;
    uint32_t hashA[16];

    /* SHA-256(Skein-512(header)), as used by Skeincoin, Myriadcoin (until
     * 2019) and DigiByte's Skein algorithm */
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, input, 80);
    sph_skein512_close(&ctx_skein, hashA);

    sha256_hash(state, (const unsigned char *)hashA, 64);
}

int scanhash_skein(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[20], hashA[16];
	sph_skein512_context ctx_mid, ctx;
	int k;

	/* the hash function takes the header in big-endian word order */
	for (k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	/* Only the nonce changes: hash the 76 bytes before it once. That
	 * processes the first 64-byte block, one of the three Threefish
	 * calls each hash used to make. */
	sph_skein512_init(&ctx_mid);
	sph_skein512(&ctx_mid, endiandata, 76);

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		ctx = ctx_mid;
		sph_skein512(&ctx, &endiandata[19], 4);
		sph_skein512_close(&ctx, hashA);
		sha256_hash((unsigned char *) hash64, (const unsigned char *) hashA, 64);
		if (hash64[7] <= Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
