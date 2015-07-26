#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_shabal.h"

void axiomhash(void *output, const void *input)
{
	uint32_t _ALIGN(128) M[65536][8];
	sph_shabal256_context ctx;
	int R = 2, N = 65536;

	sph_shabal256_init(&ctx);
	sph_shabal256(&ctx, input, 80);
	sph_shabal256_close(&ctx, M[0]);

	for(int i = 1; i < N; i++) {
		//sph_shabal256_init(&ctx);
		sph_shabal256(&ctx, M[i-1], 32);
		sph_shabal256_close(&ctx, M[i]);
	}

	for(int r = 1; r < R; r ++)
	{
		for(int b = 0; b < N; b++)
		{
			int p = (b - 1 + N) % N;
			int q = M[p][0] % 0xFFFF;
			int j = (b + q) % N;
			uint32_t _ALIGN(128) pj[2][8];

			memcpy(&pj[0], &M[p], 32);
			memcpy(&pj[1], &M[j], 32);

			//HashShabal((unsigned char*)&pj[0], 2 * sizeof(pj[0]), (unsigned char*)&M[b]);
			//sph_shabal256_init(&ctx);
			sph_shabal256(&ctx, (unsigned char*) (&pj[0]), 64);
			sph_shabal256_close(&ctx, M[b]);
		}
	}

	memcpy(output, M[N-1], 32);
}

int scanhash_axiom(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
		axiomhash(hash64, endiandata);
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
