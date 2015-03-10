#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

void animehash(void *state, const void *input)
{
	sph_bmw512_context ctx_bmw;
	sph_blake512_context ctx_blake;
	sph_groestl512_context ctx_groestl;
	sph_skein512_context ctx_skein;
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;

	unsigned char hash[64];

	sph_bmw512_init(&ctx_bmw);
	// ZBMW;
	sph_bmw512(&ctx_bmw, (const void*)input, 80);
	sph_bmw512_close(&ctx_bmw, (void*)hash);

	sph_blake512_init(&ctx_blake);
	// ZBLAKE;
	sph_blake512(&ctx_blake, hash, 64);
	sph_blake512_close(&ctx_blake, (void*)hash);

	if (hash[0] & 0x8)
	{
		sph_groestl512_init(&ctx_groestl);
		// ZGROESTL;
		sph_groestl512(&ctx_groestl, (const void*)hash, 64);
		sph_groestl512_close(&ctx_groestl, (void*)hash);
	}
	else
	{
		sph_skein512_init(&ctx_skein);
		// ZSKEIN;
		sph_skein512(&ctx_skein, (const void*)hash, 64);
		sph_skein512_close(&ctx_skein, (void*)hash);
	}

	sph_groestl512_init(&ctx_groestl);
	// ZGROESTL;
	sph_groestl512(&ctx_groestl, (const void*)hash, 64);
	sph_groestl512_close(&ctx_groestl, (void*)hash);

	sph_jh512_init(&ctx_jh);
	// ZJH;
	sph_jh512(&ctx_jh, (const void*)hash, 64);
	sph_jh512_close(&ctx_jh, (void*)hash);

	if (hash[0] & 0x8)
	{
		sph_blake512_init(&ctx_blake);
		// ZBLAKE;
		sph_blake512(&ctx_blake, (const void*)hash, 64);
		sph_blake512_close(&ctx_blake, (void*)hash);
	}
	else
	{
		sph_bmw512_init(&ctx_bmw);
		// ZBMW;
		sph_bmw512(&ctx_bmw, (const void*)hash, 64);
		sph_bmw512_close(&ctx_bmw, (void*)hash);
	}

	sph_keccak512_init(&ctx_keccak);
	// ZKECCAK;
	sph_keccak512(&ctx_keccak, (const void*)hash, 64);
	sph_keccak512_close(&ctx_keccak, (void*)hash);

	sph_skein512_init(&ctx_skein);
	// SKEIN;
	sph_skein512(&ctx_skein, (const void*)hash, 64);
	sph_skein512_close(&ctx_skein, (void*)hash);

	if (hash[0] & 0x8)
	{
		sph_keccak512_init(&ctx_keccak);
		// ZKECCAK;
		sph_keccak512(&ctx_keccak, (const void*)hash, 64);
		sph_keccak512_close(&ctx_keccak, (void*)hash);
	}
	else
	{
		sph_jh512_init(&ctx_jh);
		// ZJH;
		sph_jh512(&ctx_jh, (const void*)hash, 64);
		sph_jh512_close(&ctx_jh, (void*)hash);
	}

	memcpy(state, hash, 32);
}


int scanhash_anime(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i = 0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	};

	do {
		be32enc(&endiandata[19], n);
		animehash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return 1;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
