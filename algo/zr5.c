#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"

#define ZR_BLAKE   0
#define ZR_GROESTL 1
#define ZR_JH      2
#define ZR_SKEIN   3

#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

static const int permut[][4] = {
	{0, 1, 2, 3},
	{0, 1, 3, 2},
	{0, 2, 1, 3},
	{0, 2, 3, 1},
	{0, 3, 1, 2},
	{0, 3, 2, 1},
	{1, 0, 2, 3},
	{1, 0, 3, 2},
	{1, 2, 0, 3},
	{1, 2, 3, 0},
	{1, 3, 0, 2},
	{1, 3, 2, 0},
	{2, 0, 1, 3},
	{2, 0, 3, 1},
	{2, 1, 0, 3},
	{2, 1, 3, 0},
	{2, 3, 0, 1},
	{2, 3, 1, 0},
	{3, 0, 1, 2},
	{3, 0, 2, 1},
	{3, 1, 0, 2},
	{3, 1, 2, 0},
	{3, 2, 0, 1},
	{3, 2, 1, 0}
};

void zr5hash(void *output, const void *input)
{
	sph_keccak512_context ctx_keccak;
	sph_blake512_context ctx_blake;
	sph_groestl512_context ctx_groestl;
	sph_jh512_context ctx_jh;
	sph_skein512_context ctx_skein;

	uint32_t _ALIGN(64) hash[5][16];

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, (const void*) input, 80);
	sph_keccak512_close(&ctx_keccak, (void*) &hash[0][0]);

	unsigned int norder = hash[0][0] % ARRAY_SIZE(permut); /* % 24 */

	for(int i = 0; i < 4; i++)
	{
		void* phash = (void*) &(hash[i][0]);
		void* pdest = (void*) &(hash[i+1][0]);

		switch (permut[norder][i]) {
		case ZR_BLAKE:
			sph_blake512_init(&ctx_blake);
			sph_blake512(&ctx_blake, (const void*) phash, 64);
			sph_blake512_close(&ctx_blake, pdest);
			break;
		case ZR_GROESTL:
			sph_groestl512_init(&ctx_groestl);
			sph_groestl512(&ctx_groestl, (const void*) phash, 64);
			sph_groestl512_close(&ctx_groestl, pdest);
			break;
		case ZR_JH:
			sph_jh512_init(&ctx_jh);
			sph_jh512(&ctx_jh, (const void*) phash, 64);
			sph_jh512_close(&ctx_jh, pdest);
			break;
		case ZR_SKEIN:
			sph_skein512_init(&ctx_skein);
			sph_skein512(&ctx_skein, (const void*) phash, 64);
			sph_skein512_close(&ctx_skein, pdest);
			break;
		default:
			break;
		}
	}
	memcpy(output, &hash[4], 32);
}

int scanhash_zr5(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[16];
	uint32_t _ALIGN(64) tmpdata[20];
	const uint32_t version = pdata[0] & (~POK_DATA_MASK);
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

	memcpy(tmpdata, pdata, 80);

	do {
		#define Htarg ptarget[7]

		tmpdata[0]  = version;
		tmpdata[19] = nonce;
		zr5hash(hash, tmpdata);
		// fill PoK
		tmpdata[0] = version | (hash[0] & POK_DATA_MASK);
		zr5hash(hash, tmpdata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget))
		{
			pdata[0] = tmpdata[0];
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce + 1;
			if (opt_debug)
				applog(LOG_INFO, "found nonce %x", nonce);
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
