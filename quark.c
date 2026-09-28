#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"


/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context 	blake1, blake2;
	sph_bmw512_context		bmw1, bmw2;
	sph_groestl512_context	groestl1, groestl2;
	sph_skein512_context	skein1, skein2;
	sph_jh512_context		jh1, jh2;
	sph_keccak512_context	keccak1, keccak2;
} quarkhash_context_holder;

static quarkhash_context_holder base_contexts;

void init_quarkhash_contexts()
{
    sph_blake512_init(&base_contexts.blake1);
    sph_bmw512_init(&base_contexts.bmw1);
    sph_groestl512_init(&base_contexts.groestl1);
    sph_skein512_init(&base_contexts.skein1);
    sph_groestl512_init(&base_contexts.groestl2);
    sph_jh512_init(&base_contexts.jh1);	
    sph_blake512_init(&base_contexts.blake2);	
    sph_bmw512_init(&base_contexts.bmw2);	
    sph_keccak512_init(&base_contexts.keccak1);	
    sph_skein512_init(&base_contexts.skein2);
    sph_keccak512_init(&base_contexts.keccak2);
    sph_jh512_init(&base_contexts.jh2);	
}

void quarkhash(void *state, const void *input)
{

	quarkhash_context_holder ctx;

    uint32_t mask = 8;
    uint32_t zero = 0;

	//these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	
	

	//do one memcopy to get fresh contexts, its faster even with a larger block then issuing 9 memcopies
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	
    sph_blake512 (&ctx.blake1, input, 80);
    sph_blake512_close (&ctx.blake1, hashA);	 //0
	
    sph_bmw512 (&ctx.bmw1, hashA, 64);    //0
    sph_bmw512_close(&ctx.bmw1, hashB);   //1
	
    if ((hashB[0] & mask) != zero)   //1
    {
        sph_groestl512 (&ctx.groestl1, hashB, 64); //1
        sph_groestl512_close(&ctx.groestl1, hashA); //2
    }
    else
    {
        sph_skein512 (&ctx.skein1, hashB, 64); //1
        sph_skein512_close(&ctx.skein1, hashA); //2
    }
	
    sph_groestl512 (&ctx.groestl2, hashA, 64); //2
    sph_groestl512_close(&ctx.groestl2, hashB); //3

    sph_jh512 (&ctx.jh1, hashB, 64); //3
    sph_jh512_close(&ctx.jh1, hashA); //4

    if ((hashA[0] & mask) != zero) //4
    {
        sph_blake512 (&ctx.blake2, hashA, 64); //
        sph_blake512_close(&ctx.blake2, hashB); //5
    }
    else
    {
        sph_bmw512 (&ctx.bmw2, hashA, 64); //4
        sph_bmw512_close(&ctx.bmw2, hashB);   //5
    }
    
    sph_keccak512 (&ctx.keccak1, hashB, 64); //5
    sph_keccak512_close(&ctx.keccak1, hashA); //6

    sph_skein512 (&ctx.skein2, hashA, 64); //6
    sph_skein512_close(&ctx.skein2, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_keccak512 (&ctx.keccak2, hashB, 64); //
        sph_keccak512_close(&ctx.keccak2, hashA); //8
    }
    else
    {
        sph_jh512 (&ctx.jh2, hashB, 64); //7
        sph_jh512_close(&ctx.jh2, hashA); //8
    }

	memcpy(state, hashA, 32);
	
}

int scanhash_quark(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
		quarkhash(hash64, endiandata);
		if (hash64[7] <= Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
