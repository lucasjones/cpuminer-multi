// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
#include "miner.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"
#include "cryptonight.h"

#ifdef __unix__
#include <sys/mman.h>
#endif

void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

void do_jh_hash(const void* input, size_t len, char* output) {
    jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
}

void do_skein_hash(const void* input, size_t len, char* output) {
    skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
}

void xor_blocks_dst(const uint8_t *restrict a, const uint8_t *restrict b, uint8_t *restrict dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

void (* const extra_hashes[4])(const void *, size_t, char *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};

void cryptonight_hash(void* output, const void* input, size_t len) {
    struct cryptonight_ctx *ctx = (struct cryptonight_ctx*)malloc(sizeof(struct cryptonight_ctx));
    cryptonight_hash_ctx(output, input, ctx);
    free(ctx);
}

__thread struct cryptonight_ctx *persistentctx = NULL;

int scanhash_cryptonight(int thr_id, uint32_t *restrict pdata, const uint32_t *restrict ptarget, uint32_t max_nonce, unsigned long *restrict hashes_done) {
    uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
    uint32_t n = *nonceptr - 1;
    const uint32_t first_nonce = n + 1;
    const uint32_t Htarg = ptarget[7];
    uint32_t hash[HASH_SIZE / 4] __attribute__((aligned(32)));
	
	if(!persistentctx)
	{
		#ifdef __unix__
		persistentctx = (struct cryptonight_ctx *)mmap(0, sizeof(struct cryptonight_ctx), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, 0, 0);
		if(persistentctx == MAP_FAILED) persistentctx = (struct cryptonight_ctx *)malloc(sizeof(struct cryptonight_ctx));
		#else
		persistentctx = (struct cryptonight_ctx *)malloc(sizeof(struct cryptonight_ctx));
		#endif
	}
	
	do {
		*nonceptr = ++n;
		cryptonight_hash_ctx(hash, pdata, persistentctx);
		if (unlikely(hash[7] < ptarget[7])) {
			*hashes_done = n - first_nonce + 1;
			return true;
		}
	} while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
    
    *hashes_done = n - first_nonce + 1;
    return 0;
}
