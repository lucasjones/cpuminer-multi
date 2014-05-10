// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
#include "miner.h"
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"
#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_skein.h"

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

static void blake_hash(const void* input, size_t len, char* output) {
    sph_blake256_context ctx;

    sph_blake256_init(&ctx);
    sph_blake256(&ctx, input, len);
    sph_blake256_close(&ctx, output);
}

void groestl_hash(const void* input, size_t len, char* output) {
    char hash1[64];
    char hash2[64];

    sph_groestl512_context ctx_groestl;
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, input, len);
    sph_groestl512_close(&ctx_groestl, &hash1);

    sph_groestl512(&ctx_groestl, hash1, 64);
    sph_groestl512_close(&ctx_groestl, &hash2);

    memcpy(output, &hash2, 32);
}

static void jh_hash(const void* input, size_t len, char* output) {
    sph_jh256_context ctx;

    sph_jh256_init(&ctx);
    sph_jh256(&ctx, input, len);
    sph_jh256_close(&ctx, output);
}

static void skein_hash(const void* input, size_t len, char* output) {
    sph_skein256_context ctx;

    sph_skein256_init(&ctx);
    sph_skein256(&ctx, input, len);
    sph_skein256_close(&ctx, output);
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
    blake_hash, groestl_hash, jh_hash, skein_hash
};

static size_t e2i(const uint8_t* a, size_t count) {
    return (*((uint64_t*) a) / AES_BLOCK_SIZE) & (count - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
    uint64_t a0, b0;
    uint64_t hi, lo;

    a0 = SWAP64LE(((uint64_t*) a)[0]);
    b0 = SWAP64LE(((uint64_t*) b)[0]);
    lo = mul128(a0, b0, &hi);
    ((uint64_t*) res)[0] = SWAP64LE(hi);
    ((uint64_t*) res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    uint64_t a0, a1, b0, b1;

    a0 = SWAP64LE(((uint64_t*) a)[0]);
    a1 = SWAP64LE(((uint64_t*) a)[1]);
    b0 = SWAP64LE(((uint64_t*) b)[0]);
    b1 = SWAP64LE(((uint64_t*) b)[1]);
    a0 += b0;
    a1 += b1;
    ((uint64_t*) a)[0] = SWAP64LE(a0);
    ((uint64_t*) a)[1] = SWAP64LE(a1);
}

static void copy_block(uint8_t* dst, const uint8_t* src) {
    memcpy(dst, src, AES_BLOCK_SIZE);
}

static void swap_blocks(uint8_t* a, uint8_t* b) {
    size_t i;
    uint8_t t;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
}

static void xor_blocks(uint8_t* a, const uint8_t* b) {
    size_t i;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        a[i] ^= b[i];
    }
}

static void cryptonight_hash(void* output, const void* input) {
    uint8_t long_state[MEMORY];
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE];
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t c[AES_BLOCK_SIZE];
    uint8_t d[AES_BLOCK_SIZE];
    size_t i, j;
    uint8_t aes_key[AES_KEY_SIZE];
    OAES_CTX* aes_ctx;

    hash_process(&state.hs, input, 80);
    memcpy(text, state.init, INIT_SIZE_BYTE);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
    aes_ctx = oaes_alloc();

    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            oaes_pseudo_encrypt_ecb(aes_ctx, &text[AES_BLOCK_SIZE * j]);
        }
        memcpy(&long_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
    }

    for (i = 0; i < 16; i++) {
        a[i] = state.k[i] ^ state.k[32 + i];
        b[i] = state.k[16 + i] ^ state.k[48 + i];
    }

    for (i = 0; i < ITER / 2; i++) {
        /* Dependency chain: address -> read value ------+
         * written value <-+ hard function (AES or MUL) <+
         * next address  <-+
         */
        /* Iteration 1 */
        j = e2i(a, MEMORY / AES_BLOCK_SIZE);
        copy_block(c, &long_state[j * AES_BLOCK_SIZE]);
        oaes_encryption_round(a, c);
        xor_blocks(b, c);
        swap_blocks(b, c);
        copy_block(&long_state[j * AES_BLOCK_SIZE], c);
        assert(j == e2i(a, MEMORY / AES_BLOCK_SIZE));
        swap_blocks(a, b);
        /* Iteration 2 */
        j = e2i(a, MEMORY / AES_BLOCK_SIZE);
        copy_block(c, &long_state[j * AES_BLOCK_SIZE]);
        mul(a, c, d);
        sum_half_blocks(b, d);
        swap_blocks(b, c);
        xor_blocks(b, c);
        copy_block(&long_state[j * AES_BLOCK_SIZE], c);
        swap_blocks(a, b);
    }

    memcpy(text, state.init, INIT_SIZE_BYTE);
    oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            xor_blocks(&text[j * AES_BLOCK_SIZE],
                    &long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
            oaes_pseudo_encrypt_ecb(aes_ctx, &text[j * AES_BLOCK_SIZE]);
        }
    }
    memcpy(state.init, text, INIT_SIZE_BYTE);
    hash_permutation(&state.hs);
    /*memcpy(hash, &state, 32);*/
    extra_hashes[state.hs.b[0] & 3](&state, 200, output);
    oaes_free(&aes_ctx);
}

int scanhash_cryptonight(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done) {
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];
    uint32_t hash64[8] __attribute__((aligned(32)));
    uint32_t endiandata[32];

//char testdata[] = {"\x70\x00\x00\x00\x5d\x38\x5b\xa1\x14\xd0\x79\x97\x0b\x29\xa9\x41\x8f\xd0\x54\x9e\x7d\x68\xa9\x5c\x7f\x16\x86\x21\xa3\x14\x20\x10\x00\x00\x00\x00\x57\x85\x86\xd1\x49\xfd\x07\xb2\x2f\x3a\x8a\x34\x7c\x51\x6d\xe7\x05\x2f\x03\x4d\x2b\x76\xff\x68\xe0\xd6\xec\xff\x9b\x77\xa4\x54\x89\xe3\xfd\x51\x17\x32\x01\x1d\xf0\x73\x10\x00"};

//we need bigendian data...
//lessons learned: do NOT endianchange directly in pdata, this will all proof-of-works be considered as stale from minerd....
    int kk = 0;
    for (; kk < 32; kk++) {
        be32enc(&endiandata[kk], ((uint32_t*) pdata)[kk]);
    };

    /* I'm to lazy to put the loop in an inline function... so dirty copy'n'paste.... */
    /* i know that i could set a variable, but i don't know how the compiler will optimize it, not that then the cpu needs to load the value *everytime* in a register */
    if (ptarget[7] == 0) {
        do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            cryptonight_hash(hash64, &endiandata);
            if (((hash64[7] & 0xFFFFFFFF) == 0) && fulltest(hash64, ptarget)) {
                *hashes_done = n - first_nonce + 1;
                return true;
            }
        } while (n < max_nonce && !work_restart[thr_id].restart);
    } else if (ptarget[7] <= 0xF) {
        do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            cryptonight_hash(hash64, &endiandata);
            if (((hash64[7] & 0xFFFFFFF0) == 0) && fulltest(hash64, ptarget)) {
                *hashes_done = n - first_nonce + 1;
                return true;
            }
        } while (n < max_nonce && !work_restart[thr_id].restart);
    } else if (ptarget[7] <= 0xFF) {
        do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            cryptonight_hash(hash64, &endiandata);
            if (((hash64[7] & 0xFFFFFF00) == 0) && fulltest(hash64, ptarget)) {
                *hashes_done = n - first_nonce + 1;
                return true;
            }
        } while (n < max_nonce && !work_restart[thr_id].restart);
    } else if (ptarget[7] <= 0xFFF) {
        do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            cryptonight_hash(hash64, &endiandata);
            if (((hash64[7] & 0xFFFFF000) == 0) && fulltest(hash64, ptarget)) {
                *hashes_done = n - first_nonce + 1;
                return true;
            }
        } while (n < max_nonce && !work_restart[thr_id].restart);

    } else if (ptarget[7] <= 0xFFFF) {
        do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            cryptonight_hash(hash64, &endiandata);
            if (((hash64[7] & 0xFFFF0000) == 0) && fulltest(hash64, ptarget)) {
                *hashes_done = n - first_nonce + 1;
                return true;
            }
        } while (n < max_nonce && !work_restart[thr_id].restart);

    } else {
        do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            cryptonight_hash(hash64, &endiandata);
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
