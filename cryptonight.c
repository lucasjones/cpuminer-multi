// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
#include "miner.h"
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

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

static void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
    int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
    assert(likely(SUCCESS == r));
}

static void do_skein_hash(const void* input, size_t len, char* output) {
    int r = skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
    assert(likely(SKEIN_SUCCESS == r));
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
        do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

static size_t e2i(const uint8_t* a, size_t count) {
    return (*((uint64_t*) a) / AES_BLOCK_SIZE) & (count - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
    ((uint64_t*) res)[1] = mul128(((uint64_t*) a)[0], ((uint64_t*) b)[0], (uint64_t*) res);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    ((uint64_t*) a)[0] += ((uint64_t*) b)[0];
    ((uint64_t*) a)[1] += ((uint64_t*) b)[1];
}

static void sum_half_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] + ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] + ((uint64_t*) b)[1];
}

static mul_sum_dst(const uint8_t* a, const uint8_t* b, const uint8_t* c, uint8_t* dst) {
    ((uint64_t*) dst)[1] = mul128(((uint64_t*) a)[0], ((uint64_t*) b)[0], (uint64_t*) dst) + ((uint64_t*) c)[1];
    ((uint64_t*) dst)[0] += ((uint64_t*) c)[0];
}

static mul_sum_xor_dst(const uint8_t* a, const uint8_t* c, uint8_t* xordst, uint8_t* dst) {
    uint64_t hi, lo = mul128(((uint64_t*) a)[0], ((uint64_t*) dst)[0], &hi) + ((uint64_t*) c)[1];
    hi += ((uint64_t*) c)[0];

    ((uint64_t*) xordst)[0] = ((uint64_t*) dst)[0] ^ hi;
    ((uint64_t*) xordst)[1] = ((uint64_t*) dst)[1] ^ lo;
    ((uint64_t*) dst)[0] = hi;
    ((uint64_t*) dst)[1] = lo;
}

static inline void copy_block(uint8_t* dst, const uint8_t* src) {
    ((uint64_t*) dst)[0] = ((uint64_t*) src)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) src)[1];
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

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
    ((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
    ((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

struct cryptonight_ctx {
    uint8_t long_state[MEMORY];
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE];
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t c[AES_BLOCK_SIZE];
    uint8_t d[AES_BLOCK_SIZE];
    uint8_t aes_key[AES_KEY_SIZE];
    OAES_CTX* aes_ctx;
};

void cryptonight_hash_ctx(void* output, const void* input, size_t len, struct cryptonight_ctx* ctx) {
    hash_process(&ctx->state.hs, (const uint8_t*) input, len);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    memcpy(ctx->aes_key, ctx->state.hs.b, AES_KEY_SIZE);
    ctx->aes_ctx = oaes_alloc();
    size_t i, j;

    oaes_key_import_data(ctx->aes_ctx, ctx->aes_key, AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            oaes_pseudo_encrypt_ecb(ctx->aes_ctx, &ctx->text[AES_BLOCK_SIZE * j]);
        }
        memcpy(&ctx->long_state[i * INIT_SIZE_BYTE], ctx->text, INIT_SIZE_BYTE);
    }

    for (i = 0; i < 16; i++) {
        ctx->a[i] = ctx->state.k[i] ^ ctx->state.k[32 + i];
        ctx->b[i] = ctx->state.k[16 + i] ^ ctx->state.k[48 + i];
    }

    for (i = 0; i < ITER / 2; i++) {
        /* Dependency chain: address -> read value ------+
         * written value <-+ hard function (AES or MUL) <+
         * next address  <-+
         */
        /* Iteration 1 */
        j = e2i(ctx->a, MEMORY / AES_BLOCK_SIZE);
        copy_block(ctx->c, &ctx->long_state[j * AES_BLOCK_SIZE]);
        oaes_encryption_round(ctx->a, ctx->c);
        xor_blocks_dst(ctx->b, ctx->c, &ctx->long_state[j * AES_BLOCK_SIZE]);
        /* Iteration 2 */
        mul_sum_xor_dst(ctx->c, ctx->a, ctx->b, &ctx->long_state[e2i(ctx->c, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE]);
        copy_block(ctx->a, ctx->b);
        copy_block(ctx->b, ctx->c);
    }

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    oaes_key_import_data(ctx->aes_ctx, &ctx->state.hs.b[32], AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            xor_blocks(&ctx->text[j * AES_BLOCK_SIZE],
                    &ctx->long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
            oaes_pseudo_encrypt_ecb(ctx->aes_ctx, &ctx->text[j * AES_BLOCK_SIZE]);
        }
    }
    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
    hash_permutation(&ctx->state.hs);
    /*memcpy(hash, &state, 32);*/
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
    oaes_free(&ctx->aes_ctx);
}

void cryptonight_hash(void* output, const void* input, size_t len) {
    cryptonight_hash_ctx(output, input, len, alloca(sizeof(struct cryptonight_ctx)));
}

int scanhash_cryptonight(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done) {
    uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
    uint32_t n = *nonceptr - 1;
    const uint32_t first_nonce = n + 1;
    const uint32_t Htarg = ptarget[7];
    uint32_t hash[HASH_SIZE / 4] __attribute__((aligned(32)));

    struct cryptonight_ctx *ctx = alloca(sizeof(struct cryptonight_ctx));

    do {
        *nonceptr = ++n;
        cryptonight_hash_ctx(hash, pdata, 76, ctx);
        if (unlikely(hash[7] < ptarget[7])) {
            *hashes_done = n - first_nonce + 1;
            return true;
        }
    } while (likely((n <= max_nonce) && !work_restart[thr_id].restart));
    *hashes_done = n - first_nonce + 1;
    return 0;
}
