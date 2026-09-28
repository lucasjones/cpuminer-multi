// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

/*
 * CryptoNight (the original version, "variant 0"): fill a 2 MiB scratchpad
 * from the Keccak state with 10-round AES, do 2^19 rounds of AES and
 * 64x64-bit multiplications at data-dependent places in it, fold it back
 * with AES and finish with one of four hashes.
 *
 * Two implementations: portable C (table AES, crypto/aesb.c), and AES-NI
 * intrinsics for x86 CPUs that have it, picked at run time. Each thread
 * keeps its context and scratchpad for its whole life: allocating 2 MiB per
 * call cost page faults, and the scratchpad is 2 MiB aligned so that Linux
 * can back it with one transparent huge page (fewer TLB misses).
 */

#include "cpuminer-config.h"
#include "miner.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <malloc.h>
#else
#include <sys/mman.h>
#endif

#if (defined(__x86_64__) || defined(__i386__)) && \
	(defined(__GNUC__) || defined(__clang__))
#define HAVE_AESNI 1
#include <cpuid.h>
#include <emmintrin.h>
#include <wmmintrin.h>
#endif

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_ROUNDS      10
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

struct cryptonight_ctx {
	union cn_slow_hash_state state;
	uint8_t text[INIT_SIZE_BYTE] __attribute__((aligned(16)));
	uint8_t a[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t b[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t key[AES_ROUNDS * AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t *long_state;	/* MEMORY bytes, MEMORY aligned */
};

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

/* Portable AES rounds (crypto/aesb.c) */
void aesb_single_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);
void aesb_pseudo_round_mut(uint8_t *val, const uint8_t *expandedKey);

static const uint8_t aes_sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/* The first 10 round keys of the AES-256 key schedule (FIPS-197): all
 * CryptoNight uses. This replaces the whole OpenAES library, which also
 * seeded rand() and allocated memory on every hash. */
static void cn_expand_key(const uint8_t *key, uint8_t *exp)
{
	static const uint8_t rcon[4] = { 0x01, 0x02, 0x04, 0x08 };
	uint8_t t[4];
	int i, k;

	memcpy(exp, key, 32);
	for (i = 8; i < 4 * AES_ROUNDS; i++) {
		memcpy(t, exp + 4 * (i - 1), 4);
		if (i % 8 == 0) {
			uint8_t u = t[0];

			t[0] = aes_sbox[t[1]] ^ rcon[i / 8 - 1];
			t[1] = aes_sbox[t[2]];
			t[2] = aes_sbox[t[3]];
			t[3] = aes_sbox[u];
		} else if (i % 8 == 4) {
			for (k = 0; k < 4; k++)
				t[k] = aes_sbox[t[k]];
		}
		for (k = 0; k < 4; k++)
			exp[4 * i + k] = exp[4 * (i - 8) + k] ^ t[k];
	}
}

// Credit to Wolf for optimizing this function
static inline size_t e2i(const uint8_t* a) {
	return ((uint32_t *)a)[0] & 0x1FFFF0;
}

static inline void mul_sum_xor_dst(const uint8_t* a, uint8_t* c, uint8_t* dst) {
	uint64_t hi, lo = mul128(((uint64_t*) a)[0], ((uint64_t*) dst)[0], &hi) + ((uint64_t*) c)[1];
	hi += ((uint64_t*) c)[0];

	((uint64_t*) c)[0] = ((uint64_t*) dst)[0] ^ hi;
	((uint64_t*) c)[1] = ((uint64_t*) dst)[1] ^ lo;
	((uint64_t*) dst)[0] = hi;
	((uint64_t*) dst)[1] = lo;
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
	((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
	((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
	((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
	((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

static void cn_hash_portable(void *output, const void *input, size_t len,
		struct cryptonight_ctx *ctx)
{
	uint8_t *ls = ctx->long_state;
	size_t i, j;

	hash_process(&ctx->state.hs, (const uint8_t *) input, len);
	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	cn_expand_key(ctx->state.hs.b, ctx->key);
	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * j], ctx->key);
		memcpy(&ls[i], ctx->text, INIT_SIZE_BYTE);
	}

	xor_blocks_dst(&ctx->state.k[0], &ctx->state.k[32], ctx->a);
	xor_blocks_dst(&ctx->state.k[16], &ctx->state.k[48], ctx->b);

	for (i = 0; likely(i < ITER / 4); ++i) {
		/* Dependency chain: address -> read value ------+
		 * written value <-+ hard function (AES or MUL) <+
		 * next address  <-+
		 */
		/* Iteration 1 */
		j = e2i(ctx->a);
		aesb_single_round(&ls[j], ctx->c, ctx->a);
		xor_blocks_dst(ctx->c, ctx->b, &ls[j]);
		/* Iteration 2 */
		mul_sum_xor_dst(ctx->c, ctx->a, &ls[e2i(ctx->c)]);
		/* Iteration 3 */
		j = e2i(ctx->a);
		aesb_single_round(&ls[j], ctx->b, ctx->a);
		xor_blocks_dst(ctx->b, ctx->c, &ls[j]);
		/* Iteration 4 */
		mul_sum_xor_dst(ctx->b, ctx->a, &ls[e2i(ctx->b)]);
	}

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	cn_expand_key(&ctx->state.hs.b[32], ctx->key);
	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&ctx->text[j * AES_BLOCK_SIZE], &ls[i + j * AES_BLOCK_SIZE]);
			aesb_pseudo_round_mut(&ctx->text[j * AES_BLOCK_SIZE], ctx->key);
		}
	}
	memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	hash_permutation(&ctx->state.hs);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}

#ifdef HAVE_AESNI
#define AESNI_TARGET __attribute__((target("aes,sse2")))

#ifdef __x86_64__
#define LO64(x) ((uint64_t) _mm_cvtsi128_si64(x))
#else
#define LO64(x) ((uint64_t) (uint32_t) _mm_cvtsi128_si32(x) | \
		 (uint64_t) (uint32_t) _mm_cvtsi128_si32(_mm_srli_si128((x), 4)) << 32)
#endif

/* The same with AES-NI; the 8 blocks of the scratchpad passes go through
 * the AES rounds together, so that their latencies overlap. */
AESNI_TARGET
static void cn_hash_aesni(void *output, const void *input, size_t len,
		struct cryptonight_ctx *ctx)
{
	uint8_t *ls = ctx->long_state;
	__m128i k[AES_ROUNDS], x[INIT_SIZE_BLK], bx;
	uint64_t a0, a1, idx, s[8];
	size_t i;
	int r, n;

	hash_process(&ctx->state.hs, (const uint8_t *) input, len);

	cn_expand_key(ctx->state.hs.b, ctx->key);
	for (r = 0; r < AES_ROUNDS; r++)
		k[r] = _mm_load_si128((const __m128i *) (ctx->key + AES_BLOCK_SIZE * r));
	for (n = 0; n < INIT_SIZE_BLK; n++)
		x[n] = _mm_loadu_si128((const __m128i *) (ctx->state.init + AES_BLOCK_SIZE * n));
	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE) {
		for (r = 0; r < AES_ROUNDS; r++)
			for (n = 0; n < INIT_SIZE_BLK; n++)
				x[n] = _mm_aesenc_si128(x[n], k[r]);
		for (n = 0; n < INIT_SIZE_BLK; n++)
			_mm_store_si128((__m128i *) (ls + i + AES_BLOCK_SIZE * n), x[n]);
	}

	memcpy(s, ctx->state.k, sizeof(s));
	a0 = s[0] ^ s[4];
	a1 = s[1] ^ s[5];
	bx = _mm_set_epi64x((int64_t) (s[3] ^ s[7]), (int64_t) (s[2] ^ s[6]));
	idx = a0;
	for (i = 0; likely(i < ITER / 2); i++) {
		__m128i cx;
		uint64_t hi, lo, cl, ch, *p;

		/* AES round keyed by a, at a place chosen by a */
		p = (uint64_t *) (ls + (idx & 0x1FFFF0));
		cx = _mm_aesenc_si128(_mm_load_si128((const __m128i *) p),
				_mm_set_epi64x((int64_t) a1, (int64_t) a0));
		_mm_store_si128((__m128i *) p, _mm_xor_si128(bx, cx));
		bx = cx;
		idx = LO64(cx);

		/* multiply-add at a place chosen by the AES result */
		p = (uint64_t *) (ls + (idx & 0x1FFFF0));
		cl = p[0];
		ch = p[1];
		lo = mul128(idx, cl, &hi);
		a0 += hi;
		a1 += lo;
		p[0] = a0;
		p[1] = a1;
		a0 ^= cl;
		a1 ^= ch;
		idx = a0;
	}

	cn_expand_key(&ctx->state.hs.b[32], ctx->key);
	for (r = 0; r < AES_ROUNDS; r++)
		k[r] = _mm_load_si128((const __m128i *) (ctx->key + AES_BLOCK_SIZE * r));
	for (n = 0; n < INIT_SIZE_BLK; n++)
		x[n] = _mm_loadu_si128((const __m128i *) (ctx->state.init + AES_BLOCK_SIZE * n));
	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE) {
		for (n = 0; n < INIT_SIZE_BLK; n++)
			x[n] = _mm_xor_si128(x[n],
				_mm_load_si128((const __m128i *) (ls + i + AES_BLOCK_SIZE * n)));
		for (r = 0; r < AES_ROUNDS; r++)
			for (n = 0; n < INIT_SIZE_BLK; n++)
				x[n] = _mm_aesenc_si128(x[n], k[r]);
	}
	for (n = 0; n < INIT_SIZE_BLK; n++)
		_mm_storeu_si128((__m128i *) (ctx->state.init + AES_BLOCK_SIZE * n), x[n]);
	hash_permutation(&ctx->state.hs);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}
#endif /* HAVE_AESNI */

/* True if the CPU has AES-NI and this build can use it. */
bool cryptonight_cpu_has_aesni(void)
{
#ifdef HAVE_AESNI
	unsigned int eax, ebx, ecx, edx;

	if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
		return false;
	return (ecx & bit_AES) && (edx & bit_SSE2);
#else
	return false;
#endif
}

static void *alloc_aligned(size_t size, size_t align)
{
	void *p;

#ifdef _WIN32
	p = _aligned_malloc(size, align);
#else
	if (posix_memalign(&p, align, size))
		p = NULL;
#endif
	return p;
}

/* This thread's context, created on first use and kept for the thread's
 * life. */
static struct cryptonight_ctx *cn_thread_ctx(void)
{
	static __thread struct cryptonight_ctx *ctx;

	if (unlikely(!ctx)) {
		struct cryptonight_ctx *c = alloc_aligned(sizeof(*c), 64);
		uint8_t *ls = alloc_aligned(MEMORY, MEMORY);

		if (!c || !ls) {
#ifdef _WIN32
			_aligned_free(c);
			_aligned_free(ls);
#else
			free(c);
			free(ls);
#endif
			applog(LOG_ERR, "CryptoNight: cannot allocate its 2 MiB of memory");
			return NULL;
		}
#if defined(__linux__) && defined(MADV_HUGEPAGE)
		/* ask for a transparent huge page before the memory is touched */
		madvise(ls, MEMORY, MADV_HUGEPAGE);
#endif
		memset(c, 0, sizeof(*c));
		c->long_state = ls;
		ctx = c;
	}
	return ctx;
}

static inline void cn_hash_ctx(void *output, const void *input, size_t len,
		struct cryptonight_ctx *ctx)
{
#ifdef HAVE_AESNI
	if (aes_ni_supported)
		cn_hash_aesni(output, input, len, ctx);
	else
#endif
		cn_hash_portable(output, input, len, ctx);
}

void cryptonight_hash(void* output, const void* input, size_t len) {
	struct cryptonight_ctx *ctx = cn_thread_ctx();

	if (likely(ctx))
		cn_hash_ctx(output, input, len, ctx);
	else
		memset(output, 0xff, HASH_SIZE);	/* never a share */
}

/* Scan nonces for a CryptoNight job. pdata holds a data_size-byte blob with
 * the nonce at bytes 39..42; target[7]:target[6] is the 64-bit share target
 * compared with the top 64 bits of the hash. */
int scanhash_cryptonight(int thr_id, uint32_t *pdata, size_t data_size,
		const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done,
		unsigned char *hash_out) {
	unsigned char *blob = (unsigned char *) pdata;
	uint32_t n = le32dec(blob + 39) - 1;
	const uint32_t first_nonce = n + 1;
	const uint64_t target = ((uint64_t) ptarget[7] << 32) | ptarget[6];
	uint32_t hash[HASH_SIZE / 4] __attribute__((aligned(32)));
	struct cryptonight_ctx *ctx = cn_thread_ctx();

	if (data_size < RPC2_MIN_BLOB || data_size > RPC2_MAX_BLOB || !ctx) {
		*hashes_done = 0;
		return 0;
	}

	do {
		le32enc(blob + 39, ++n);
		cn_hash_ctx(hash, blob, data_size, ctx);
		if (unlikely((((uint64_t) hash[7] << 32) | hash[6]) < target)) {
			memcpy(hash_out, hash, HASH_SIZE);
			*hashes_done = n - first_nonce + 1;
			return 1;
		}
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));

	*hashes_done = n - first_nonce + 1;
	return 0;
}
