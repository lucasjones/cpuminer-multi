#ifndef __MINER_H__
#define __MINER_H__

#include "cpuminer-config.h"

#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>
#include <pthread.h>
#include <jansson.h>
#include <curl/curl.h>

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#elif !defined alloca
# ifdef __GNUC__
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# elif !defined HAVE_ALLOCA
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
enum {
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
};
#endif

/* Let the compiler check applog() format strings against their arguments.
 * MinGW's format flavour depends on which printf implementation is in use. */
#if defined(__GNUC__) || defined(__clang__)
# if defined(__MINGW32__) && defined(__MINGW_PRINTF_FORMAT)
#  define PRINTF_FMT(fmt_idx, arg_idx) \
	__attribute__((format(__MINGW_PRINTF_FORMAT, fmt_idx, arg_idx)))
# else
#  define PRINTF_FMT(fmt_idx, arg_idx) \
	__attribute__((format(printf, fmt_idx, arg_idx)))
# endif
#else
# define PRINTF_FMT(fmt_idx, arg_idx)
#endif

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#endif

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
	return __builtin_bswap32(v);
#else
	return bswap_32(v);
#endif
}

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}
#endif

#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))

#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION

void sha256_init(uint32_t *state);
void sha256_transform(uint32_t *state, const uint32_t *block, int swap);
bool sha256_use_shani(bool on);
void sha256_hash(unsigned char *hash, const unsigned char *data, size_t len);
void sha256d(unsigned char *hash, const unsigned char *data, int len);

#ifdef USE_ASM
/* four SHA-256s at once: in the x86 assembly, and in the 32-bit ARM
 * assembly when it is built for NEON (sha2-arm.S). Not on 64-bit ARM, where
 * Apple's compilers define __ARM_NEON__ too but there is no such code. */
#if defined(__i386__) || defined(__x86_64__) || \
	(defined(__arm__) && defined(__APCS_32__) && defined(__ARM_NEON__))
#define HAVE_SHA256_4WAY 1
int sha256_use_4way(void);
void sha256_init_4way(uint32_t *state);
void sha256_transform_4way(uint32_t *state, const uint32_t *block, int swap);
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
#define HAVE_SHA256_8WAY 1
int sha256_use_8way(void);
void sha256_init_8way(uint32_t *state);
void sha256_transform_8way(uint32_t *state, const uint32_t *block, int swap);
#endif
#endif

extern int scanhash_sha256d(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern unsigned char *scrypt_buffer_alloc(int N);
extern void scrypt_hash(void *output, const void *input, int N);
extern int scanhash_scrypt(int thr_id, uint32_t *pdata,
                            unsigned char *scratchbuf, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done, int N);

extern int scanhash_keccak(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_quark(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern void init_quarkhash_contexts();

extern int scanhash_skein(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_ink(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern void init_blakehash_contexts();

extern int scanhash_blake(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_fresh(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_x11(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_x13(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_x14(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_x15(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_qubit(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern int scanhash_neoscrypt(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);
extern int neoscrypt_use_impl(int impl);

/* yescrypt and yespower variants */
enum { YESCRYPT, YESCRYPT_R8, YESCRYPT_R16, YESCRYPT_R32, YESPOWER, YESPOWER_R16 };
extern bool yespower_set_params(int variant, uint32_t N, uint32_t r, const char *key);
extern void yespower_describe(int variant, char *buf, size_t len);
extern void yespower_hash(void *output, const void *input, int variant);
extern int scanhash_yespower(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            int variant, uint32_t max_nonce, uint64_t *hashes_done);

/* instruction set extensions, for code that picks one at run time */
extern bool cpu_has_sse2(void);
extern bool cpu_has_avx2(void);
extern bool cpu_has_avx512vl(void);
extern uint64_t cpu_l3_cache_size(void);
extern uint64_t system_memory(void);

/* Argon2d variants */
enum { ARGON2D_4096, ARGON2D_500, ARGON2D_250, ARGON2D_16000 };
extern void argon2d_hash(void *output, const void *input, int variant);
extern int argon2d_use_impl(int impl);
extern const char *argon2d_impl_name(void);
extern int argon2d_raw(void *out, uint32_t outlen, const void *pwd, uint32_t pwdlen,
	const void *salt, uint32_t saltlen, const void *secret, uint32_t secretlen,
	const void *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost,
	uint32_t lanes, uint32_t version);
extern int scanhash_argon2d(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            int variant, uint32_t max_nonce, uint64_t *hashes_done);
extern const char *neoscrypt_impl_name(void);

/* Odocrypt (DigiByte): the key is the block time rounded down to a whole
 * number of "shape change" periods; testnet's period is 1 day */
#define ODO_INTERVAL_MAINNET (10 * 24 * 60 * 60)
extern uint32_t odo_key(uint32_t ntime, uint32_t interval);
extern void odo_hash(void *output, const void *input, uint32_t key);
extern void odo_encrypt_block(void *output, const void *input, uint32_t key);
extern int scanhash_odo(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t key, uint32_t max_nonce, uint64_t *hashes_done);

/* Verthash (Vertcoin): its 1.2 GB data file (verthash.dat): read (1, or
 * 0 if missing, -1 if wrong); built, and saved unless path is NULL (1, or
 * 0 without the memory, -1 if wrong); or either as the miner needs it */
extern int verthash_load(const char *path);
extern int verthash_create(const char *path, int threads);
extern bool verthash_setup(const char *path, int threads);
extern void verthash_free(void);
extern void verthash_generate(unsigned char *data, int threads);
extern void verthash_hash(void *output, const void *input);
extern int scanhash_verthash(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done);

extern void cryptonight_hash(void* output, const void* input, size_t input_len);
extern bool cryptonight_cpu_has_aesni(void);

/* Single-shot proof-of-work hashes of an 80-byte block header (header byte
 * order in, 32-byte hash out). The scan loops call these per nonce; tests
 * and share checks call them directly. quarkhash() and blakehash() need
 * init_quarkhash_contexts() / init_blakehash_contexts() to run first. */
extern void keccakhash(void *state, const void *input);
extern void quarkhash(void *state, const void *input);
extern void skeinhash(void *state, const void *input);
extern void inkhash(void *state, const void *input);
extern void blakehash(void *state, const void *input);
extern void freshhash(void *output, const void *input, uint32_t len);
extern void x11hash(void *output, const void *input);
extern void x13hash(void *output, const void *input);
extern void x14hash(void *output, const void *input);
extern void x15hash(void *output, const void *input);
extern void qubithash(void *output, const void *input);
extern void odohash(void *output, const void *input);
extern void neoscrypt_hash(void *output, const void *input);

/* CryptoNight and RandomX (JSON-RPC 2.0) job blobs: the nonce is at bytes
 * 39..42. The scan loops return the hash they found, which pools want. */
#define RPC2_MIN_BLOB 43
#define RPC2_MAX_BLOB 128

extern int scanhash_cryptonight(int thr_id, uint32_t *pdata, size_t data_size,
                            const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done,
                            unsigned char *hash);

/* RandomX (rx.c): the miner threads share a cache and, in fast mode, a
 * dataset, rebuilt when the key (the job's seed hash) changes */
enum { RX_MODE_AUTO, RX_MODE_FAST, RX_MODE_LIGHT };
extern bool rx_setup(int mode, int threads, int init_threads);
extern const char *rx_describe(void);
extern bool rx_is_fast(void);
extern void rx_cleanup(void);
extern bool rx_hash(int thr_id, void *output, const void *key, size_t keylen,
                            const void *input, size_t len);
extern int scanhash_randomx(int thr_id, uint32_t *pdata, size_t data_size,
                            const unsigned char *seed, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done,
                            unsigned char *hash);

struct thr_info {
	int		id;
	pthread_t	pth;
	struct thread_q	*q;
};

/* Set by the network threads when the miner threads should drop what they
 * are hashing; read in every scan loop. Atomic (a volatile flag is a data
 * race in C11); plain reads and writes of it are atomic operations, which
 * on x86 compile to ordinary loads. Padded to keep each thread's flag in
 * its own cache line. */
struct work_restart {
	_Atomic unsigned long	restart;
	char			padding[128 - sizeof(unsigned long)];
};

extern bool opt_debug;
extern bool opt_protocol;
extern bool opt_redirect;
extern int opt_timeout;
/* set at startup, or by one thread and read by others: atomic */
extern bool want_longpoll;
extern _Atomic bool have_longpoll;
extern _Atomic bool have_gbt;
extern bool want_stratum;
extern _Atomic bool have_stratum;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool use_syslog;
extern pthread_mutex_t applog_lock;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int stratum_thr_id;
extern struct work_restart *work_restart;
extern bool jsonrpc_2;
extern bool aes_ni_supported;

#define JSON_RPC_LONGPOLL	(1 << 0)
#define JSON_RPC_QUIET_404	(1 << 1)
#define JSON_RPC_IGNOREERR  (1 << 2)

extern void applog(int prio, const char *fmt, ...) PRINTF_FMT(2, 3);
extern json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass,
	const char *rpc_req, int *curl_err, int flags);
extern char *bin2hex(const unsigned char *p, size_t len);
extern void bin2hex_buf(char *s, const unsigned char *p, size_t len);
extern void memrev(unsigned char *p, size_t len);
extern int varint_encode(unsigned char *p, uint64_t n);
extern size_t address_to_script(unsigned char *out, size_t outsz, const char *addr);
extern bool hex2bin(unsigned char *p, const char *hexstr, size_t len);
extern int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y);
extern bool fulltest(const uint32_t *hash, const uint32_t *target);
extern void diff_to_target(uint32_t *target, double diff);

/* hex of a block's transaction count and transactions (megabytes), shared
 * by all the copies of a piece of work instead of copied (cpu-miner.c) */
struct txs_ref;

struct work {
    uint32_t data[32];
    uint32_t target[8];
    size_t data_size;	/* JSON-RPC 2.0: job blob length in bytes */
    double targetdiff;	/* stratum: pool difficulty the target came from */
    unsigned char seed_hash[32];	/* RandomX: the job's key */
    unsigned char result[32];	/* JSON-RPC 2.0: the hash of the share found */

    char *job_id;
    size_t xnonce2_len;
    unsigned char *xnonce2;
    unsigned conn_gen;	/* stratum: the connection the job came from */
    uint32_t odo_key;	/* Odocrypt's key for this header */

    /* getblocktemplate */
    int64_t height;
    struct txs_ref *txs;	/* the block's transactions, shared */
    char *workid;
};

struct stratum_job {
	char *job_id;
	unsigned char prevhash[32];
	size_t coinbase_size;
	unsigned char *coinbase;
	unsigned char *xnonce2;
	int merkle_count;
	unsigned char **merkle;
	unsigned char version[4];
	unsigned char nbits[4];
	unsigned char ntime[4];
	bool clean;
	double diff;
};

struct stratum_ctx {
	char *url;

	CURL *curl;
	char *curl_url;
	char curl_err_str[CURL_ERROR_SIZE];
	curl_socket_t sock;
	size_t sockbuf_size;
	char *sockbuf;
	pthread_mutex_t sock_lock;
	/* counts connections: work records the one its job came from, and
	 * shares from an earlier connection are not sent */
	_Atomic unsigned conn_gen;

	double next_diff;

	char *session_id;
	size_t xnonce1_size;
	unsigned char *xnonce1;
	size_t xnonce2_size;
	struct stratum_job job;
	struct work work;
	pthread_mutex_t work_lock;
};

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);

extern bool rpc2_job_decode(const json_t *job, struct work *work);
extern bool rpc2_login_decode(const json_t *val);
extern char *rpc2_login_req(const char *user, const char *pass);

struct thread_q;

extern struct thread_q *tq_new(void);
extern void tq_free(struct thread_q *tq);
extern bool tq_push(struct thread_q *tq, void *data);
extern void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
extern void tq_freeze(struct thread_q *tq);
extern void tq_thaw(struct thread_q *tq);

#endif /* __MINER_H__ */
