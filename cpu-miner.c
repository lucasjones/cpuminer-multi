/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>	/* before windows.h (curl.h includes it too) */
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

#define PROGRAM_NAME		"minerd"
#define LP_SCANTIME		60

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void) {
    struct sched_param param;
    param.sched_priority = 0;

#ifdef SCHED_IDLE
    if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
    sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static inline void affine_to_cpu(int id, int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif

enum workio_commands {
    WC_GET_WORK, WC_SUBMIT_WORK,
};

struct workio_cmd {
    enum workio_commands cmd;
    struct thr_info *thr;
    union {
        struct work *work;
    } u;
};

enum algos {
    ALGO_SCRYPT,      /* scrypt(1024,1,1) */
    ALGO_SHA256D,     /* SHA-256d */
    ALGO_KECCAK,      /* Keccak */
    ALGO_QUARK,       /* Quark */
    ALGO_SKEIN,       /* Skein */
    ALGO_SHAVITE3,    /* Shavite3 */
    ALGO_BLAKE,       /* Blake */
    ALGO_FRESH,       /* Fresh */
    ALGO_X11,         /* X11 */
    ALGO_X13,         /* X13 */
    ALGO_X14,         /* X14 */
    ALGO_X15,         /* X15 Whirlpool */
    ALGO_QUBIT,       /* Qubit */
    ALGO_ODO,         /* Odocrypt */
    ALGO_NEOSCRYPT,   /* NeoScrypt(128, 2, 1) */
    ALGO_ARGON2D4096, /* Argon2d, t=1 m=4096 p=1, version 1.3 */
    ALGO_ARGON2D500,  /* Argon2d, t=2 m=500 p=8 */
    ALGO_ARGON2D250,  /* Argon2d, t=1 m=250 p=4 */
    ALGO_ARGON2D16000,/* Argon2d, t=1 m=16000 p=1 */
    ALGO_YESCRYPT,    /* yescrypt 0.5, N=2048 r=8, the header as key */
    ALGO_YESCRYPTR8,  /* yescrypt 0.5, N=2048 r=8 */
    ALGO_YESCRYPTR16, /* yescrypt 0.5, N=4096 r=16 */
    ALGO_YESCRYPTR32, /* yescrypt 0.5, N=4096 r=32 */
    ALGO_YESPOWER,    /* yespower 1.0, N=2048 r=32 */
    ALGO_YESPOWERR16, /* yespower 1.0, N=4096 r=16 */
    ALGO_CRYPTONIGHT, /* CryptoNight */
    ALGO_RANDOMX,     /* RandomX (rx/0) */
    ALGO_VERTHASH,    /* Verthash */
};

static const char *algo_names[] = {
    [ALGO_SCRYPT] =      "scrypt",
    [ALGO_SHA256D] =     "sha256d",
    [ALGO_KECCAK] =      "keccak",
    [ALGO_QUARK] =       "quark",
    [ALGO_SKEIN] =       "skein",
    [ALGO_SHAVITE3] =    "shavite3",
    [ALGO_BLAKE] =       "blake",
    [ALGO_FRESH] =       "fresh",
    [ALGO_X11] =         "x11",
    [ALGO_X13] =         "x13",
    [ALGO_X14] =         "x14",
    [ALGO_X15] =         "x15",
    [ALGO_QUBIT] =       "qubit",
    [ALGO_ODO] =         "odo",
    [ALGO_NEOSCRYPT] =   "neoscrypt",
    [ALGO_ARGON2D4096] = "argon2d4096",
    [ALGO_ARGON2D500] =  "argon2d500",
    [ALGO_ARGON2D250] =  "argon2d250",
    [ALGO_ARGON2D16000] = "argon2d16000",
    [ALGO_YESCRYPT] =    "yescrypt",
    [ALGO_YESCRYPTR8] =  "yescryptr8",
    [ALGO_YESCRYPTR16] = "yescryptr16",
    [ALGO_YESCRYPTR32] = "yescryptr32",
    [ALGO_YESPOWER] =    "yespower",
    [ALGO_YESPOWERR16] = "yespowerr16",
    [ALGO_CRYPTONIGHT] = "cryptonight",
    [ALGO_RANDOMX] =     "randomx",
    [ALGO_VERTHASH] =    "verthash",
};

bool opt_debug = false;
bool opt_protocol = false;
static bool opt_benchmark = false;
bool opt_redirect = true;
bool want_longpoll = true;
_Atomic bool have_longpoll = false;
bool want_stratum = true;
_Atomic bool have_stratum = false;
static _Atomic bool submit_old = false;
_Atomic bool have_gbt = true;	/* HTTP: try getblocktemplate before getwork */
static bool allow_getwork = true;
/* the node mines several algorithms (DigiByte): name ours in requests */
static _Atomic bool gbt_name_algo = false;
static char *opt_coinbase_addr;	/* getblocktemplate: where the block reward goes */
static uint32_t opt_param_n, opt_param_r;	/* yescrypt/yespower parameters */
static char *opt_param_key;
static char coinbase_sig[101] = "";
static unsigned char pk_script[128];	/* ... as an output script */
static size_t pk_script_size;
static char *lp_id;		/* getblocktemplate long polling id */
static pthread_mutex_t lp_id_lock = PTHREAD_MUTEX_INITIALIZER;
/* set when retrying cannot help (bad payout address, unsupported coin) */
static _Atomic bool fatal_error = false;
bool use_syslog = false;
static bool opt_background = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
bool jsonrpc_2 = false;
int opt_timeout = 0;
static int opt_scantime = 5;
static json_t *opt_config;
static const bool opt_time = true;
static enum algos opt_algo = ALGO_SCRYPT;
static int opt_scrypt_n = 1024;
static int opt_randomx_mode = RX_MODE_AUTO;
static char *opt_verthash_data;
static double opt_diff_factor = 1.0;
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
struct work_restart *work_restart = NULL;
static struct stratum_ctx stratum;
/* CryptoNight and RandomX (JSON-RPC 2.0) session state, protected by
 * rpc2_job_lock */
static char rpc2_id[64] = "";		/* under rpc2_id_lock */
static unsigned char rpc2_blob[RPC2_MAX_BLOB];
static size_t rpc2_bloblen = 0;
static uint32_t rpc2_target[2] = { 0, 0 };	/* low, high 32 bits */
static unsigned char rpc2_seed[32];	/* RandomX: the key */
static char *rpc2_job_id = NULL;
#define RPC2_KEEPALIVE_ID 3		/* the id of our "keepalived" requests */
bool aes_ni_supported = false;

/* Statically initialized: applog() can run before main() gets far, and a
 * zero-filled mutex is not a valid mutex everywhere (e.g. winpthreads). */
pthread_mutex_t applog_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

/* Shares handed to the workio thread but not sent yet. The queue is bounded
 * so that a pool setting an absurdly low difficulty (every hash a share)
 * cannot make the miner threads queue shares faster than they can be sent
 * until memory runs out. Protected by stats_lock. */
#define MAX_PENDING_SHARES 256
static int pending_shares;

static pthread_mutex_t rpc2_job_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rpc2_login_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rpc2_id_lock = PTHREAD_MUTEX_INITIALIZER;

/* copy the CryptoNight pool session id (empty before login) */
static void rpc2_get_id(char *id)
{
    pthread_mutex_lock(&rpc2_id_lock);
    strcpy(id, rpc2_id);
    pthread_mutex_unlock(&rpc2_id_lock);
}

static unsigned long accepted_count = 0L;
static unsigned long rejected_count = 0L;
static double *thr_hashrates;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#endif

static char const usage[] =
        "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the algorithm to use\n\
                          scrypt       scrypt(1024, 1, 1): Litecoin, Dogecoin\n\
                                         (default)\n\
                          scrypt:N     scrypt(N, 1, 1)\n\
                          sha256d      SHA-256d: Bitcoin and many others\n\
                          x11          X11: Dash\n\
                          blake        BLAKE-256, 8 rounds: Blakecoin\n\
                          skein        SHA-256 of Skein-512: DigiByte\n\
                          qubit        Qubit: DigiByte\n\
                          odo          Odocrypt: DigiByte\n\
                          neoscrypt    NeoScrypt: Feathercoin\n\
                          argon2d4096  Argon2d, 4 MiB: Myriad, Unitus\n\
                          argon2d500   Argon2d, 500 KiB: Dynamic\n\
                          argon2d250   Argon2d, 250 KiB: Credits\n\
                          argon2d16000 Argon2d, 16 MB: Alterdot\n\
                          yescrypt     yescrypt: Myriad, GlobalBoost-Y\n\
                          yescryptr8   yescrypt, \"Client Key\"\n\
                          yescryptr16  yescrypt, N=4096 r=16\n\
                          yescryptr32  yescrypt, N=4096 r=32: WAVI\n\
                          yespower     yespower 1.0, N=2048 r=32 (--param-*)\n\
                          yespowerr16  yespower 1.0, N=4096 r=16: Yenten\n\
                          randomx      RandomX (rx/0): Monero\n\
                          verthash     Verthash: Vertcoin\n\
                          cryptonight  CryptoNight: Bytecoin\n\
                          keccak       Keccak-256: Maxcoin\n\
                          quark        Quark\n\
                          shavite3     SHAvite-3: INKcoin\n\
                          fresh        Fresh\n\
                          x13          X13\n\
                          x14          X14\n\
                          x15          X15\n\
  -o, --url=URL         URL of mining server: stratum+tcp://HOST:PORT for a\n\
                          pool, http://HOST:PORT for a coin node (solo\n\
                          mining) or a getwork server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --coinbase-addr=ADDR  solo mining: address to pay the block reward to\n\
      --coinbase-sig=TEXT   solo mining: text to put in the coinbase\n\
      --no-gbt          disable getblocktemplate support\n\
      --no-getwork      disable getwork support\n\
  -f, --diff-factor=N   divide the pool's share difficulty by N (default: 1)\n\
      --param-n=N       yescrypt/yespower: N (a power of 2 from 1024 on)\n\
      --param-r=R       yescrypt/yespower: r (8 to 32)\n\
      --param-key=TEXT  yescrypt/yespower: personalization string\n\
      --randomx-mode=MODE  RandomX: fast (2.3 GiB of memory), light (256 MiB,\n\
                          several times slower), or auto (default: fast if\n\
                          the machine has the memory)\n\
      --verthash-data=FILE  Verthash: the 1.2 GB data file (default:\n\
                          verthash.dat here, or Vertcoin Core's; built and\n\
                          saved if there is none)\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 10)\n\
  -T, --timeout=N       timeout for long polling, in seconds (default: none)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
      --no-longpoll     disable long polling\n\
      --no-stratum      disable X-Stratum support\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -q, --quiet           disable per-thread hashmeter output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n"
#ifdef HAVE_SYSLOG_H
        "\
  -S, --syslog          use system log for output messages\n"
#endif
#ifndef _WIN32
        "\
  -B, --background      run the miner in the background\n"
#endif
        "\
      --benchmark       run in offline benchmark mode\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] =
#ifndef _WIN32
        "B"
#endif
#ifdef HAVE_SYSLOG_H
                "S"
#endif
        "a:c:Df:hp:Px:qr:R:s:t:T:o:u:O:V";

static struct option const options[] = {
        { "algo", 1, NULL, 'a' },
#ifndef _WIN32
        { "background", 0, NULL, 'B' },
#endif
        { "benchmark", 0, NULL, 1005 },
        { "cert", 1, NULL, 1001 },
        { "coinbase-addr", 1, NULL, 1013 },
        { "coinbase-sig", 1, NULL, 1015 },
        { "config", 1, NULL, 'c' },
        { "debug", 0, NULL, 'D' },
        { "diff-factor", 1, NULL, 'f' },
        { "help", 0, NULL, 'h' },
        { "no-gbt", 0, NULL, 1011 },
        { "no-getwork", 0, NULL, 1010 },
        { "no-longpoll", 0, NULL, 1003 },
        { "no-redirect", 0, NULL, 1009 },
        { "no-stratum", 0, NULL, 1007 },
        { "param-key", 1, NULL, 1018 },
        { "param-n", 1, NULL, 1016 },
        { "param-r", 1, NULL, 1017 },
        { "pass", 1, NULL, 'p' },
        { "protocol-dump", 0, NULL, 'P' },
        { "proxy", 1, NULL, 'x' },
        { "quiet", 0, NULL, 'q' },
        { "randomx-mode", 1, NULL, 1019 },
        { "retries", 1, NULL, 'r' },
        { "retry-pause", 1, NULL, 'R' },
        { "scantime", 1, NULL, 's' },
#ifdef HAVE_SYSLOG_H
        { "syslog", 0, NULL, 'S' },
#endif
        { "threads", 1, NULL, 't' },
        { "timeout", 1, NULL, 'T' },
        { "url", 1, NULL, 'o' },
        { "user", 1, NULL, 'u' },
        { "userpass", 1, NULL, 'O' },
        { "verthash-data", 1, NULL, 1020 },
        { "version", 0, NULL, 'V' },
        { 0, 0, 0, 0 }
};

static struct work g_work;
static time_t g_work_time;
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;

static bool rpc2_login(CURL *curl);
static void workio_cmd_free(struct workio_cmd *wc);

json_t *json_rpc2_call_recur(CURL *curl, const char *url,
		const char *userpass, json_t *rpc_req,
		int *curl_err, int flags, int recur) {
	json_t *res, *error, *message, *params, *auth_id;
	const char *mes;
	char *req, id[sizeof(rpc2_id)];

	if (recur >= 5) {
		if (opt_debug)
			applog(LOG_DEBUG, "Failed to call rpc command after %i tries", recur);
		return NULL;
	}
	rpc2_get_id(id);
	if (!*id) {
		if (opt_debug)
			applog(LOG_DEBUG, "Tried to call rpc2 command before authentication");
		return NULL;
	}
	params = json_object_get(rpc_req, "params");
	auth_id = json_object_get(params, "id");
	if (auth_id)
		json_string_set(auth_id, id);

	req = json_dumps(rpc_req, 0);
	if (!req)
		return NULL;
	res = json_rpc_call(curl, url, userpass, req, curl_err,
			flags | JSON_RPC_IGNOREERR);
	free(req);
	if (!res)
		return NULL;

	error = json_object_get(res, "error");
	if (!error || json_is_null(error))
		return res;
	message = json_is_string(error) ? error : json_object_get(error, "message");
	mes = json_string_value(message);
	if (!mes)
		return res;

	if (!strcmp(mes, "Unauthenticated")) {
		json_decref(res);
		pthread_mutex_lock(&rpc2_login_lock);
		rpc2_login(curl);
		sleep(1);
		pthread_mutex_unlock(&rpc2_login_lock);
		return json_rpc2_call_recur(curl, url, userpass, rpc_req,
				curl_err, flags, recur + 1);
	}
	if (!strcmp(mes, "Low difficulty share") || !strcmp(mes, "Block expired") ||
	    !strcmp(mes, "Invalid job id") || !strcmp(mes, "Duplicate share")) {
		json_t *result = json_object_get(res, "result");
		if (json_is_object(result))
			json_object_set_new(result, "reject-reason", json_string(mes));
		return res;
	}
	applog(LOG_ERR, "JSON-RPC 2.0 error: %s", mes);
	json_decref(res);
	return NULL;
}

json_t *json_rpc2_call(CURL *curl, const char *url,
		const char *userpass, const char *rpc_req,
		int *curl_err, int flags) {
	json_t *req_json = JSON_LOADS(rpc_req, NULL);
	json_t *res;

	if (!req_json)
		return NULL;
	res = json_rpc2_call_recur(curl, url, userpass, req_json,
			curl_err, flags, 0);
	json_decref(req_json);
	return res;
}

struct txs_ref {
    unsigned refs;	/* under txs_ref_lock */
    size_t len;
    char hex[];
};
static pthread_mutex_t txs_ref_lock = PTHREAD_MUTEX_INITIALIZER;

static void txs_release(struct txs_ref *t)
{
    bool last;

    if (!t)
        return;
    pthread_mutex_lock(&txs_ref_lock);
    last = --t->refs == 0;
    pthread_mutex_unlock(&txs_ref_lock);
    if (last)
        free(t);
}

static struct txs_ref *txs_share(struct txs_ref *t)
{
    if (t) {
        pthread_mutex_lock(&txs_ref_lock);
        t->refs++;
        pthread_mutex_unlock(&txs_ref_lock);
    }
    return t;
}

static inline void work_free(struct work *w) {
    free(w->job_id);
    free(w->xnonce2);
    txs_release(w->txs);
    free(w->workid);
    w->job_id = NULL;
    w->xnonce2 = NULL;
    w->txs = NULL;
    w->workid = NULL;
}

static inline void work_copy(struct work *dest, const struct work *src) {
    memcpy(dest, src, sizeof(struct work));
    if (src->job_id)
        dest->job_id = strdup(src->job_id);
    if (src->xnonce2) {
        dest->xnonce2 = malloc(src->xnonce2_len);
        if (dest->xnonce2)
            memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
    }
    dest->txs = txs_share(src->txs);
    if (src->workid)
        dest->workid = strdup(src->workid);
}

static bool jobj_binary(const json_t *obj, const char *key, void *buf,
        size_t buflen) {
    const char *hexstr;
    json_t *tmp;

    tmp = json_object_get(obj, key);
    if (unlikely(!tmp)) {
        applog(LOG_ERR, "JSON key '%s' not found", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (unlikely(!hexstr)) {
        applog(LOG_ERR, "JSON key '%s' is not a string", key);
        return false;
    }
    if (!hex2bin(buf, hexstr, buflen))
        return false;

    return true;
}

/* A CryptoNight "target" is the share target as little-endian hex: either
 * 4 bytes (compared with the top 32 bits of the hash) or 8 bytes (compared
 * with the top 64 bits). Returns the low and high 32-bit halves. */
static bool rpc2_decode_target(const char *hex, uint32_t target[2])
{
    unsigned char t[8];

    if (!hex)
        return false;
    switch (strlen(hex)) {
    case 8:
        if (!hex2bin(t, hex, 4))
            return false;
        target[0] = 0;
        target[1] = le32dec(t);
        break;
    case 16:
        if (!hex2bin(t, hex, 8))
            return false;
        target[0] = le32dec(t);
        target[1] = le32dec(t + 4);
        break;
    default:
        return false;
    }
    return target[0] || target[1];
}

static double rpc2_target_diff(const uint32_t target[2])
{
    uint64_t t = ((uint64_t) target[1] << 32) | target[0];
    return t ? 18446744073709551615.0 / (double) t : 0.;
}

/* the names pools give the algorithm being mined (xmrig's, and others) */
static bool rpc2_algo_ok(const char *algo)
{
    static const char *const cn[] = { "cn/0", "cryptonight", "cryptonight/0", "cn", NULL };
    static const char *const rx[] = { "rx/0", "randomx", "rx", NULL };
    const char *const *name = opt_algo == ALGO_RANDOMX ? rx : cn;

    if (!algo)
        return true;	/* the pool did not say */
    for (; *name; name++)
        if (!strcasecmp(algo, *name))
            return true;
    return false;
}

/* the name we give pools for the algorithm */
static const char *rpc2_algo_name(void)
{
    return opt_algo == ALGO_RANDOMX ? "rx/0" : "cn/0";
}

/* Decode a JSON-RPC 2.0 job ("job" notification, or the job in a login or
 * getjob reply). An empty blob keeps the previous job. With a non-NULL
 * work, the current job is copied into it. */
bool rpc2_job_decode(const json_t *job, struct work *work) {
    const char *job_id, *hexblob, *hextarget, *algo, *hexseed;
    unsigned char blob[RPC2_MAX_BLOB], seed[32];
    uint32_t target[2];
    size_t bloblen;
    bool ok = false;

    if (!jsonrpc_2) {
        applog(LOG_ERR, "Tried to decode job without JSON-RPC 2.0");
        return false;
    }
    job_id = json_string_value(json_object_get(job, "job_id"));
    hexblob = json_string_value(json_object_get(job, "blob"));
    hextarget = json_string_value(json_object_get(job, "target"));
    if (!job_id || !*job_id || !hexblob) {
        applog(LOG_ERR, "JSON-RPC 2.0 job: missing or invalid job_id or blob");
        return false;
    }
    bloblen = strlen(hexblob);
    if (bloblen && (bloblen % 2 || bloblen / 2 < RPC2_MIN_BLOB ||
                    bloblen / 2 > RPC2_MAX_BLOB)) {
        applog(LOG_ERR, "JSON-RPC 2.0 job: invalid blob length (%zu bytes)", bloblen / 2);
        return false;
    }
    bloblen /= 2;
    if (bloblen && !hex2bin(blob, hexblob, bloblen))
        return false;
    if (bloblen && !rpc2_decode_target(hextarget, target)) {
        applog(LOG_ERR, "JSON-RPC 2.0 job: missing or invalid target");
        return false;
    }
    /* a pool that mines several algorithms says which (xmrig's names) */
    algo = json_string_value(json_object_get(job, "algo"));
    if (bloblen && !rpc2_algo_ok(algo)) {
        applog(LOG_ERR, "The pool sent a job for %s; this miner mines %s",
                algo, rpc2_algo_name());
        return false;
    }
    /* RandomX: the key, which changes every 2048 blocks on Monero */
    if (bloblen && opt_algo == ALGO_RANDOMX) {
        hexseed = json_string_value(json_object_get(job, "seed_hash"));
        if (!hexseed || strlen(hexseed) != 64 || !hex2bin(seed, hexseed, 32)) {
            applog(LOG_ERR, "JSON-RPC 2.0 job: missing or invalid seed_hash (not a RandomX pool?)");
            return false;
        }
    }

    pthread_mutex_lock(&rpc2_job_lock);
    if (bloblen) {
        memcpy(rpc2_blob, blob, bloblen);
        rpc2_bloblen = bloblen;
        if (opt_algo == ALGO_RANDOMX)
            memcpy(rpc2_seed, seed, 32);
        if (target[0] != rpc2_target[0] || target[1] != rpc2_target[1]) {
            applog(LOG_INFO, "Pool set diff to %g", rpc2_target_diff(target));
            rpc2_target[0] = target[0];
            rpc2_target[1] = target[1];
        }
        free(rpc2_job_id);
        rpc2_job_id = strdup(job_id);
    }
    if (!rpc2_bloblen || !rpc2_job_id) {
        applog(LOG_ERR, "Requested work before work was received");
        goto out;
    }
    if (work) {
        memset(work->data, 0, sizeof(work->data));
        memcpy(work->data, rpc2_blob, rpc2_bloblen);
        work->data_size = rpc2_bloblen;
        memset(work->target, 0xff, sizeof(work->target));
        work->target[6] = rpc2_target[0];
        work->target[7] = rpc2_target[1];
        memcpy(work->seed_hash, rpc2_seed, 32);
        free(work->job_id);
        work->job_id = strdup(rpc2_job_id);
    }
    ok = true;
out:
    pthread_mutex_unlock(&rpc2_job_lock);
    return ok;
}

static bool work_decode(const json_t *val, struct work *work) {
    int i;

    if(jsonrpc_2) {
        return rpc2_job_decode(val, work);
    }

    if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
        applog(LOG_ERR, "getwork: invalid data");
        goto err_out;
    }
    if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
        applog(LOG_ERR, "getwork: invalid target");
        goto err_out;
    }

    for (i = 0; i < ARRAY_SIZE(work->data); i++)
        work->data[i] = le32dec(work->data + i);
    for (i = 0; i < ARRAY_SIZE(work->target); i++)
        work->target[i] = le32dec(work->target + i);
    work->odo_key = odo_key(swab32(work->data[17]), ODO_INTERVAL_MAINNET);

    return true;

    err_out: return false;
}

/* The id of a transaction the miner builds itself (the coinbase): double
 * SHA-256 for Bitcoin and most coins derived from it; Blakecoin (and the
 * coins merge-mined with it) and Maxcoin use a single SHA-256. */
static void coinbase_txid(unsigned char *hash, const unsigned char *tx, size_t len)
{
    if (opt_algo == ALGO_BLAKE || opt_algo == ALGO_KECCAK)
        sha256_hash(hash, tx, len);
    else
        sha256d(hash, tx, (int) len);
}

/* Merkle root of n >= 1 leaves; tree needs room for n + 1 hashes and is
 * overwritten. */
static void merkle_root(unsigned char (*tree)[32], size_t n)
{
    size_t i;

    while (n > 1) {
        if (n % 2)
            memcpy(tree[n], tree[n - 1], 32);
        n = (n + 1) / 2;
        for (i = 0; i < n; i++)
            sha256d(tree[i], tree[2 * i], 64);
    }
}

/* JSON integer member in [min, max] */
static bool jobj_int(const json_t *obj, const char *key, int64_t min,
        int64_t max, int64_t *out)
{
    json_t *v = json_object_get(obj, key);

    if (!json_is_integer(v) || json_integer_value(v) < min
            || json_integer_value(v) > max) {
        applog(LOG_ERR, "getblocktemplate: missing or invalid %s", key);
        return false;
    }
    *out = json_integer_value(v);
    return true;
}

/*
 * Build work from a block template (BIP 22, 23; BIP 34 height in the
 * coinbase; BIP 141 witness commitment). Unless the server sends a coinbase
 * transaction ("coinbasetxn"), we build one paying the whole reward to
 * pk_script.
 */
static bool gbt_work_decode(const json_t *val, struct work *work)
{
    unsigned char prevhash[32], bits[4], target[32], ssig[100], xsig[100];
    unsigned char (*merkle)[32] = NULL, (*wtree)[32] = NULL;
    unsigned char *cbtx = NULL, commitment[38];
    size_t cbtx_size = 0, ssig_len = 0, xsig_len = 0, commitment_len = 0;
    size_t tx_count, txs_hex_len = 0, i, n;
    bool coinbase_append = false, segwit = false;
    int64_t height, version, curtime, cbvalue = 0;
    json_t *tmp, *txa;
    char *p;
    bool rc = false;

    if (!json_is_object(val)) {
        applog(LOG_ERR, "getblocktemplate: no block template in the reply");
        return false;
    }

    /* BIP 9: rules in force; one marked '!' must be understood by whoever
     * builds the block, or the block is invalid */
    tmp = json_object_get(val, "rules");
    for (i = 0; i < json_array_size(tmp); i++) {
        const char *rule = json_string_value(json_array_get(tmp, i));
        bool required = rule && *rule == '!';

        if (!rule)
            continue;
        if (required)
            rule++;
        if (!strcmp(rule, "segwit"))
            segwit = true;
        else if (required) {
            applog(LOG_ERR, "getblocktemplate: the node requires rule \"%s\", "
                    "which this miner does not support: mine through a pool",
                    rule);
            fatal_error = true;
            return false;
        }
    }
    tmp = json_object_get(val, "mutable");
    for (i = 0; i < json_array_size(tmp); i++) {
        const char *s = json_string_value(json_array_get(tmp, i));
        if (s && !strcmp(s, "coinbase/append"))
            coinbase_append = true;
    }

    /* A node of a coin with several algorithms (DigiByte) makes templates
     * for one of them, named in "pow_algo" (and in the version bits): its
     * default one, unless the request names another. */
    tmp = json_object_get(val, "pow_algo");
    if (json_is_string(tmp) && strcmp(json_string_value(tmp), algo_names[opt_algo])) {
        if (!gbt_name_algo) {
            applog(LOG_INFO, "The node made a %s block template: asking for %s",
                    json_string_value(tmp), algo_names[opt_algo]);
            gbt_name_algo = true;
        } else {
            applog(LOG_ERR, "The node cannot make %s block templates (it made a %s one)",
                    algo_names[opt_algo], json_string_value(tmp));
            fatal_error = true;
        }
        return false;
    }

    if (!jobj_int(val, "height", 1, 0x7fffffff, &height)
            || !jobj_int(val, "version", 0, 0xffffffffLL, &version)
            || !jobj_int(val, "curtime", 0, 0xffffffffLL, &curtime))
        return false;
    if (!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash))
            || !jobj_binary(val, "bits", bits, sizeof(bits))
            || !jobj_binary(val, "target", target, sizeof(target))) {
        applog(LOG_ERR, "getblocktemplate: invalid previousblockhash, bits or target");
        return false;
    }
    txa = json_object_get(val, "transactions");
    if (!json_is_array(txa)) {
        applog(LOG_ERR, "getblocktemplate: invalid transactions");
        return false;
    }
    tx_count = json_array_size(txa);

    /* Merkle leaves: the coinbase, then the transactions by the ids the
     * node gives (so no need to know how this coin hashes transactions) */
    merkle = malloc(32 * (tx_count + 2));
    if (segwit)
        wtree = calloc(tx_count + 2, 32);
    if (!merkle || (segwit && !wtree))
        goto out;
    for (i = 0; i < tx_count; i++) {
        const json_t *tx = json_array_get(txa, i);
        const char *data = json_string_value(json_object_get(tx, "data"));
        const char *txid = json_string_value(json_object_get(tx, "txid"));
        const char *hash = json_string_value(json_object_get(tx, "hash"));

        if (!txid)
            txid = hash;	/* before segwit, "hash" was the txid */
        if (!data || strlen(data) % 2) {
            applog(LOG_ERR, "getblocktemplate: invalid transaction data");
            goto out;
        }
        txs_hex_len += strlen(data);
        if (txid) {
            if (strlen(txid) != 64 || !hex2bin(merkle[1 + i], txid, 32)) {
                applog(LOG_ERR, "getblocktemplate: invalid transaction id");
                goto out;
            }
            memrev(merkle[1 + i], 32);
        } else {
            size_t len = strlen(data) / 2;
            unsigned char *buf = malloc(len ? len : 1);

            if (!buf || !hex2bin(buf, data, len)) {
                free(buf);
                applog(LOG_ERR, "getblocktemplate: invalid transaction data");
                goto out;
            }
            coinbase_txid(merkle[1 + i], buf, len);
            free(buf);
        }
        /* witness ids, for the witness commitment (BIP 141) */
        if (wtree && hash) {
            if (strlen(hash) != 64 || !hex2bin(wtree[1 + i], hash, 32)) {
                applog(LOG_ERR, "getblocktemplate: invalid transaction hash");
                goto out;
            }
            memrev(wtree[1 + i], 32);
        } else if (wtree)
            memcpy(wtree[1 + i], merkle[1 + i], 32);
    }

    /* the witness commitment output: the node's, or computed as in BIP 141
     * (the coinbase's witness id is zero, the witness reserved value too) */
    if (segwit) {
        const char *wc = json_string_value(json_object_get(val,
                "default_witness_commitment"));
        if (wc) {
            commitment_len = strlen(wc) / 2;
            if (strlen(wc) % 2 || commitment_len > sizeof(commitment)
                    || !hex2bin(commitment, wc, commitment_len)) {
                applog(LOG_ERR, "getblocktemplate: invalid default_witness_commitment");
                goto out;
            }
        } else {
            unsigned char buf[64];

            memset(wtree[0], 0, 32);
            merkle_root(wtree, tx_count + 1);
            memcpy(buf, wtree[0], 32);
            memset(buf + 32, 0, 32);
            commitment[0] = 0x6a;		/* OP_RETURN */
            commitment[1] = 0x24;		/* push 36 bytes */
            memcpy(commitment + 2, "\xaa\x21\xa9\xed", 4);
            sha256d(commitment + 6, buf, 64);
            commitment_len = 38;
        }
    }

    /* extra coinbase data: what the node asks for (coinbaseaux), and ours */
    tmp = json_object_get(val, "coinbaseaux");
    if (json_is_object(tmp)) {
        const char *key;
        json_t *v;

        json_object_foreach(tmp, key, v) {
            const char *s = json_string_value(v);

            n = s ? strlen(s) / 2 : 0;
            if (!s || strlen(s) % 2 || xsig_len + n > sizeof(xsig)
                    || !hex2bin(xsig + xsig_len, s, n)) {
                applog(LOG_ERR, "getblocktemplate: invalid coinbaseaux");
                goto out;
            }
            xsig_len += n;
        }
    }
    n = strlen(coinbase_sig);
    if (xsig_len + n <= sizeof(xsig)) {
        memcpy(xsig + xsig_len, coinbase_sig, n);
        xsig_len += n;
    } else
        applog(LOG_WARNING, "Coinbase signature does not fit, leaving it out");

    tmp = json_object_get(val, "coinbasetxn");
    if (tmp) {
        /* the server's coinbase: version, 1 input (null prevout),
         * scriptSig length (< 253) at byte 41, the rest */
        const char *hex = json_string_value(json_object_get(tmp, "data"));

        n = hex ? strlen(hex) / 2 : 0;
        cbtx = malloc(n + sizeof(ssig) + 2);
        if (!cbtx || n < 60 || strlen(hex) % 2 || !hex2bin(cbtx, hex, n)
                || cbtx[4] != 1 || cbtx[41] > 100 || 42 + cbtx[41] + 4 > n) {
            applog(LOG_ERR, "getblocktemplate: invalid coinbasetxn");
            goto out;
        }
        cbtx_size = n;
        if (coinbase_append && xsig_len && cbtx[41] + xsig_len + 2 <= 100) {
            unsigned char *end = cbtx + 42 + cbtx[41];
            size_t push = xsig_len < 76 ? 1 : 2;

            memmove(end + push + xsig_len, end, cbtx + cbtx_size - end);
            if (push == 2)
                *end++ = 0x4c;		/* OP_PUSHDATA1 */
            *end++ = (unsigned char) xsig_len;
            memcpy(end, xsig, xsig_len);
            cbtx[41] += (unsigned char) (push + xsig_len);
            cbtx_size += push + xsig_len;
        }
    } else {
        if (!pk_script_size) {
            if (allow_getwork) {
                applog(LOG_INFO, "No payout address (--coinbase-addr), trying getwork");
                have_gbt = false;
            } else {
                applog(LOG_ERR, "Solo mining needs a payout address: --coinbase-addr=ADDRESS");
                fatal_error = true;
            }
            goto out;
        }
        if (!jobj_int(val, "coinbasevalue", 0, INT64_MAX, &cbvalue))
            goto out;

        /* scriptSig: the block height (BIP 34) as Bitcoin Core writes it,
         * then the extra data as one push */
        if (height <= 16) {
            ssig[ssig_len++] = 0x50 + height;	/* OP_1 .. OP_16 */
            ssig[ssig_len++] = 0x00;		/* OP_0: at least 2 bytes */
        } else {
            size_t lenpos = ssig_len++;
            int64_t h;

            for (h = height; h; h >>= 8) {
                ssig[ssig_len++] = h & 0xff;
                if (h < 0x100 && h >= 0x80)
                    ssig[ssig_len++] = 0;	/* keep the number positive */
            }
            ssig[lenpos] = (unsigned char) (ssig_len - lenpos - 1);
        }
        if (xsig_len && ssig_len + xsig_len + (xsig_len < 76 ? 1 : 2) > sizeof(ssig))
            xsig_len = sizeof(ssig) - ssig_len - 2;
        if (xsig_len) {
            if (xsig_len >= 76)
                ssig[ssig_len++] = 0x4c;	/* OP_PUSHDATA1 */
            ssig[ssig_len++] = (unsigned char) xsig_len;
            memcpy(ssig + ssig_len, xsig, xsig_len);
            ssig_len += xsig_len;
        }

        /* 42 bytes up to the scriptSig, sequence 4, output count 1,
         * 2 * (value 8 + script length 1), lock time 4: 69 */
        cbtx = malloc(69 + ssig_len + pk_script_size + commitment_len);
        if (!cbtx)
            goto out;
        le32enc((uint32_t *) cbtx, 1);			/* version */
        cbtx[4] = 1;					/* inputs */
        memset(cbtx + 5, 0, 32);			/* prevout: none */
        le32enc((uint32_t *) (cbtx + 37), 0xffffffff);
        cbtx[41] = (unsigned char) ssig_len;
        memcpy(cbtx + 42, ssig, ssig_len);
        cbtx_size = 42 + ssig_len;
        le32enc((uint32_t *) (cbtx + cbtx_size), 0xffffffff);	/* sequence */
        cbtx_size += 4;
        cbtx[cbtx_size++] = commitment_len ? 2 : 1;	/* outputs */
        le32enc((uint32_t *) (cbtx + cbtx_size), (uint32_t) cbvalue);
        le32enc((uint32_t *) (cbtx + cbtx_size + 4), (uint32_t) (cbvalue >> 32));
        cbtx_size += 8;
        cbtx[cbtx_size++] = (unsigned char) pk_script_size;
        memcpy(cbtx + cbtx_size, pk_script, pk_script_size);
        cbtx_size += pk_script_size;
        if (commitment_len) {
            memset(cbtx + cbtx_size, 0, 8);		/* value */
            cbtx_size += 8;
            cbtx[cbtx_size++] = (unsigned char) commitment_len;
            memcpy(cbtx + cbtx_size, commitment, commitment_len);
            cbtx_size += commitment_len;
        }
        le32enc((uint32_t *) (cbtx + cbtx_size), 0);	/* lock time */
        cbtx_size += 4;
    }

    /* the block's transactions, hex, for submitblock */
    {
        unsigned char vi[9];
        int vi_len = varint_encode(vi, 1 + tx_count);

        size_t len = 2 * (vi_len + cbtx_size) + txs_hex_len;

        txs_release(work->txs);
        work->txs = malloc(sizeof(*work->txs) + len + 1);
        if (!work->txs)
            goto out;
        work->txs->refs = 1;
        work->txs->len = len;
        bin2hex_buf(work->txs->hex, vi, vi_len);
        bin2hex_buf(work->txs->hex + 2 * vi_len, cbtx, cbtx_size);
        p = work->txs->hex + 2 * (vi_len + cbtx_size);
        for (i = 0; i < tx_count; i++) {
            const char *data = json_string_value(json_object_get(
                    json_array_get(txa, i), "data"));
            n = strlen(data);
            memcpy(p, data, n);
            p += n;
        }
        *p = '\0';
    }

    coinbase_txid(merkle[0], cbtx, cbtx_size);
    merkle_root(merkle, tx_count + 1);

    /* assemble block header */
    work->data[0] = swab32((uint32_t) version);
    for (i = 0; i < 8; i++)
        work->data[8 - i] = le32dec((uint32_t *) prevhash + i);
    for (i = 0; i < 8; i++)
        work->data[9 + i] = be32dec((uint32_t *) merkle[0] + i);
    work->data[17] = swab32((uint32_t) curtime);
    /* Odocrypt (DigiByte): the node's key, which is right on every network */
    tmp = json_object_get(val, "odokey");
    if (json_is_integer(tmp))
        work->odo_key = (uint32_t) json_integer_value(tmp);
    else
        work->odo_key = odo_key((uint32_t) curtime, ODO_INTERVAL_MAINNET);
    work->data[18] = le32dec((uint32_t *) bits);
    memset(work->data + 19, 0x00, 52);
    work->data[20] = 0x80000000;
    work->data[31] = 0x00000280;
    for (i = 0; i < ARRAY_SIZE(work->target); i++)
        work->target[7 - i] = be32dec((uint32_t *) target + i);
    work->height = height;

    free(work->workid);
    work->workid = NULL;
    tmp = json_object_get(val, "workid");
    if (json_is_string(tmp))
        work->workid = strdup(json_string_value(tmp));

    /* long polling (BIP 22) */
    tmp = json_object_get(val, "longpollid");
    if (want_longpoll && longpoll_thr_id >= 0 && json_is_string(tmp)) {
        pthread_mutex_lock(&lp_id_lock);
        free(lp_id);
        lp_id = strdup(json_string_value(tmp));
        pthread_mutex_unlock(&lp_id_lock);
        if (!have_longpoll) {
            json_t *uri = json_object_get(val, "longpolluri");

            have_longpoll = true;
            tq_push(thr_info[longpoll_thr_id].q,
                    strdup(json_is_string(uri) ? json_string_value(uri) : rpc_url));
        }
    }

    rc = true;

out:
    free(cbtx);
    free(merkle);
    free(wtree);
    return rc;
}

/* getblocktemplate request; with a long polling id for long polling */
static char *gbt_request(const char *longpollid)
{
    json_t *params, *req;
    char *s;

    params = json_pack("{s:[s, s, s, s], s:[s]}",
            "capabilities", "coinbasetxn", "coinbasevalue", "longpoll", "workid",
            "rules", "segwit");
    if (params && longpollid)
        json_object_set_new(params, "longpollid", json_string(longpollid));
    req = json_pack("{s:s, s:[o], s:i}", "method", "getblocktemplate",
            "params", params, "id", 0);
    /* DigiByte: the algorithm, as the second parameter */
    if (req && gbt_name_algo)
        json_array_append_new(json_object_get(req, "params"),
                json_string(algo_names[opt_algo]));
    s = req ? json_dumps(req, 0) : NULL;
    json_decref(req);
    return s;
}

/*
 * Find the output script paying to --coinbase-addr. The node knows best:
 * base58 version bytes vary from coin to coin, and it can tell an address
 * of another coin or network. Nodes too old to say (validateaddress without
 * scriptPubKey) leave it to address_to_script(). False on network errors.
 */
static bool resolve_payout_script(CURL *curl)
{
    json_t *req, *val, *res;
    const char *spk = NULL;
    char *s;
    int err = CURLE_OK;

    req = json_pack("{s:s, s:[s], s:i}", "method", "validateaddress",
            "params", opt_coinbase_addr, "id", 1);
    s = req ? json_dumps(req, 0) : NULL;
    json_decref(req);
    if (!s)
        return false;
    val = json_rpc_call(curl, rpc_url, rpc_userpass, s, &err,
            JSON_RPC_QUIET_404 | JSON_RPC_IGNOREERR);
    free(s);
    if (!val && err != CURLE_OK)
        return false;

    res = json_object_get(val, "result");
    if (json_is_object(res) && json_is_false(json_object_get(res, "isvalid"))) {
        applog(LOG_ERR, "The node says %s is not a valid address (wrong coin or network?)",
                opt_coinbase_addr);
        fatal_error = true;
        json_decref(val);
        return false;
    }
    spk = json_string_value(json_object_get(res, "scriptPubKey"));
    if (spk && strlen(spk) % 2 == 0 && strlen(spk) / 2 <= sizeof(pk_script)
            && hex2bin(pk_script, spk, strlen(spk) / 2))
        pk_script_size = strlen(spk) / 2;
    else {
        pk_script_size = address_to_script(pk_script, sizeof(pk_script),
                opt_coinbase_addr);
        if (!pk_script_size) {
            applog(LOG_ERR, "Invalid payout address %s", opt_coinbase_addr);
            fatal_error = true;
            json_decref(val);
            return false;
        }
        applog(LOG_WARNING, "The node did not say what %s pays to: decoded it "
                "here as a %s address, please check", opt_coinbase_addr,
                pk_script[0] == 0x76 ? "pay-to-pubkey-hash" :
                pk_script[0] == 0xa9 ? "pay-to-script-hash" : "segwit");
    }
    if (opt_debug) {
        char *hex = bin2hex(pk_script, pk_script_size);
        applog(LOG_DEBUG, "DEBUG: payout script %s", hex);
        free(hex);
    }
    json_decref(val);
    return true;
}

bool rpc2_login_decode(const json_t *val) {
    const char *id;
    const char *s;

    json_t *res = json_object_get(val, "result");
    if(!res) {
        applog(LOG_ERR, "JSON-RPC 2.0 login: no result");
        goto err_out;
    }

    json_t *tmp;
    tmp = json_object_get(res, "id");
    if(!tmp) {
        applog(LOG_ERR, "JSON-RPC 2.0 login: no session id");
        goto err_out;
    }
    id = json_string_value(tmp);
    if (!id || !*id || strlen(id) >= sizeof(rpc2_id)) {
        applog(LOG_ERR, "JSON-RPC 2.0 login: invalid session id");
        goto err_out;
    }

    pthread_mutex_lock(&rpc2_id_lock);
    strcpy(rpc2_id, id);
    pthread_mutex_unlock(&rpc2_id_lock);

    if(opt_debug)
        applog(LOG_DEBUG, "Auth id: %s", id);

    tmp = json_object_get(res, "status");
    if(!tmp) {
        applog(LOG_ERR, "JSON-RPC 2.0 login: no status");
        goto err_out;
    }
    s = json_string_value(tmp);
    if (!s) {
        applog(LOG_ERR, "JSON-RPC 2.0 login: status is not a string");
        goto err_out;
    }
    if(strcmp(s, "OK")) {
        applog(LOG_ERR, "JSON-RPC 2.0 login: status \"%s\"", s);
        return false;
    }

    return true;

    err_out: return false;
}

static void share_result(int result, struct work *work, const char *reason) {
    char s[345];
    double hashrate;
    int i;

    hashrate = 0.;
    pthread_mutex_lock(&stats_lock);
    for (i = 0; i < opt_n_threads; i++)
        hashrate += thr_hashrates[i];
    result ? accepted_count++ : rejected_count++;
    pthread_mutex_unlock(&stats_lock);

    switch (opt_algo) {
    case ALGO_CRYPTONIGHT:
    case ALGO_RANDOMX:
        applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %.2f H/s at diff %g %s",
                accepted_count, accepted_count + rejected_count,
                100. * accepted_count / (accepted_count + rejected_count), hashrate,
                rpc2_target_diff(work ? &work->target[6] : rpc2_target),
                result ? "(yay!!!)" : "(booooo)");
        break;
    default:
        sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
        applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %s khash/s %s",
                accepted_count, accepted_count + rejected_count,
                100. * accepted_count / (accepted_count + rejected_count), s,
                result ? "(yay!!!)" : "(booooo)");
        break;
    }

    if (opt_debug && reason)
        applog(LOG_DEBUG, "DEBUG: reject reason: %s", reason);
}

/* JSON-RPC 2.0 "submit" request for a share, with the hash the miner thread
 * found (caller frees) */
static char *rpc2_submit_req(const struct work *work)
{
    char *noncestr, *hashhex, *req = NULL, id[sizeof(rpc2_id)];
    json_t *obj;

    rpc2_get_id(id);
    noncestr = bin2hex((const unsigned char *) work->data + 39, 4);
    hashhex = bin2hex(work->result, 32);
    obj = json_pack("{s:s, s:{s:s, s:s, s:s, s:s}, s:i}",
            "method", "submit",
            "params",
                "id", id,
                "job_id", work->job_id ? work->job_id : "",
                "nonce", noncestr ? noncestr : "",
                "result", hashhex ? hashhex : "",
            "id", 1);
    if (obj)
        req = json_dumps(obj, 0);
    json_decref(obj);
    free(noncestr);
    free(hashhex);
    return req;
}

/* A share is stale once the block it builds on is no longer the tip. That
 * is the previous-block hash: words 1-8 of a block header, bytes 7-38 of a
 * CryptoNote blob (major version, minor version and a 5-byte timestamp come
 * first; the nonce follows at byte 39). Other job changes, such as a new
 * timestamp or new transactions, leave older shares valid.
 * The current one is kept apart from g_work, under its own lock: the workio
 * thread must never wait for g_work_lock, which a miner thread may hold
 * while it waits for the workio thread (getwork, getblocktemplate). */
static unsigned char cur_prev_block[32];
static pthread_mutex_t cur_prev_block_lock = PTHREAD_MUTEX_INITIALIZER;

static void prev_block_of(const struct work *w, unsigned char *out)
{
    if (jsonrpc_2)
        memcpy(out, (const unsigned char *) w->data + 7, 32);
    else
        memcpy(out, w->data + 1, 32);
}

/* call whenever g_work changes */
static void g_work_updated(void)
{
    pthread_mutex_lock(&cur_prev_block_lock);
    prev_block_of(&g_work, cur_prev_block);
    pthread_mutex_unlock(&cur_prev_block_lock);
}

static bool share_is_stale(const struct work *work)
{
    unsigned char prev[32];
    bool stale;

    prev_block_of(work, prev);
    pthread_mutex_lock(&cur_prev_block_lock);
    stale = memcmp(prev, cur_prev_block, 32) != 0;
    pthread_mutex_unlock(&cur_prev_block_lock);
    return stale;
}

/* serialize a request object and free it */
static char *json_request(json_t *req)
{
    char *s = req ? json_dumps(req, 0) : NULL;

    json_decref(req);
    return s;
}

/* JSON-RPC 2.0 "getjob" request (CryptoNight over HTTP), or NULL before
 * login */
static char *rpc2_getjob_req(void)
{
    char id[sizeof(rpc2_id)];

    rpc2_get_id(id);
    if (!*id)
        return NULL;
    return json_request(json_pack("{s:s, s:{s:s}, s:i}", "method", "getjob",
            "params", "id", id, "id", 1));
}

static bool submit_upstream_work(CURL *curl, struct work *work) {
    json_t *val, *res;
    char *req = NULL;
    int i;
    bool rc = false;

    /* pass if the previous hash is not the current previous hash */
    if (!submit_old && share_is_stale(work)) {
        if (opt_debug)
            applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
        return true;
    }

    if (have_stratum) {
        /* job ids only mean something on the connection they came from */
        if (work->conn_gen != stratum.conn_gen) {
            if (opt_debug)
                applog(LOG_DEBUG, "DEBUG: share for an earlier connection, discarding");
            return true;
        }
        if (jsonrpc_2)
            req = rpc2_submit_req(work);
        else {
            uint32_t ntime, nonce;
            char ntimestr[9], noncestr[9], *xnonce2str;

            le32enc(&ntime, work->data[17]);
            le32enc(&nonce, work->data[19]);
            bin2hex_buf(ntimestr, (const unsigned char *) &ntime, 4);
            bin2hex_buf(noncestr, (const unsigned char *) &nonce, 4);
            xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);
            /* built with jansson: user names and job ids get escaped */
            if (xnonce2str)
                req = json_request(json_pack("{s:s, s:[s, s, s, s, s], s:i}",
                        "method", "mining.submit",
                        "params", rpc_user, work->job_id ? work->job_id : "",
                                xnonce2str, ntimestr, noncestr,
                        "id", 4));
            free(xnonce2str);
        }
        if (unlikely(!req || !stratum_send_line(&stratum, req))) {
            applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
            goto out;
        }
    } else if (jsonrpc_2) {
        const char *status;

        req = rpc2_submit_req(work);
        if (!req)
            goto out;
        val = json_rpc2_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
        if (unlikely(!val)) {
            applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
            goto out;
        }
        res = json_object_get(val, "result");
        status = json_string_value(json_object_get(res, "status"));
        share_result(status && !strcmp(status, "OK"), work,
                json_string_value(json_object_get(res, "reject-reason")));
        json_decref(val);
    } else if (work->txs) {
        /* getblocktemplate: submit the block, header and transactions */
        size_t txs_len = work->txs->len;
        uint32_t header[20];
        const char *reason;
        json_t *params;
        char *block;

        for (i = 0; i < 20; i++)
            be32enc(&header[i], work->data[i]);
        block = malloc(160 + txs_len + 1);
        if (!block)
            goto out;
        bin2hex_buf(block, (const unsigned char *) header, 80);
        memcpy(block + 160, work->txs->hex, txs_len + 1);
        params = json_pack("[s]", block);
        free(block);
        if (params && work->workid)
            json_array_append_new(params, json_pack("{s:s}", "workid", work->workid));
        req = json_request(json_pack("{s:s, s:o, s:i}", "method", "submitblock",
                "params", params, "id", 1));
        if (!req)
            goto out;
        applog(LOG_INFO, "Found a block for height %" PRId64 ", submitting it",
                work->height);
        val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
        if (unlikely(!val)) {
            applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
            goto out;
        }
        /* BIP 22: null when accepted, else the reason ("inconclusive": the
         * node accepted it but could not check it fully yet) */
        res = json_object_get(val, "result");
        reason = json_string_value(res);
        share_result(json_is_null(res) || (reason && !strcmp(reason, "inconclusive")),
                work, reason);
        if (reason && strcmp(reason, "inconclusive"))
            applog(LOG_ERR, "Block rejected: %s", reason);
        json_decref(val);
    } else {
        /* getwork: all 128 bytes of the work, the nonce included */
        uint32_t data[32];
        char data_str[2 * sizeof(data) + 1];

        for (i = 0; i < 32; i++)
            le32enc(&data[i], work->data[i]);
        bin2hex_buf(data_str, (const unsigned char *) data, sizeof(data));
        req = json_request(json_pack("{s:s, s:[s], s:i}", "method", "getwork",
                "params", data_str, "id", 1));
        if (!req)
            goto out;
        val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
        if (unlikely(!val)) {
            applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
            goto out;
        }
        res = json_object_get(val, "result");
        share_result(json_is_true(res), work,
                json_string_value(json_object_get(val, "reject-reason")));
        json_decref(val);
    }

    rc = true;

out:
    free(req);
    return rc;
}

static const char *getwork_req =
        "{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work) {
    json_t *val;
    bool rc;
    struct timeval tv_start, tv_end, diff;
    int err = CURLE_OK;
    char *req = NULL;

start:
    if (!jsonrpc_2 && have_gbt && opt_coinbase_addr && !pk_script_size
            && !resolve_payout_script(curl))
        return false;

    gettimeofday(&tv_start, NULL );
    if (jsonrpc_2) {
        req = rpc2_getjob_req();
        if (!req)
            return false;
        val = json_rpc2_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
    } else if (have_gbt) {
        req = gbt_request(NULL);
        if (!req)
            return false;
        /* a server without getblocktemplate answers 404 */
        val = json_rpc_call(curl, rpc_url, rpc_userpass, req, &err,
                JSON_RPC_QUIET_404);
    } else
        val = json_rpc_call(curl, rpc_url, rpc_userpass, getwork_req, &err, 0);
    free(req);
    req = NULL;
    gettimeofday(&tv_end, NULL );

    if (have_stratum) {
        if (val)
            json_decref(val);
        return true;
    }

    if (!jsonrpc_2 && have_gbt && !val && err == CURLE_OK) {
        if (!allow_getwork) {
            applog(LOG_ERR, "The server does not support getblocktemplate");
            fatal_error = true;
            return false;
        }
        applog(LOG_INFO, "getblocktemplate not supported, falling back to getwork");
        have_gbt = false;
        goto start;
    }
    if (!val)
        return false;

    if (jsonrpc_2 || !have_gbt)
        rc = work_decode(json_object_get(val, "result"), work);
    else {
        bool named = gbt_name_algo;

        rc = gbt_work_decode(json_object_get(val, "result"), work);
        /* switched to getwork (no payout address), or to naming our
         * algorithm: ask again */
        if (!have_gbt || (!rc && !named && gbt_name_algo)) {
            json_decref(val);
            goto start;
        }
    }

    if (opt_debug && rc) {
        timeval_subtract(&diff, &tv_end, &tv_start);
        applog(LOG_DEBUG, "DEBUG: got new work in %ld ms",
                (long) (diff.tv_sec * 1000 + diff.tv_usec / 1000));
    }

    json_decref(val);

    return rc;
}

/* JSON-RPC 2.0 "login" request (caller frees): naming the algorithm lets a
 * pool or proxy that serves several send the right jobs */
char *rpc2_login_req(const char *user, const char *pass)
{
    return json_request(json_pack("{s:s, s:{s:s, s:s, s:s, s:[s]}, s:i}",
            "method", "login",
            "params", "login", user, "pass", pass, "agent", USER_AGENT,
                      "algo", rpc2_algo_name(),
            "id", 1));
}

static bool rpc2_login(CURL *curl) {
    json_t *val, *result;
    struct timeval tv_start, tv_end, diff;
    char *s;
    bool rc = false;

    if (!jsonrpc_2)
        return false;

    s = rpc2_login_req(rpc_user, rpc_pass);
    if (!s)
        return false;

    gettimeofday(&tv_start, NULL );
    val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
    gettimeofday(&tv_end, NULL );
    free(s);
    if (!val)
        return false;

    rc = rpc2_login_decode(val);
    result = json_object_get(val, "result");
    /* Cache the job that comes with the login reply; miner threads fetch it
     * through get_work(). Never touch g_work here: a miner thread may be
     * holding g_work_lock while it waits for this (workio) thread. */
    if (rc && json_object_get(result, "job"))
        rpc2_job_decode(json_object_get(result, "job"), NULL);

    if (opt_debug && rc) {
        timeval_subtract(&diff, &tv_end, &tv_start);
        applog(LOG_DEBUG, "DEBUG: authenticated in %ld ms",
                (long) (diff.tv_sec * 1000 + diff.tv_usec / 1000));
    }

    json_decref(val);
    return rc;
}

static void workio_cmd_free(struct workio_cmd *wc) {
    if (!wc)
        return;

    switch (wc->cmd) {
    case WC_SUBMIT_WORK:
        work_free(wc->u.work);
        free(wc->u.work);
        break;
    default: /* do nothing */
        break;
    }

    memset(wc, 0, sizeof(*wc)); /* poison */
    free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl) {
    struct work *ret_work;
    int failures = 0;

    ret_work = calloc(1, sizeof(*ret_work));
    if (!ret_work)
        return false;

    /* obtain new work from bitcoin via JSON-RPC */
    while (!get_upstream_work(curl, ret_work)) {
        if (fatal_error) {
            work_free(ret_work);
            free(ret_work);
            return false;
        }
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
            work_free(ret_work);
            free(ret_work);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "Getting work failed, retry after %d seconds",
                opt_fail_pause);
        sleep(opt_fail_pause);
    }

    /* send work to requesting thread */
    if (!tq_push(wc->thr->q, ret_work)) {
        work_free(ret_work);
        free(ret_work);
    }

    return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl) {
    int failures = 0;

    /* submit solution to bitcoin via JSON-RPC */
    while (!submit_upstream_work(curl, wc->u.work)) {
        /* Stratum job ids only mean something on the connection they
         * came from, and that connection is gone: drop the share rather
         * than stall every other share for a retry that cannot succeed. */
        if (have_stratum) {
            applog(LOG_ERR, "Share not sent: lost the connection to the pool");
            return true;
        }
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "...terminating workio thread");
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
    }

    return true;
}

static bool workio_login(CURL *curl) {
    int failures = 0;

    /* submit solution to bitcoin via JSON-RPC */
    pthread_mutex_lock(&rpc2_login_lock);
    while (!rpc2_login(curl)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "...terminating workio thread");
            pthread_mutex_unlock(&rpc2_login_lock);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
        pthread_mutex_unlock(&rpc2_login_lock);
        pthread_mutex_lock(&rpc2_login_lock);
    }
    pthread_mutex_unlock(&rpc2_login_lock);

    return true;
}

static void *workio_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    CURL *curl;
    bool ok = true;

    curl = curl_easy_init();
    if (unlikely(!curl)) {
        applog(LOG_ERR, "CURL initialization failed");
        return NULL ;
    }

    /* JSON-RPC 2.0 (CryptoNight) pools want a login first; nothing else
     * does (this used to loop forever in getwork mode and --benchmark) */
    if (jsonrpc_2 && !have_stratum && !opt_benchmark)
        ok = workio_login(curl);

    while (ok) {
        struct workio_cmd *wc;

        /* wait for workio_cmd sent to us, on our queue */
        wc = tq_pop(mythr->q, NULL );
        if (!wc) {
            ok = false;
            break;
        }

        /* process workio_cmd */
        switch (wc->cmd) {
        case WC_GET_WORK:
            ok = workio_get_work(wc, curl);
            break;
        case WC_SUBMIT_WORK:
            ok = workio_submit_work(wc, curl);
            pthread_mutex_lock(&stats_lock);
            pending_shares--;
            pthread_mutex_unlock(&stats_lock);
            break;

        default: /* should never happen */
            ok = false;
            break;
        }

        workio_cmd_free(wc);
    }

    tq_freeze(mythr->q);
    curl_easy_cleanup(curl);

    return NULL ;
}

static bool get_work(struct thr_info *thr, struct work *work) {
    struct workio_cmd *wc;
    struct work *work_heap;

    if (opt_benchmark) {
        memset(work->data, 0x55, 76);
        work->data[17] = swab32(time(NULL ));
        work->odo_key = odo_key((uint32_t) time(NULL), ODO_INTERVAL_MAINNET);
        memset(work->data + 19, 0x00, 52);
        work->data[20] = 0x80000000;
        work->data[31] = 0x00000280;
        memset(work->target, 0x00, sizeof(work->target));
        work->data_size = 76;
        return true;
    }

    /* fill out work request message */
    wc = calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->cmd = WC_GET_WORK;
    wc->thr = thr;

    /* send work request to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc)) {
        workio_cmd_free(wc);
        return false;
    }

    /* wait for response, a unit of work */
    work_heap = tq_pop(thr->q, NULL );
    if (!work_heap)
        return false;

    /* move returned work into storage provided by caller */
    work_free(work);
    memcpy(work, work_heap, sizeof(*work));
    free(work_heap);

    return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in) {
    static time_t last_warning;
    struct workio_cmd *wc;
    bool drop, warn = false;

    pthread_mutex_lock(&stats_lock);
    drop = pending_shares >= MAX_PENDING_SHARES;
    if (!drop)
        pending_shares++;
    else if (time(NULL) - last_warning >= 10) {
        time(&last_warning);
        warn = true;
    }
    pthread_mutex_unlock(&stats_lock);
    if (drop) {
        if (warn)
            applog(LOG_WARNING, "Too many shares waiting to be sent, dropping shares");
        return true;
    }

    /* fill out work request message */
    wc = calloc(1, sizeof(*wc));
    if (!wc)
        goto err_out;

    wc->u.work = malloc(sizeof(*work_in));
    if (!wc->u.work)
        goto err_out;

    wc->cmd = WC_SUBMIT_WORK;
    wc->thr = thr;
    work_copy(wc->u.work, work_in);

    /* send solution to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc))
        goto err_out;

    return true;

    err_out: workio_cmd_free(wc);
    pthread_mutex_lock(&stats_lock);
    pending_shares--;
    pthread_mutex_unlock(&stats_lock);
    return false;
}

/* Build the next piece of work from the current stratum job. Returns false,
 * leaving *work alone, when there is no job (not connected yet, or the
 * connection was lost). */
static bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work) {
    unsigned char merkle_root[64], *xnonce2;
    char *job_id;
    double diff;
    int i;

    pthread_mutex_lock(&sctx->work_lock);

    if (jsonrpc_2) {
        job_id = sctx->work.job_id ? strdup(sctx->work.job_id) : NULL;
        if (!job_id) {
            pthread_mutex_unlock(&sctx->work_lock);
            return false;
        }
        free(work->job_id);
        free(work->xnonce2);
        memcpy(work, &sctx->work, sizeof(struct work));
        work->job_id = job_id;
        work->xnonce2 = NULL;
        work->xnonce2_len = 0;
        work->conn_gen = sctx->conn_gen;
        pthread_mutex_unlock(&sctx->work_lock);
        return true;
    }

    job_id = sctx->job.job_id ? strdup(sctx->job.job_id) : NULL;
    xnonce2 = job_id ? malloc(sctx->xnonce2_size) : NULL;
    if (!xnonce2) {
        pthread_mutex_unlock(&sctx->work_lock);
        free(job_id);
        return false;
    }
    free(work->job_id);
    work->job_id = job_id;
    free(work->xnonce2);
    work->xnonce2 = xnonce2;
    work->xnonce2_len = sctx->xnonce2_size;
    work->conn_gen = sctx->conn_gen;
    memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

    /* generate merkle root */
    coinbase_txid(merkle_root, sctx->job.coinbase, sctx->job.coinbase_size);
    for (i = 0; i < sctx->job.merkle_count; i++) {
        memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
        sha256d(merkle_root, merkle_root, 64);
    }

    /* Increment extranonce2 */
    for (i = 0; i < sctx->xnonce2_size && !++sctx->job.xnonce2[i]; i++)
        ;

    /* Assemble block header */
    memset(work->data, 0, 128);
    work->data[0] = le32dec(sctx->job.version);
    for (i = 0; i < 8; i++)
        work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
    for (i = 0; i < 8; i++)
        work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);
    work->data[17] = le32dec(sctx->job.ntime);
    work->data[18] = le32dec(sctx->job.nbits);
    /* Odocrypt (DigiByte): the key comes from the block time; pools do not
     * say which network, so it is the main network's */
    work->odo_key = odo_key(swab32(work->data[17]), ODO_INTERVAL_MAINNET);
    work->data[20] = 0x80000000;
    work->data[31] = 0x00000280;
    diff = sctx->job.diff;

    pthread_mutex_unlock(&sctx->work_lock);

    if (opt_debug) {
        char *xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);
        applog(LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
                work->job_id, xnonce2str, swab32(work->data[17]));
        free(xnonce2str);
    }

    /* Pools express share difficulty relative to a per-algorithm
     * "difficulty 1" target */
    work->targetdiff = diff;
    switch (opt_algo) {
    case ALGO_SCRYPT:
    case ALGO_NEOSCRYPT:
    case ALGO_ARGON2D4096:
    case ALGO_ARGON2D500:
    case ALGO_ARGON2D250:
    case ALGO_ARGON2D16000:
    case ALGO_YESCRYPT:
    case ALGO_YESCRYPTR8:
    case ALGO_YESCRYPTR16:
    case ALGO_YESCRYPTR32:
    case ALGO_YESPOWER:
    case ALGO_YESPOWERR16:
        diff_to_target(work->target, diff / (65536.0 * opt_diff_factor));
        break;
    case ALGO_FRESH:
    case ALGO_VERTHASH:
        diff_to_target(work->target, diff / (256.0 * opt_diff_factor));
        break;
    case ALGO_KECCAK:
        diff_to_target(work->target, diff / (128.0 * opt_diff_factor));
        break;
    default:
        diff_to_target(work->target, diff / opt_diff_factor);
        break;
    }
    return true;
}

/* The nonce is data[19] of a block header, but 4 unaligned bytes at offset
 * 39 of a CryptoNight blob. */
static inline uint32_t work_nonce(const struct work *w)
{
    return jsonrpc_2 ? le32dec((const unsigned char *) w->data + 39) : w->data[19];
}

static inline void work_set_nonce(struct work *w, uint32_t nonce)
{
    if (jsonrpc_2)
        le32enc((unsigned char *) w->data + 39, nonce);
    else
        w->data[19] = nonce;
}

/*
 * A thread's share of a job's nonces, first to end: of a block header's,
 * all 32 bits; of a JSON-RPC 2.0 blob's, the low 24 bits, with the top byte
 * the job's own. NiceHash-style proxies (xmrig-proxy) give each miner its
 * own top byte; other pools leave it 0.
 */
static inline uint32_t nonce_base(const struct work *w)
{
    return jsonrpc_2 ? (uint32_t) ((const unsigned char *) w->data)[42] << 24 : 0;
}

static inline uint32_t nonce_span(void)
{
    return jsonrpc_2 ? 0x00ffffffU : 0xffffffffU;
}

static inline uint32_t nonce_first(const struct work *w, int thr_id)
{
    return nonce_base(w) | (nonce_span() / opt_n_threads * thr_id);
}

static inline uint32_t nonce_end(const struct work *w, int thr_id)
{
    return nonce_base(w) | (nonce_span() / opt_n_threads * (thr_id + 1) - 0x20);
}

/* true if a and b are different jobs (their nonces are ignored, but for
 * a JSON-RPC 2.0 job's top nonce byte, which is the pool's) */
static bool work_differs(const struct work *a, const struct work *b)
{
    const unsigned char *x = (const unsigned char *) a->data;
    const unsigned char *y = (const unsigned char *) b->data;

    if (!jsonrpc_2)
        return memcmp(x, y, 76) != 0;
    if (a->data_size != b->data_size || a->data_size < RPC2_MIN_BLOB
            || memcmp(a->seed_hash, b->seed_hash, sizeof(a->seed_hash)))
        return true;
    return memcmp(x, y, 39) || memcmp(x + 42, y + 42, a->data_size - 42);
}

static void work_sync_job(struct work *w, const struct work *g)
{
    memcpy(w->target, g->target, sizeof(w->target));
    w->targetdiff = g->targetdiff;
    if (g->job_id && (!w->job_id || strcmp(w->job_id, g->job_id))) {
        char *id = strdup(g->job_id);
        if (id) {
            free(w->job_id);
            w->job_id = id;
        }
    }
}

static void *miner_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    int thr_id = mythr->id;
    struct work work = { { 0 } };
    uint32_t max_nonce;
    unsigned char *scratchbuf = NULL;
    char s[16];
    int i;

    /* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
     * and if that fails, then SCHED_BATCH. No need for this to be an
     * error if it fails */
    if (!opt_benchmark) {
        setpriority(PRIO_PROCESS, 0, 19);
        drop_policy();
    }

    /* Cpu affinity only makes sense if the number of threads is a multiple
     * of the number of CPUs */
    if (num_processors > 1 && opt_n_threads % num_processors == 0) {
        if (!opt_quiet)
            applog(LOG_INFO, "Binding thread %d to cpu %d", thr_id,
                    thr_id % num_processors);
        affine_to_cpu(thr_id, thr_id % num_processors);
    }

    if (opt_algo == ALGO_SCRYPT) {
        scratchbuf = scrypt_buffer_alloc(opt_scrypt_n);
        if (!scratchbuf) {
            applog(LOG_ERR, "scrypt buffer allocation failed");
            pthread_mutex_lock(&applog_lock);
            exit(1);
        }
    }
    while (1) {
        uint64_t hashes_done;
        struct timeval tv_start, tv_end, diff;
        int64_t max64;
        time_t work_time;
        int rc;

        if (have_stratum) {
            /* wait for a job: while (re)connecting g_work_time is 0, and a
             * Bitcoin-style job older than 2 minutes is considered stale
             * (CryptoNight pools can go much longer between jobs) */
            pthread_mutex_lock(&g_work_lock);
            while (time(NULL) >= g_work_time + 120
                    && (!jsonrpc_2 || !g_work_time)) {
                pthread_mutex_unlock(&g_work_lock);
                sleep(1);
                pthread_mutex_lock(&g_work_lock);
            }
            if (work_nonce(&work) >= nonce_end(&work, thr_id)
                    && !work_differs(&work, &g_work)) {
                if (!stratum_gen_work(&stratum, &g_work)) {
                    /* nonce range used up and the connection just dropped */
                    pthread_mutex_unlock(&g_work_lock);
                    sleep(1);
                    continue;
                }
                g_work_updated();
            }
        } else {
            int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;

            /* obtain new work from internal workio thread: when the shared
             * work is getting old, or this thread has used up its nonces
             * (it used to ask on every pass of every thread without long
             * polling: a block template request per thread every few
             * seconds) */
            pthread_mutex_lock(&g_work_lock);
            if (time(NULL) - g_work_time >= min_scantime
                    || work_nonce(&work) >= nonce_end(&work, thr_id)) {
                if (unlikely(!get_work(mythr, &g_work))) {
                    applog(LOG_ERR, "work retrieval failed, exiting "
                            "mining thread %d", mythr->id);
                    pthread_mutex_unlock(&g_work_lock);
                    goto out;
                }
                g_work_updated();
                g_work_time = have_stratum ? 0 : time(NULL );
            }
            if (have_stratum) {
                pthread_mutex_unlock(&g_work_lock);
                continue;
            }
        }
        /* Clear the restart flag while holding g_work_lock, before looking
         * at g_work: clearing it afterwards could erase a restart for a job
         * that arrived in between, and the thread would keep hashing the
         * old job for up to LP_SCANTIME seconds. */
        work_restart[thr_id].restart = 0;
        if (work_differs(&work, &g_work)) {
            work_free(&work);
            work_copy(&work, &g_work);
            work_set_nonce(&work, nonce_first(&work, thr_id));
        } else {
            /* same header: carry on from the last nonce, but under the
             * current job id and share target (a pool may re-send a job
             * with a new id or difficulty and an identical header) */
            work_sync_job(&work, &g_work);
            work_set_nonce(&work, work_nonce(&work) + 1);
        }
        work_time = g_work_time;
        pthread_mutex_unlock(&g_work_lock);

        if (jsonrpc_2 && work.data_size < RPC2_MIN_BLOB) {
            /* no JSON-RPC 2.0 job yet */
            sleep(1);
            continue;
        }
        if (jsonrpc_2 && work_nonce(&work) > nonce_end(&work, thr_id)) {
            /* all this thread's nonces of the job are hashed, and a
             * JSON-RPC 2.0 job has nothing else to vary: wait for another
             * (going on would take other threads' nonces, or another
             * miner's top byte) */
            work_set_nonce(&work, nonce_end(&work, thr_id));
            sleep(1);
            continue;
        }

        /* adjust max_nonce to meet target scan time */
        if (have_stratum)
            max64 = LP_SCANTIME;
        else
            max64 = work_time + (have_longpoll ? LP_SCANTIME : opt_scantime)
                    - time(NULL );
        max64 *= thr_hashrates[thr_id];
        if (max64 <= 0) {
            switch (opt_algo) {
            case ALGO_SCRYPT:
                max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
                break;
            case ALGO_CRYPTONIGHT:
            case ALGO_RANDOMX:
                max64 = 0x40LL;
                break;
            case ALGO_VERTHASH:
                max64 = 0x1fff;
                break;
            case ALGO_NEOSCRYPT:
                max64 = 0x3fff;
                break;
            case ALGO_ARGON2D4096:
            case ALGO_ARGON2D500:
            case ALGO_ARGON2D250:
            case ALGO_ARGON2D16000:
            case ALGO_YESCRYPT:
            case ALGO_YESCRYPTR8:
            case ALGO_YESCRYPTR16:
            case ALGO_YESCRYPTR32:
            case ALGO_YESPOWER:
            case ALGO_YESPOWERR16:
                max64 = 0x3ff;
                break;
            case ALGO_FRESH:
            case ALGO_QUARK:
            case ALGO_X11:
            case ALGO_QUBIT:
            case ALGO_ODO:
                max64 = 0x3ffff;
                break;
            case ALGO_X13:
                max64 = 0x1ffff;
                break;
            case ALGO_X14:
                max64 = 0x3ffff;
                break;
            case ALGO_X15:
                max64 = 0x1ffff;
                break;
            default:
                max64 = 0x1fffffLL;
                break;
            }
        }
        if (work_nonce(&work) + max64 > nonce_end(&work, thr_id))
            max_nonce = nonce_end(&work, thr_id);
        else
            max_nonce = work_nonce(&work) + max64;

        hashes_done = 0;
        gettimeofday(&tv_start, NULL );

        /* scan nonces for a proof-of-work hash */
        switch (opt_algo) {
        case ALGO_SCRYPT:
            rc = scanhash_scrypt(thr_id, work.data, scratchbuf, work.target,
                    max_nonce, &hashes_done, opt_scrypt_n);
            break;

        case ALGO_SHA256D:
            rc = scanhash_sha256d(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;

        case ALGO_KECCAK:
            rc = scanhash_keccak(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;

        case ALGO_QUARK:
            rc = scanhash_quark(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;

        case ALGO_SKEIN:
            rc = scanhash_skein(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_SHAVITE3:
            rc = scanhash_ink(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_BLAKE:
            rc = scanhash_blake(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_FRESH:
            rc = scanhash_fresh(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_VERTHASH:
            rc = scanhash_verthash(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_X11:
            rc = scanhash_x11(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_X13:
            rc = scanhash_x13(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_X14:
            rc = scanhash_x14(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_X15:
            rc = scanhash_x15(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_QUBIT:
            rc = scanhash_qubit(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_ODO:
            rc = scanhash_odo(thr_id, work.data, work.target, work.odo_key,
                    max_nonce, &hashes_done);
            break;
        case ALGO_NEOSCRYPT:
            rc = scanhash_neoscrypt(thr_id, work.data, work.target, max_nonce,
                    &hashes_done);
            break;
        case ALGO_ARGON2D4096:
        case ALGO_ARGON2D500:
        case ALGO_ARGON2D250:
        case ALGO_ARGON2D16000:
            rc = scanhash_argon2d(thr_id, work.data, work.target,
                    ARGON2D_4096 + (opt_algo - ALGO_ARGON2D4096),
                    max_nonce, &hashes_done);
            break;
        case ALGO_YESCRYPT:
        case ALGO_YESCRYPTR8:
        case ALGO_YESCRYPTR16:
        case ALGO_YESCRYPTR32:
        case ALGO_YESPOWER:
        case ALGO_YESPOWERR16:
            rc = scanhash_yespower(thr_id, work.data, work.target,
                    YESCRYPT + (opt_algo - ALGO_YESCRYPT),
                    max_nonce, &hashes_done);
            break;
        case ALGO_CRYPTONIGHT:
            rc = scanhash_cryptonight(thr_id, work.data, work.data_size,
                    work.target, max_nonce, &hashes_done, work.result);
            break;
        case ALGO_RANDOMX:
            rc = scanhash_randomx(thr_id, work.data, work.data_size,
                    work.seed_hash, work.target, max_nonce, &hashes_done,
                    work.result);
            break;

        default:
            /* should never happen */
            goto out;
        }

        /* record scanhash elapsed time */
        gettimeofday(&tv_end, NULL);
        timeval_subtract(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec) {
            pthread_mutex_lock(&stats_lock);
            thr_hashrates[thr_id] = 
                hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
            pthread_mutex_unlock(&stats_lock);
        }
        /* (no hashes: a RandomX thread that waited for the dataset) */
        if (!opt_quiet && hashes_done) {
            switch(opt_algo) {
            case ALGO_CRYPTONIGHT:
            case ALGO_RANDOMX:
                applog(LOG_INFO, "thread %d: %" PRIu64 " hashes, %.2f H/s",
                        thr_id, hashes_done, thr_hashrates[thr_id]);
                break;
            default:
                sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
                        thr_hashrates[thr_id] / 1e3);
                applog(LOG_INFO, "thread %d: %" PRIu64 " hashes, %s khash/s",
                        thr_id, hashes_done, s);
                break;
            }
        }
        if (opt_benchmark && thr_id == opt_n_threads - 1) {
            double hashrate = 0.;
            pthread_mutex_lock(&stats_lock);
            for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
                hashrate += thr_hashrates[i];
            pthread_mutex_unlock(&stats_lock);
            if (i == opt_n_threads) {
                switch(opt_algo) {
                case ALGO_CRYPTONIGHT:
                case ALGO_RANDOMX:
                    applog(LOG_INFO, "Total: %.2f H/s", hashrate);
                    break;
                default:
                    sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", hashrate / 1000);
                    applog(LOG_INFO, "Total: %s khash/s", s);
                    break;
                }
            }
        }

        /* if nonce found, submit work */
        if (rc && !opt_benchmark && !submit_work(mythr, &work))
            break;
    }

    out: tq_freeze(mythr->q);

    return NULL ;
}

static void restart_threads(void) {
    int i;

    for (i = 0; i < opt_n_threads; i++)
        work_restart[i].restart = 1;
}

/* true if new work changes what the miner threads should be doing */
static bool work_changed(const struct work *a, const struct work *b)
{
    if (!a->job_id != !b->job_id || (a->job_id && strcmp(a->job_id, b->job_id)))
        return true;
    if (jsonrpc_2 && memcmp(a->seed_hash, b->seed_hash, sizeof(a->seed_hash)))
        return true;
    return memcmp(a->data, b->data, jsonrpc_2 ? sizeof(a->data) : 76) != 0;
}

static void *longpoll_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    CURL *curl = NULL;
    char *copy_start, *hdr_path = NULL, *lp_url = NULL;
    bool need_slash = false;

    curl = curl_easy_init();
    if (unlikely(!curl)) {
        applog(LOG_ERR, "CURL initialization failed");
        goto out;
    }

    start: hdr_path = tq_pop(mythr->q, NULL );
    if (!hdr_path)
        goto out;

    /* full URL */
    if (strstr(hdr_path, "://")) {
        lp_url = hdr_path;
        hdr_path = NULL;
    }

    /* absolute path, on current server */
    else {
        copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
        need_slash = rpc_url[strlen(rpc_url) - 1] != '/';

        lp_url = malloc(strlen(rpc_url) + strlen(copy_start) + 2);
        if (!lp_url)
            goto out;

        sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
    }

    applog(LOG_INFO, "Long-polling activated for %s", lp_url);

    while (1) {
        struct work work = { { 0 } };
        json_t *val, *res;
        char *req = NULL;
        int err = CURLE_OK;
        bool rc;

        /* the requests go to the long polling URL (they used to go to
         * the main URL, which answers at once: a busy loop) */
        if (jsonrpc_2) {
            req = rpc2_getjob_req();
            if (!req) {	/* not logged in yet */
                sleep(1);
                continue;
            }
            val = json_rpc2_call(curl, lp_url, rpc_userpass, req, &err,
                    JSON_RPC_LONGPOLL);
        } else if (have_gbt) {
            pthread_mutex_lock(&lp_id_lock);
            req = gbt_request(lp_id);
            pthread_mutex_unlock(&lp_id_lock);
            if (!req) {
                sleep(1);
                continue;
            }
            val = json_rpc_call(curl, lp_url, rpc_userpass, req, &err,
                    JSON_RPC_LONGPOLL);
        } else
            val = json_rpc_call(curl, lp_url, rpc_userpass, getwork_req, &err,
                    JSON_RPC_LONGPOLL);
        free(req);
        if (have_stratum) {
            if (val)
                json_decref(val);
            goto out;
        }
        if (likely(val)) {
            res = json_object_get(val, "result");
            if (!jsonrpc_2)
                submit_old = json_is_true(json_object_get(res, "submitold"));
            /* decode into a scratch copy: g_work stays intact on errors */
            pthread_mutex_lock(&g_work_lock);
            if (!jsonrpc_2 && have_gbt)
                rc = gbt_work_decode(res, &work);
            else
                rc = work_decode(res, &work);
            if (rc && work_changed(&work, &g_work)) {
                work_free(&g_work);
                memcpy(&g_work, &work, sizeof(work));
                memset(&work, 0, sizeof(work));
                g_work_updated();
                time(&g_work_time);
                applog(LOG_INFO, "LONGPOLL pushed new work");
                restart_threads();
            }
            pthread_mutex_unlock(&g_work_lock);
            work_free(&work);
            json_decref(val);
        } else {
            pthread_mutex_lock(&g_work_lock);
            g_work_time -= LP_SCANTIME;
            pthread_mutex_unlock(&g_work_lock);
            if (err == CURLE_OPERATION_TIMEDOUT) {
                restart_threads();
            } else {
                have_longpoll = false;
                restart_threads();
                free(hdr_path);
                free(lp_url);
                hdr_path = NULL;
                lp_url = NULL;
                sleep(opt_fail_pause);
                goto start;
            }
        }
    }

    out: free(hdr_path);
    free(lp_url);
    tq_freeze(mythr->q);
    if (curl)
        curl_easy_cleanup(curl);

    return NULL ;
}

static bool stratum_handle_response(char *buf) {
    json_t *val, *err_val, *res_val, *id_val;
    const char *reason;
    json_error_t err;
    bool ret = false;
    bool valid = false;

    val = JSON_LOADS(buf, &err);
    if (!val) {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    id_val = json_object_get(val, "id");

    if (!id_val || json_is_null(id_val) || (jsonrpc_2 ? (!res_val && !err_val) : !res_val))
        goto out;
    /* the answer to a keep-alive, not to a share */
    if (jsonrpc_2 && json_integer_value(id_val) == RPC2_KEEPALIVE_ID) {
        ret = true;
        goto out;
    }

    if(jsonrpc_2) {
        json_t *status = json_object_get(res_val, "status");
        bool no_error = !err_val || json_is_null(err_val);
        if (status) {
            const char *s = json_string_value(status);
            valid = s && !strcmp(s, "OK") && no_error;
        } else {
            valid = no_error;
        }
    } else {
        valid = json_is_true(res_val);
    }

    reason = NULL;
    if (err_val && !json_is_null(err_val)) {
        if (jsonrpc_2)
            reason = json_string_value(json_is_string(err_val) ? err_val
                    : json_object_get(err_val, "message"));
        else
            reason = json_string_value(json_array_get(err_val, 1));
    }
    share_result(valid, NULL, reason);

    ret = true;
    out: if (val)
        json_decref(val);

    return ret;
}

/* JSON-RPC 2.0 pools send nothing between jobs, which can be minutes apart
 * (a new Monero block every 2 minutes on average), and some drop miners
 * they have not heard from: after a minute of silence, say we are still
 * here */
static bool rpc2_keepalive(void)
{
    char id[sizeof(rpc2_id)], *req;
    bool ok;

    rpc2_get_id(id);
    req = json_request(json_pack("{s:s, s:{s:s}, s:i}", "method", "keepalived",
            "params", "id", id, "id", RPC2_KEEPALIVE_ID));
    ok = req && stratum_send_line(&stratum, req);
    free(req);
    return ok;
}

static void *stratum_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    int silent = 0;	/* JSON-RPC 2.0: minutes without a word from the pool */
    char *s;

    stratum.url = tq_pop(mythr->q, NULL );
    if (!stratum.url)
        goto out;
    applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

    while (1) {
        int failures = 0;

        while (!stratum.curl) {
            silent = 0;
            pthread_mutex_lock(&g_work_lock);
            g_work_time = 0;
            pthread_mutex_unlock(&g_work_lock);
            restart_threads();

            if (!stratum_connect(&stratum, stratum.url)
                    || !stratum_subscribe(&stratum)
                    || !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
                stratum_disconnect(&stratum);
                if (opt_retries >= 0 && ++failures > opt_retries) {
                    applog(LOG_ERR, "...terminating workio thread");
                    tq_push(thr_info[work_thr_id].q, NULL );
                    goto out;
                }
                applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
                sleep(opt_fail_pause);
            }
        }

        /* This thread is the only one that changes stratum.job and
         * stratum.work, so it may read them without stratum.work_lock;
         * g_work is shared with the miner threads. */
        if (jsonrpc_2 ? stratum.work.job_id != NULL : stratum.job.job_id != NULL) {
            bool new_job;

            pthread_mutex_lock(&g_work_lock);
            if (jsonrpc_2)
                new_job = !g_work_time || !g_work.job_id
                        || strcmp(stratum.work.job_id, g_work.job_id);
            else
                new_job = !g_work_time || !g_work.job_id
                        || strcmp(stratum.job.job_id, g_work.job_id)
                        || stratum.job.diff != g_work.targetdiff;
            if (new_job && stratum_gen_work(&stratum, &g_work)) {
                g_work_updated();
                time(&g_work_time);
            } else
                new_job = false;
            pthread_mutex_unlock(&g_work_lock);
            if (new_job && (jsonrpc_2 || stratum.job.clean)) {
                applog(LOG_INFO, "Stratum detected new block");
                restart_threads();
            }
        }

        if (!stratum_socket_full(&stratum, jsonrpc_2 ? 60 : 120)) {
            /* JSON-RPC 2.0: give up after 5 silent minutes */
            if (jsonrpc_2 && ++silent < 5 && rpc2_keepalive())
                continue;
            applog(LOG_ERR, "Stratum connection timed out");
            s = NULL;
        } else
            s = stratum_recv_line(&stratum);
        if (!s) {
            stratum_disconnect(&stratum);
            applog(LOG_ERR, "Stratum connection interrupted");
            continue;
        }
        silent = 0;
        if (!stratum_handle_method(&stratum, s))
            stratum_handle_response(s);
        free(s);
    }

    out: return NULL ;
}

static void show_version_and_exit(void) {
    printf(PACKAGE_STRING "\n built on " __DATE__ "\n features:"
#if defined(USE_ASM) && defined(__i386__)
            " i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
            " x86_64"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
            " SSE2"
#endif
#if (defined(__x86_64__) || defined(__i386__)) && \
    (defined(__GNUC__) || defined(__clang__))
            " AES-NI"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
            " AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
            " AVX2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
            " XOP"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
            " ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
            " ARMv5E"
#endif
#if defined(__ARM_NEON__)
            " NEON"
#endif
#endif
            "\n");

    printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
    printf("libjansson %s\n", JANSSON_VERSION);
#endif
    exit(0);
}

static void show_usage_and_exit(int status) {
    if (status)
        fprintf(stderr,
                "Try `" PROGRAM_NAME " --help' for more information.\n");
    else
        printf(usage);
    exit(status);
}

static void parse_arg(int key, char *arg) {
    char *p;
    int v, i;

    switch (key) {
    case 'a':
        for (i = 0; i < ARRAY_SIZE(algo_names); i++) {
            v = strlen(algo_names[i]);
            if (!strncmp(arg, algo_names[i], v)) {
                if (arg[v] == '\0') {
                    opt_algo = i;
                    break;
                }
                if (arg[v] == ':' && i == ALGO_SCRYPT) {
                    char *ep;
                    v = strtol(arg+v+1, &ep, 10);
                    if (*ep || v & (v-1) || v < 2)
                        continue;
                    opt_algo = i;
                    opt_scrypt_n = v;
                    break;
                }
            }
        }
        /* other names */
        if (i == ARRAY_SIZE(algo_names) && !strcmp(arg, "odocrypt"))
            opt_algo = i = ALGO_ODO;
        if (i == ARRAY_SIZE(algo_names) && (!strcmp(arg, "rx/0") || !strcmp(arg, "rx")))
            opt_algo = i = ALGO_RANDOMX;
        if (i == ARRAY_SIZE(algo_names))
            show_usage_and_exit(1);
        break;
    case 'B':
        opt_background = true;
        break;
    case 'c': {
        json_error_t err;
        if (opt_config)
            json_decref(opt_config);
        opt_config = json_load_file(arg, 0, &err);
        if (!json_is_object(opt_config)) {
            applog(LOG_ERR, "JSON decode of %s failed", arg);
            exit(1);
        }
        break;
    }
    case 'q':
        opt_quiet = true;
        break;
    case 'D':
        opt_debug = true;
        break;
    case 'f': {
        char *ep;
        double d = strtod(arg, &ep);
        if (*ep || !(d > 0.0) || d > 1e9)
            show_usage_and_exit(1);
        opt_diff_factor = d;
        break;
    }
    case 'p':
        free(rpc_pass);
        rpc_pass = strdup(arg);
        break;
    case 'P':
        opt_protocol = true;
        break;
    case 'r':
        v = atoi(arg);
        if (v < -1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_retries = v;
        break;
    case 'R':
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_fail_pause = v;
        break;
    case 's':
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_scantime = v;
        break;
    case 'T':
        v = atoi(arg);
        if (v < 1 || v > 99999) /* sanity check */
            show_usage_and_exit(1);
        opt_timeout = v;
        break;
    case 't':
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_n_threads = v;
        break;
    case 'u':
        free(rpc_user);
        rpc_user = strdup(arg);
        break;
    case 'o': /* --url */
        p = strstr(arg, "://");
        if (p) {
            if (strncasecmp(arg, "http://", 7)
                    && strncasecmp(arg, "https://", 8)
                    && strncasecmp(arg, "stratum+tcp://", 14))
                show_usage_and_exit(1);
            free(rpc_url);
            rpc_url = strdup(arg);
        } else {
            if (!strlen(arg) || *arg == '/')
                show_usage_and_exit(1);
            free(rpc_url);
            rpc_url = malloc(strlen(arg) + 8);
            sprintf(rpc_url, "http://%s", arg);
        }
        p = strrchr(rpc_url, '@');
        if (p) {
            char *sp, *ap;
            *p = '\0';
            ap = strstr(rpc_url, "://") + 3;
            sp = strchr(ap, ':');
            if (sp) {
                free(rpc_userpass);
                rpc_userpass = strdup(ap);
                free(rpc_user);
                rpc_user = calloc(sp - ap + 1, 1);
                strncpy(rpc_user, ap, sp - ap);
                free(rpc_pass);
                rpc_pass = strdup(sp + 1);
            } else {
                free(rpc_user);
                rpc_user = strdup(ap);
            }
            memmove(ap, p + 1, strlen(p + 1) + 1);
        }
        have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
        break;
    case 'O': /* --userpass */
        p = strchr(arg, ':');
        if (!p)
            show_usage_and_exit(1);
        free(rpc_userpass);
        rpc_userpass = strdup(arg);
        free(rpc_user);
        rpc_user = calloc(p - arg + 1, 1);
        strncpy(rpc_user, arg, p - arg);
        free(rpc_pass);
        rpc_pass = strdup(p + 1);
        break;
    case 'x': /* --proxy */
        if (!strncasecmp(arg, "socks4://", 9))
            opt_proxy_type = CURLPROXY_SOCKS4;
        else if (!strncasecmp(arg, "socks5://", 9))
            opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
        else if (!strncasecmp(arg, "socks4a://", 10))
            opt_proxy_type = CURLPROXY_SOCKS4A;
        else if (!strncasecmp(arg, "socks5h://", 10))
            opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
        else
            opt_proxy_type = CURLPROXY_HTTP;
        free(opt_proxy);
        opt_proxy = strdup(arg);
        break;
    case 1001:
        free(opt_cert);
        opt_cert = strdup(arg);
        break;
    case 1005:
        opt_benchmark = true;
        want_longpoll = false;
        want_stratum = false;
        have_stratum = false;
        break;
    case 1003:
        want_longpoll = false;
        break;
    case 1007:
        want_stratum = false;
        break;
    case 1009:
        opt_redirect = false;
        break;
    case 1010:
        allow_getwork = false;
        break;
    case 1011:
        have_gbt = false;
        break;
    case 1013:
        /* checked against the node once connected (validateaddress) */
        if (!*arg)
            show_usage_and_exit(1);
        free(opt_coinbase_addr);
        opt_coinbase_addr = strdup(arg);
        break;
    case 1015:
        if (strlen(arg) + 1 > sizeof(coinbase_sig)) {
            fprintf(stderr, "coinbase signature too long\n");
            show_usage_and_exit(1);
        }
        strcpy(coinbase_sig, arg);
        break;
    case 1016:
    case 1017: {
        /* checked against the algorithm once all options are read */
        char *ep;
        unsigned long n = strtoul(arg, &ep, 10);

        if (!*arg || *ep || n == 0 || n > 0x7fffffff)
            show_usage_and_exit(1);
        if (key == 1016)
            opt_param_n = (uint32_t) n;
        else
            opt_param_r = (uint32_t) n;
        break;
    }
    case 1018:
        free(opt_param_key);
        opt_param_key = strdup(arg);
        break;
    case 1020:
        free(opt_verthash_data);
        opt_verthash_data = strdup(arg);
        break;
    case 1019:
        if (!strcmp(arg, "auto"))
            opt_randomx_mode = RX_MODE_AUTO;
        else if (!strcmp(arg, "fast"))
            opt_randomx_mode = RX_MODE_FAST;
        else if (!strcmp(arg, "light"))
            opt_randomx_mode = RX_MODE_LIGHT;
        else
            show_usage_and_exit(1);
        break;
    case 'S':
        use_syslog = true;
        break;
    case 'V':
        show_version_and_exit();
    case 'h':
        show_usage_and_exit(0);
    default:
        show_usage_and_exit(1);
    }
}

static void parse_config(void) {
    int i;
    json_t *val;

    if (!json_is_object(opt_config))
        return;

    for (i = 0; i < ARRAY_SIZE(options); i++) {
        if (!options[i].name)
            break;
        if (!strcmp(options[i].name, "config"))
            continue;

        val = json_object_get(opt_config, options[i].name);
        if (!val)
            continue;

        if (options[i].has_arg && json_is_string(val)) {
            char *s = strdup(json_string_value(val));
            if (!s)
                break;
            parse_arg(options[i].val, s);
            free(s);
        } else if (!options[i].has_arg && json_is_true(val))
            parse_arg(options[i].val, "");
        else
            applog(LOG_ERR, "JSON option %s invalid", options[i].name);
    }
}

static void parse_cmdline(int argc, char *argv[]) {
    int key;

    while (1) {
#if HAVE_GETOPT_LONG
        key = getopt_long(argc, argv, short_options, options, NULL );
#else
        key = getopt(argc, argv, short_options);
#endif
        if (key < 0)
            break;

        parse_arg(key, optarg);
    }
    if (optind < argc) {
        fprintf(stderr, "%s: unsupported non-option argument '%s'\n", argv[0],
                argv[optind]);
        show_usage_and_exit(1);
    }

    parse_config();
}

#ifndef _WIN32
/*
 * Signals are blocked in every thread and taken here with sigwait(), in an
 * ordinary thread: the old signal handler called applog() (which takes a
 * mutex) and exit(), neither of which may be used in a signal handler; a
 * signal arriving while a thread held the log lock deadlocked the miner.
 */
static sigset_t handled_signals;

static void *signal_thread(void *userdata) {
    int sig;

    (void) userdata;
    for (;;) {
        if (sigwait(&handled_signals, &sig))
            continue;
        switch (sig) {
        case SIGHUP:
            applog(LOG_INFO, "SIGHUP received");
            break;
        case SIGINT:
            applog(LOG_INFO, "SIGINT received, exiting");
            exit(0);
        case SIGTERM:
            applog(LOG_INFO, "SIGTERM received, exiting");
            exit(0);
        }
    }
    return NULL;
}

/* Call before starting any other thread, so that they all inherit the
 * blocked signal mask. */
static void start_signal_thread(void) {
    pthread_t pth;

    sigemptyset(&handled_signals);
    sigaddset(&handled_signals, SIGINT);
    sigaddset(&handled_signals, SIGTERM);
    /* a daemon survives its terminal closing; in the foreground SIGHUP
     * keeps its default action */
    if (opt_background)
        sigaddset(&handled_signals, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &handled_signals, NULL);
    if (pthread_create(&pth, NULL, signal_thread, NULL)) {
        applog(LOG_ERR, "signal thread create failed");
        pthread_sigmask(SIG_UNBLOCK, &handled_signals, NULL);
    }
}
#endif

int main(int argc, char *argv[]) {
	struct thr_info *thr;
	long flags;
	int i;

#ifndef _WIN32
	/* Writing to a connection the pool has closed must fail with EPIPE,
	 * which the network code handles, instead of killing the miner. */
	signal(SIGPIPE, SIG_IGN);
#endif

	rpc_user = strdup("");
	rpc_pass = strdup("");

	/* parse command line */
	parse_cmdline(argc, argv);

	if (opt_algo == ALGO_QUARK) {
		init_quarkhash_contexts();
	} else if (opt_algo == ALGO_BLAKE) {
		init_blakehash_contexts();
	} else if(opt_algo == ALGO_CRYPTONIGHT) {
		jsonrpc_2 = true;
		aes_ni_supported = cryptonight_cpu_has_aesni();
		applog(LOG_INFO, "Using JSON-RPC 2.0");
		applog(LOG_INFO, "AES-NI: %s", aes_ni_supported ? "yes" : "no (using portable AES)");
	} else if (opt_algo == ALGO_RANDOMX) {
		jsonrpc_2 = true;
		applog(LOG_INFO, "Using JSON-RPC 2.0");
	} else if (opt_algo == ALGO_NEOSCRYPT) {
		applog(LOG_INFO, "NeoScrypt: using %s", neoscrypt_impl_name());
	} else if (opt_algo >= ALGO_ARGON2D4096 && opt_algo <= ALGO_ARGON2D16000) {
		applog(LOG_INFO, "Argon2d: using %s", argon2d_impl_name());
	}

	/* yescrypt and yespower parameters */
	if (opt_param_n || opt_param_r || opt_param_key) {
		if (opt_algo < ALGO_YESCRYPT || opt_algo > ALGO_YESPOWERR16) {
			fprintf(stderr, "%s: --param-n, --param-r and --param-key are for "
				"yescrypt and yespower\n", argv[0]);
			show_usage_and_exit(1);
		}
		if (!yespower_set_params(YESCRYPT + (opt_algo - ALGO_YESCRYPT),
				opt_param_n, opt_param_r, opt_param_key)) {
			fprintf(stderr, "%s: N must be a power of 2 from 1024 to 524288, "
				"r from 8 to 32\n", argv[0]);
			show_usage_and_exit(1);
		}
	}
	if (opt_randomx_mode != RX_MODE_AUTO && opt_algo != ALGO_RANDOMX) {
		fprintf(stderr, "%s: --randomx-mode is for randomx\n", argv[0]);
		show_usage_and_exit(1);
	}
	if (opt_verthash_data && opt_algo != ALGO_VERTHASH) {
		fprintf(stderr, "%s: --verthash-data is for verthash\n", argv[0]);
		show_usage_and_exit(1);
	}
	if (opt_algo >= ALGO_YESCRYPT && opt_algo <= ALGO_YESPOWERR16) {
		char params[160];

		yespower_describe(YESCRYPT + (opt_algo - ALGO_YESCRYPT), params,
				sizeof(params));
		applog(LOG_INFO, "%s: %s", algo_names[opt_algo], params);
	}


	if (!opt_benchmark && !rpc_url) {
		fprintf(stderr, "%s: no URL supplied\n", argv[0]);
		show_usage_and_exit(1);
	}

	if (!rpc_userpass) {
		rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	pthread_mutex_init(&stratum.sock_lock, NULL );
	pthread_mutex_init(&stratum.work_lock, NULL );

	flags = !opt_benchmark && strncmp(rpc_url, "https:", 6) ?
			(CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL) : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

#ifndef _WIN32
	if (opt_background) {
		i = fork();
		if (i < 0)
			exit(1);
		if (i > 0)
			exit(0);
		i = setsid();
		if (i < 0)
			applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
		i = chdir("/");
		if (i < 0)
			applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
	}
	start_signal_thread();
#endif

#if defined(_WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_processors = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_processors = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = {CTL_HW, HW_NCPU};
	size_t len = sizeof(num_processors);
	sysctl(req, 2, &num_processors, &len, NULL, 0);
#else
	num_processors = 1;
#endif
	if (num_processors < 1)
		num_processors = 1;
	if (!opt_n_threads) {
		opt_n_threads = num_processors;
		/* a thread per 2 MiB scratchpad the L3 cache holds, at most */
		if (opt_algo == ALGO_CRYPTONIGHT || opt_algo == ALGO_RANDOMX) {
			uint64_t l3 = cpu_l3_cache_size();

			if (l3 && l3 / (2 << 20) < (uint64_t) num_processors) {
				opt_n_threads = l3 >= (2 << 20) ? (int) (l3 / (2 << 20)) : 1;
				applog(LOG_INFO, "%d threads, as many 2 MiB scratchpads as the processor's L3 cache (%u MiB) holds (-t sets another number)",
						opt_n_threads, (unsigned) (l3 >> 20));
			}
		}
	}

	/* RandomX: the cache and dataset, before any thread needs them */
	if (opt_algo == ALGO_RANDOMX) {
		if (!rx_setup(opt_randomx_mode, opt_n_threads, num_processors))
			return 1;
		applog(LOG_INFO, "RandomX: %s", rx_describe());
	}
	/* Verthash: the data file */
	if (opt_algo == ALGO_VERTHASH && !verthash_setup(opt_verthash_data, num_processors))
		return 1;

#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog("cpuminer", LOG_PID, LOG_USER);
#endif

	work_restart = calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = calloc(opt_n_threads + 3, sizeof(*thr));
	if (!thr_info)
		return 1;

	thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
	if (!thr_hashrates)
		return 1;

	/* Create every thread's queue before starting any thread: the
	 * workio thread can hand work to the long polling and stratum
	 * threads as soon as it runs (it used to find their ids and queues
	 * not set up yet). */
	work_thr_id = opt_n_threads;
	thr_info[work_thr_id].id = work_thr_id;
	thr_info[work_thr_id].q = tq_new();
	if (!thr_info[work_thr_id].q)
		return 1;
	if (want_longpoll && !have_stratum) {
		longpoll_thr_id = opt_n_threads + 1;
		thr_info[longpoll_thr_id].id = longpoll_thr_id;
		thr_info[longpoll_thr_id].q = tq_new();
		if (!thr_info[longpoll_thr_id].q)
			return 1;
	}
	if (want_stratum) {
		stratum_thr_id = opt_n_threads + 2;
		thr_info[stratum_thr_id].id = stratum_thr_id;
		thr_info[stratum_thr_id].q = tq_new();
		if (!thr_info[stratum_thr_id].q)
			return 1;
	}
	for (i = 0; i < opt_n_threads; i++) {
		thr_info[i].id = i;
		thr_info[i].q = tq_new();
		if (!thr_info[i].q)
			return 1;
	}

	if (longpoll_thr_id >= 0 && unlikely(pthread_create(&thr_info[longpoll_thr_id].pth,
			NULL, longpoll_thread, &thr_info[longpoll_thr_id]))) {
		applog(LOG_ERR, "longpoll thread create failed");
		return 1;
	}
	if (stratum_thr_id >= 0) {
		if (unlikely(pthread_create(&thr_info[stratum_thr_id].pth, NULL,
				stratum_thread, &thr_info[stratum_thr_id]))) {
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}
		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}
	if (pthread_create(&thr_info[work_thr_id].pth, NULL, workio_thread,
			&thr_info[work_thr_id])) {
		applog(LOG_ERR, "workio thread create failed");
		return 1;
	}

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}
	}

	applog(LOG_INFO, "%d miner threads started, "
			"using '%s' algorithm.", opt_n_threads, algo_names[opt_algo]);

	/* main loop - simply wait for workio thread to exit, which it only
	 * does when it gives up (a fatal error, or --retries exhausted);
	 * signals end the program in the signal thread */
	pthread_join(thr_info[work_thr_id].pth, NULL );

	applog(LOG_INFO, "workio thread dead, exiting.");

	return 1;
}
