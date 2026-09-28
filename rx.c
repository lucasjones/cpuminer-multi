/*
 * RandomX, Monero's proof of work ("rx/0"): the miner's side of tevador's
 * library (randomx/, see randomx/README.cpuminer).
 *
 * RandomX hashes with a virtual machine that runs random programs over a
 * large read-only data set. The data set is built from a key: for Monero
 * the "seed hash" that pools send with every job, the hash of a block that
 * changes every 2048 blocks (about every 2.8 days). There are two modes:
 *
 *   fast   the threads share a 2080 MiB dataset, built from a 256 MiB cache
 *          (using every processor: from a few seconds to a minute or two);
 *   light  the threads share only the cache and compute the parts of the
 *          dataset they need as they go: several times slower, for machines
 *          without the memory.
 *
 * Each thread has its own virtual machine, with 2 MiB of scratchpad. The
 * first thread to get work for a new key rebuilds the cache (and dataset)
 * while the others wait: rx_lock is read-locked while hashing, and
 * write-locked while rebuilding.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE		/* sched_setaffinity() */
#include "miner.h"

#ifdef USE_RANDOMX

#include <fenv.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "compat.h"
#include "randomx/randomx.h"
#include "randomx/configuration.h"

#define RX_CACHE_SIZE	((uint64_t) RANDOMX_ARGON_MEMORY * 1024)
#define RX_DATASET_SIZE	((uint64_t) randomx_dataset_item_count() * RANDOMX_DATASET_ITEM_SIZE)
#define RX_MAX_KEY	64	/* pools' keys are 32 bytes */
#define MIB(bytes)	((unsigned) (((bytes) + (1 << 20) - 1) >> 20))

static pthread_rwlock_t rx_lock;
static bool rx_lock_made;
static bool rx_ready;			/* rx_setup() succeeded */
static bool rx_fast;			/* with the dataset */
static randomx_cache *rx_cache;
static randomx_dataset *rx_dataset;
static int rx_init_threads;		/* for building the dataset */
static char rx_desc[200];

/* the key the cache (and dataset) are built from, under rx_lock */
static unsigned char rx_key[RX_MAX_KEY];
static size_t rx_keylen;
static bool rx_keyed;
static unsigned rx_gen;			/* one more at each rebuild */

/* each miner thread's virtual machine, and the rx_gen it has caught up with */
static struct rx_thread {
	randomx_vm *vm;
	unsigned gen;
} *rx_threads;
static int rx_nthreads;

/* flags for new virtual machines: fewer as they turn out not to work here */
static randomx_flags rx_vm_flags;
static pthread_mutex_t rx_vm_lock = PTHREAD_MUTEX_INITIALIZER;

static inline randomx_flags rx_flags_with(randomx_flags f, int add)
{
	return (randomx_flags) (f | add);
}

static inline randomx_flags rx_flags_without(randomx_flags f, int drop)
{
	return (randomx_flags) (f & ~drop);
}

/* Linux: ask for transparent huge pages for memory that is read at random
 * (fewer TLB misses, a faster hash). It has to come before the memory is
 * first written. */
static void rx_advise_huge(void *p, uint64_t len)
{
#if defined(MADV_HUGEPAGE) && defined(_SC_PAGESIZE)
	long page = sysconf(_SC_PAGESIZE);
	uintptr_t start, end;

	if (page <= 0)
		return;
	start = ((uintptr_t) p + page - 1) & ~(uintptr_t) (page - 1);
	end = ((uintptr_t) p + len) & ~(uintptr_t) (page - 1);
	if (end > start)
		madvise((void *) start, end - start, MADV_HUGEPAGE);
#else
	(void) p;
	(void) len;
#endif
}

/*
 * Choose the mode and allocate the cache, and the dataset in fast mode, for
 * threads miner threads (thr_id 0 to threads - 1). Datasets are built with
 * init_threads threads. False if there is not the memory.
 */
bool rx_setup(int mode, int threads, int init_threads)
{
	randomx_flags flags = randomx_get_flags();
	uint64_t mem = system_memory();
	bool large_cache = false, large_dataset = false;
	char memory[64];

	if (rx_ready || threads < 1)
		return false;
	rx_threads = calloc(threads, sizeof(*rx_threads));
	if (!rx_threads)
		return false;
	rx_nthreads = threads;
	rx_init_threads = init_threads > 0 ? init_threads : 1;
	if (pthread_rwlock_init(&rx_lock, NULL)) {
		rx_cleanup();
		return false;
	}
	rx_lock_made = true;

	/* Fast mode, unless memory is short: it takes the dataset, the cache
	 * (kept to rebuild the dataset when the key changes), a scratchpad per
	 * thread, and there has to be some left for everything else. A 32-bit
	 * program cannot hold the dataset at all. */
	if (mode == RX_MODE_AUTO) {
		uint64_t need = RX_DATASET_SIZE + RX_CACHE_SIZE
			+ (uint64_t) threads * RANDOMX_SCRATCHPAD_L3 + (1ULL << 30);

		rx_fast = sizeof(void *) >= 8 && (!mem || mem >= need);
		if (!rx_fast && sizeof(void *) < 8)
			applog(LOG_INFO, "RandomX: light mode (fast mode needs a 64-bit build)");
		else if (!rx_fast)
			applog(LOG_INFO, "RandomX: light mode (fast mode needs %u MiB of memory; %u MiB here)",
			       MIB(need), MIB(mem));
	} else
		rx_fast = mode == RX_MODE_FAST;

	/* large pages if the system has some set aside, else ordinary pages;
	 * without the JIT compiler if the system will not have it */
	rx_cache = randomx_alloc_cache(rx_flags_with(flags, RANDOMX_FLAG_LARGE_PAGES));
	if (rx_cache)
		large_cache = true;
	else
		rx_cache = randomx_alloc_cache(flags);
	if (!rx_cache && (flags & RANDOMX_FLAG_JIT)) {
		flags = rx_flags_without(flags, RANDOMX_FLAG_JIT | RANDOMX_FLAG_SECURE);
		rx_cache = randomx_alloc_cache(flags);
	}
	if (!rx_cache) {
		applog(LOG_ERR, "RandomX: not enough memory for the cache (%u MiB)",
		       MIB(RX_CACHE_SIZE));
		rx_cleanup();
		return false;
	}
	if (!large_cache)
		rx_advise_huge(randomx_get_cache_memory(rx_cache), RX_CACHE_SIZE);

	if (rx_fast) {
		rx_dataset = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
		if (rx_dataset)
			large_dataset = true;
		else {
			rx_dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
			if (rx_dataset)
				rx_advise_huge(randomx_get_dataset_memory(rx_dataset), RX_DATASET_SIZE);
		}
		if (!rx_dataset) {
			if (mode == RX_MODE_FAST) {
				applog(LOG_ERR, "RandomX: not enough memory for the dataset (%u MiB); --randomx-mode=light needs %u MiB",
				       MIB(RX_DATASET_SIZE), MIB(RX_CACHE_SIZE));
				rx_cleanup();
				return false;
			}
			applog(LOG_INFO, "RandomX: not enough memory for the dataset (%u MiB): light mode",
			       MIB(RX_DATASET_SIZE));
			rx_fast = false;
		}
	}

	/* virtual machines: scratchpads in large pages too if there are
	 * enough, which the first machine created will find out */
	rx_vm_flags = rx_flags_with(flags, RANDOMX_FLAG_LARGE_PAGES
		| (rx_fast ? RANDOMX_FLAG_FULL_MEM : 0));

	if (rx_fast)
		snprintf(memory, sizeof(memory), "%u MiB dataset%s, ",
			 MIB(RX_DATASET_SIZE), large_dataset ? " in large pages" : "");
	else
		memory[0] = '\0';
	snprintf(rx_desc, sizeof(rx_desc), "%s mode (%s%u MiB cache%s), %s, %s AES, Argon2 %s",
		 rx_fast ? "fast" : "light", memory, MIB(RX_CACHE_SIZE),
		 large_cache ? " in large pages" : "",
		 flags & RANDOMX_FLAG_JIT ? "JIT compiler" : "interpreter",
		 flags & RANDOMX_FLAG_HARD_AES ? "hardware" : "software",
		 flags & RANDOMX_FLAG_ARGON2_AVX2 ? "AVX2" :
		 flags & RANDOMX_FLAG_ARGON2_SSSE3 ? "SSSE3" : "portable");
	rx_ready = true;
	return true;
}

/* how RandomX will run, for the log */
const char *rx_describe(void)
{
	return rx_desc;
}

/* with the dataset (fast mode)? */
bool rx_is_fast(void)
{
	return rx_ready && rx_fast;
}

/* free everything rx_setup() and mining allocated (no thread may be using
 * RandomX); rx_setup() may be called again */
void rx_cleanup(void)
{
	int i;

	for (i = 0; rx_threads && i < rx_nthreads; i++)
		if (rx_threads[i].vm)
			randomx_destroy_vm(rx_threads[i].vm);
	free(rx_threads);
	rx_threads = NULL;
	rx_nthreads = 0;
	if (rx_dataset)
		randomx_release_dataset(rx_dataset);
	rx_dataset = NULL;
	if (rx_cache)
		randomx_release_cache(rx_cache);
	rx_cache = NULL;
	if (rx_lock_made)
		pthread_rwlock_destroy(&rx_lock);
	rx_lock_made = false;
	rx_keyed = false;
	rx_keylen = 0;
	rx_ready = false;
}

struct rx_part {
	unsigned long start, count;
};

static void *rx_build_part(void *arg)
{
	const struct rx_part *p = arg;

	randomx_init_dataset(rx_dataset, rx_cache, p->start, p->count);
	return NULL;
}

/* A thread inherits the processor its creator is bound to (a miner thread
 * may be): let a helper thread run on any. */
static void *rx_build_part_anywhere(void *arg)
{
#if defined(__linux__) && defined(CPU_SETSIZE)
	cpu_set_t set;
	int i;

	CPU_ZERO(&set);
	for (i = 0; i < CPU_SETSIZE; i++)
		CPU_SET(i, &set);
	sched_setaffinity(0, sizeof(set), &set);
#endif
	return rx_build_part(arg);
}

/* Rebuild the cache (and the dataset, with rx_init_threads threads) for a
 * new key. rx_lock is write-locked. */
static void rx_rebuild(const void *key, size_t keylen)
{
	struct timeval start, end;
	char hex[2 * 8 + 1];
	size_t i;

	gettimeofday(&start, NULL);
	randomx_init_cache(rx_cache, key, keylen);
	if (rx_fast) {
		const unsigned long items = randomx_dataset_item_count();
		int n = rx_init_threads, i;
		struct rx_part *parts = calloc(n, sizeof(*parts));
		pthread_t *tids = calloc(n, sizeof(*tids));
		bool *started = calloc(n, sizeof(*started));

		if (!parts || !tids || !started) {
			struct rx_part all = { 0, items };

			rx_build_part(&all);
		} else {
			/* the calling thread waits: it may be bound to a
			 * processor that one of the helpers gets */
			for (i = 0; i < n; i++) {
				parts[i].start = (unsigned long) ((uint64_t) items * i / n);
				parts[i].count = (unsigned long) ((uint64_t) items * (i + 1) / n)
					- parts[i].start;
				started[i] = n > 1 && !pthread_create(&tids[i], NULL,
						rx_build_part_anywhere, &parts[i]);
			}
			for (i = 0; i < n; i++) {
				if (started[i])
					pthread_join(tids[i], NULL);
				else
					rx_build_part(&parts[i]);
			}
		}
		free(parts);
		free(tids);
		free(started);
	}
	memcpy(rx_key, key, keylen);
	rx_keylen = keylen;
	rx_keyed = true;
	rx_gen++;

	gettimeofday(&end, NULL);
	for (i = 0; i < keylen && i < 8; i++)
		snprintf(hex + 2 * i, 3, "%02x", ((const unsigned char *) key)[i]);
	hex[2 * i] = '\0';
	applog(LOG_INFO, "RandomX: %s for seed %s%s ready in %.1f s",
	       rx_fast ? "dataset" : "cache", hex, keylen > 8 ? "..." : "",
	       (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1e-6);
}

/* a virtual machine with the current flags, dropping those that turn out
 * not to work here */
static randomx_vm *rx_create_vm(void)
{
	randomx_vm *vm;

	pthread_mutex_lock(&rx_vm_lock);
	for (;;) {
		randomx_flags flags = rx_vm_flags;

		vm = randomx_create_vm(flags, rx_fast ? NULL : rx_cache,
				       rx_fast ? rx_dataset : NULL);
		if (vm)
			break;
		if (flags & RANDOMX_FLAG_LARGE_PAGES)
			/* none set aside (or not enough) */
			rx_vm_flags = rx_flags_without(flags, RANDOMX_FLAG_LARGE_PAGES);
		else if ((flags & RANDOMX_FLAG_JIT) && !(flags & RANDOMX_FLAG_SECURE))
			/* the system may not have memory that is writable and
			 * executable at the same time */
			rx_vm_flags = rx_flags_with(flags, RANDOMX_FLAG_SECURE);
		else if (flags & RANDOMX_FLAG_JIT) {
			rx_vm_flags = rx_flags_without(flags, RANDOMX_FLAG_JIT | RANDOMX_FLAG_SECURE);
			applog(LOG_WARNING, "RandomX: the system does not allow the JIT compiler: interpreting (several times slower)");
		} else
			break;	/* out of memory */
	}
	pthread_mutex_unlock(&rx_vm_lock);
	return vm;
}

enum { RX_OK, RX_DROPPED, RX_NO_MEMORY };

/*
 * Get thread thr_id's virtual machine ready for a key. RX_OK: *vm is it, and
 * rx_lock is read-locked (unlock when done hashing). RX_DROPPED: the thread
 * has been told to drop its work, whose key this is, so it was not built.
 * *fresh says if the cache was rebuilt (by any thread) since this thread
 * last hashed, so that it probably waited for it.
 */
static int rx_acquire(int thr_id, const void *key, size_t keylen,
		      randomx_vm **vm, bool *fresh)
{
	struct rx_thread *t;

	*fresh = false;
	if (!rx_ready || keylen > RX_MAX_KEY || thr_id < 0 || thr_id >= rx_nthreads)
		return RX_NO_MEMORY;
	t = &rx_threads[thr_id];
	for (;;) {
		pthread_rwlock_rdlock(&rx_lock);
		if (rx_keyed && rx_keylen == keylen && !memcmp(rx_key, key, keylen))
			break;
		pthread_rwlock_unlock(&rx_lock);

		pthread_rwlock_wrlock(&rx_lock);
		if (!rx_keyed || rx_keylen != keylen || memcmp(rx_key, key, keylen)) {
			/* the work is out of date: its key may be older than
			 * the one another thread just built */
			if (work_restart[thr_id].restart) {
				pthread_rwlock_unlock(&rx_lock);
				return RX_DROPPED;
			}
			rx_rebuild(key, keylen);
		}
		pthread_rwlock_unlock(&rx_lock);
	}

	if (!t->vm) {
		t->vm = rx_create_vm();
		if (!t->vm) {
			pthread_rwlock_unlock(&rx_lock);
			return RX_NO_MEMORY;
		}
		*fresh = true;
	} else if (t->gen != rx_gen) {
		/* light mode: the machine keeps things computed from the key */
		if (!rx_fast)
			randomx_vm_set_cache(t->vm, rx_cache);
		*fresh = true;
	}
	t->gen = rx_gen;
	*vm = t->vm;
	return RX_OK;
}

static inline uint64_t rx_le64dec(const unsigned char *p)
{
	return (uint64_t) le32dec(p + 4) << 32 | le32dec(p);
}

/*
 * Scan nonces of a job blob (the nonce is the 4 bytes at 39) for a hash whose
 * top 64 bits are below the target (ptarget[7] high, ptarget[6] low), with
 * key seed (32 bytes). Found: 1, the nonce in the blob and the hash in hash.
 */
int scanhash_randomx(int thr_id, uint32_t *pdata, size_t data_size,
		const unsigned char *seed, const uint32_t *ptarget,
		uint32_t max_nonce, uint64_t *hashes_done, unsigned char *hash)
{
	unsigned char *blob = (unsigned char *) pdata;
	const uint64_t target = ((uint64_t) ptarget[7] << 32) | ptarget[6];
	uint32_t n = le32dec(blob + 39);
	const uint32_t first_nonce = n;
	unsigned char out[RANDOMX_HASH_SIZE];
	randomx_vm *vm;
	bool fresh, found = false;
	fenv_t fenv;

	*hashes_done = 0;
	if (data_size < RPC2_MIN_BLOB || data_size > RPC2_MAX_BLOB)
		return 0;
	switch (rx_acquire(thr_id, seed, 32, &vm, &fresh)) {
	case RX_OK:
		break;
	case RX_DROPPED:
		return 0;
	default:
		applog(LOG_ERR, "RandomX: thread %d: not enough memory for a virtual machine", thr_id);
		sleep(5);
		return 0;
	}
	if (fresh) {
		/* the time spent building (or waiting for) the cache or dataset
		 * says nothing about the hash rate: start timing anew */
		pthread_rwlock_unlock(&rx_lock);
		return 0;
	}

	/* The hash of one nonce is finished while the next one's is started
	 * (the library overlaps them). It may leave the rounding mode changed. */
	fegetenv(&fenv);
	randomx_calculate_hash_first(vm, blob, data_size);
	for (;;) {
		const bool last = n >= max_nonce || work_restart[thr_id].restart;

		if (last)
			randomx_calculate_hash_last(vm, out);
		else {
			le32enc(blob + 39, n + 1);
			randomx_calculate_hash_next(vm, blob, data_size, out);
		}
		/* out is the hash of nonce n */
		if (unlikely(rx_le64dec(out + 24) < target)) {
			memcpy(hash, out, RANDOMX_HASH_SIZE);
			found = true;
			break;
		}
		if (last)
			break;
		n++;
	}
	fesetenv(&fenv);
	pthread_rwlock_unlock(&rx_lock);

	le32enc(blob + 39, n);
	*hashes_done = (uint64_t) (n - first_nonce) + 1;
	return found;
}

/* one hash, with any key (thread thr_id's machine): for tests and checks */
bool rx_hash(int thr_id, void *output, const void *key, size_t keylen,
	     const void *input, size_t len)
{
	randomx_vm *vm;
	bool fresh;

	if (rx_acquire(thr_id, key, keylen, &vm, &fresh) != RX_OK)
		return false;
	randomx_calculate_hash(vm, input, len, output);
	pthread_rwlock_unlock(&rx_lock);
	return true;
}

#else /* !USE_RANDOMX */

bool rx_setup(int mode, int threads, int init_threads)
{
	(void) mode;
	(void) threads;
	(void) init_threads;
	applog(LOG_ERR, "This minerd was built without RandomX, which needs a C++11 compiler (see README.md)");
	return false;
}

const char *rx_describe(void)
{
	return "not built";
}

bool rx_is_fast(void)
{
	return false;
}

void rx_cleanup(void)
{
}

int scanhash_randomx(int thr_id, uint32_t *pdata, size_t data_size,
		const unsigned char *seed, const uint32_t *ptarget,
		uint32_t max_nonce, uint64_t *hashes_done, unsigned char *hash)
{
	(void) thr_id; (void) pdata; (void) data_size; (void) seed;
	(void) ptarget; (void) max_nonce; (void) hash;
	*hashes_done = 0;
	return 0;
}

bool rx_hash(int thr_id, void *output, const void *key, size_t keylen,
	     const void *input, size_t len)
{
	(void) thr_id; (void) output; (void) key; (void) keylen;
	(void) input; (void) len;
	return false;
}

#endif /* USE_RANDOMX */
