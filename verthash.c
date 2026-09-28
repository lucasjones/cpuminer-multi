/*
 * Verthash, Vertcoin's proof of work since block 1,500,000 (December 2020),
 * from its specification in vertcoin-project/verthash-pospace and
 * vertcoinhash-python (MIT licensed).
 *
 * The hash of an 80-byte block header starts as its SHA3-256, and takes in
 * 4096 32-byte pieces of a 1.2 GB data file, verthash.dat: where each piece
 * is depends on 8 SHA3-512 hashes of the header and on all that was read
 * before it, so the reads cannot be made ahead of time, and the whole file
 * has to be in memory. The file is the same for everyone: a graph of SHA3-256
 * hashes from SpaceMint's proof of space (a stack of butterfly graphs), which
 * this code can build (in seconds) as well as read.
 *
 * The miner reads the file (--verthash-data, the current directory, or
 * where Vertcoin Core keeps it), or builds and saves it if there is none;
 * either way it checks the data's SHA-256.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define VH_HEADER_SIZE	80
#define VH_HASH_SIZE	32
#define VH_P0_SIZE	64			/* a SHA3-512 */
#define VH_N_ITER	8			/* SHA3-512s of the header */
#define VH_N_SUBSET	(VH_P0_SIZE * VH_N_ITER / 4)	/* their 128 words */
#define VH_N_ROT	32			/* each rotated 0 to 31 bits */
#define VH_N_INDEXES	(VH_N_SUBSET * VH_N_ROT)	/* 4096 reads */
#define VH_ALIGN	16			/* reads start on 16 bytes */

/* the data file: the Xi graph of index 17, 32 bytes a node */
#define VH_GRAPH_INDEX	17
#define VH_NODES	((uint64_t) (1 << VH_GRAPH_INDEX) * (VH_GRAPH_INDEX + 1) * VH_GRAPH_INDEX)
#define VH_DATA_SIZE	(VH_NODES * 32)		/* 1,283,457,024 bytes */

/* its SHA-256, as sha256sum shows it */
static const unsigned char vh_data_sha256[32] = {
	0xa5, 0x55, 0x31, 0xe8, 0x43, 0xcd, 0x56, 0xb0,
	0x10, 0x11, 0x4a, 0xaf, 0x63, 0x25, 0xb0, 0xd5,
	0x29, 0xec, 0xf8, 0x8f, 0x8a, 0xd4, 0x76, 0x39,
	0xb6, 0xed, 0xed, 0xaf, 0xd7, 0x21, 0xaa, 0x48,
};

/* the file's contents, shared by all threads, read only once loaded */
static unsigned char *vh_data;
static int vh_alloc_kind;		/* how vh_data was allocated */

/* ------------------------------------------------------------------------
 * SHA3 (FIPS 202), for inputs of at most one block
 */

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t keccak_rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* one round from lanes A.. into lanes E.. (the Keccak team's
 * "Keccak-simple" arrangement: theta, rho and pi, chi, iota) */
#define KECCAK_ROUND(A, E, rc) do { \
	uint64_t Ca, Ce, Ci, Co, Cu, Da, De, Di, Do, Du; \
	Ca = A##ba ^ A##ga ^ A##ka ^ A##ma ^ A##sa; \
	Ce = A##be ^ A##ge ^ A##ke ^ A##me ^ A##se; \
	Ci = A##bi ^ A##gi ^ A##ki ^ A##mi ^ A##si; \
	Co = A##bo ^ A##go ^ A##ko ^ A##mo ^ A##so; \
	Cu = A##bu ^ A##gu ^ A##ku ^ A##mu ^ A##su; \
	Da = Cu ^ ROL64(Ce, 1); \
	De = Ca ^ ROL64(Ci, 1); \
	Di = Ce ^ ROL64(Co, 1); \
	Do = Ci ^ ROL64(Cu, 1); \
	Du = Co ^ ROL64(Ca, 1); \
	A##ba ^= Da; Ca = A##ba; \
	A##ge ^= De; Ce = ROL64(A##ge, 44); \
	A##ki ^= Di; Ci = ROL64(A##ki, 43); \
	A##mo ^= Do; Co = ROL64(A##mo, 21); \
	A##su ^= Du; Cu = ROL64(A##su, 14); \
	E##ba = Ca ^ (~Ce & Ci) ^ (rc); \
	E##be = Ce ^ (~Ci & Co); \
	E##bi = Ci ^ (~Co & Cu); \
	E##bo = Co ^ (~Cu & Ca); \
	E##bu = Cu ^ (~Ca & Ce); \
	A##bo ^= Do; Ca = ROL64(A##bo, 28); \
	A##gu ^= Du; Ce = ROL64(A##gu, 20); \
	A##ka ^= Da; Ci = ROL64(A##ka, 3); \
	A##me ^= De; Co = ROL64(A##me, 45); \
	A##si ^= Di; Cu = ROL64(A##si, 61); \
	E##ga = Ca ^ (~Ce & Ci); \
	E##ge = Ce ^ (~Ci & Co); \
	E##gi = Ci ^ (~Co & Cu); \
	E##go = Co ^ (~Cu & Ca); \
	E##gu = Cu ^ (~Ca & Ce); \
	A##be ^= De; Ca = ROL64(A##be, 1); \
	A##gi ^= Di; Ce = ROL64(A##gi, 6); \
	A##ko ^= Do; Ci = ROL64(A##ko, 25); \
	A##mu ^= Du; Co = ROL64(A##mu, 8); \
	A##sa ^= Da; Cu = ROL64(A##sa, 18); \
	E##ka = Ca ^ (~Ce & Ci); \
	E##ke = Ce ^ (~Ci & Co); \
	E##ki = Ci ^ (~Co & Cu); \
	E##ko = Co ^ (~Cu & Ca); \
	E##ku = Cu ^ (~Ca & Ce); \
	A##bu ^= Du; Ca = ROL64(A##bu, 27); \
	A##ga ^= Da; Ce = ROL64(A##ga, 36); \
	A##ke ^= De; Ci = ROL64(A##ke, 10); \
	A##mi ^= Di; Co = ROL64(A##mi, 15); \
	A##so ^= Do; Cu = ROL64(A##so, 56); \
	E##ma = Ca ^ (~Ce & Ci); \
	E##me = Ce ^ (~Ci & Co); \
	E##mi = Ci ^ (~Co & Cu); \
	E##mo = Co ^ (~Cu & Ca); \
	E##mu = Cu ^ (~Ca & Ce); \
	A##bi ^= Di; Ca = ROL64(A##bi, 62); \
	A##go ^= Do; Ce = ROL64(A##go, 55); \
	A##ku ^= Du; Ci = ROL64(A##ku, 39); \
	A##ma ^= Da; Co = ROL64(A##ma, 41); \
	A##se ^= De; Cu = ROL64(A##se, 2); \
	E##sa = Ca ^ (~Ce & Ci); \
	E##se = Ce ^ (~Ci & Co); \
	E##si = Ci ^ (~Co & Cu); \
	E##so = Co ^ (~Cu & Ca); \
	E##su = Cu ^ (~Ca & Ce); \
} while (0)

/* Keccak-f[1600] on 25 lanes */
static void keccakf1600(uint64_t s[25])
{
	uint64_t Aba = s[0], Abe = s[1], Abi = s[2], Abo = s[3], Abu = s[4];
	uint64_t Aga = s[5], Age = s[6], Agi = s[7], Ago = s[8], Agu = s[9];
	uint64_t Aka = s[10], Ake = s[11], Aki = s[12], Ako = s[13], Aku = s[14];
	uint64_t Ama = s[15], Ame = s[16], Ami = s[17], Amo = s[18], Amu = s[19];
	uint64_t Asa = s[20], Ase = s[21], Asi = s[22], Aso = s[23], Asu = s[24];
	uint64_t Eba, Ebe, Ebi, Ebo, Ebu, Ega, Ege, Egi, Ego, Egu;
	uint64_t Eka, Eke, Eki, Eko, Eku, Ema, Eme, Emi, Emo, Emu;
	uint64_t Esa, Ese, Esi, Eso, Esu;
	int round;

	for (round = 0; round < 24; round += 2) {
		KECCAK_ROUND(A, E, keccak_rc[round]);
		KECCAK_ROUND(E, A, keccak_rc[round + 1]);
	}
	s[0] = Aba; s[1] = Abe; s[2] = Abi; s[3] = Abo; s[4] = Abu;
	s[5] = Aga; s[6] = Age; s[7] = Agi; s[8] = Ago; s[9] = Agu;
	s[10] = Aka; s[11] = Ake; s[12] = Aki; s[13] = Ako; s[14] = Aku;
	s[15] = Ama; s[16] = Ame; s[17] = Ami; s[18] = Amo; s[19] = Amu;
	s[20] = Asa; s[21] = Ase; s[22] = Asi; s[23] = Aso; s[24] = Asu;
}

static inline uint64_t le64dec_p(const unsigned char *p)
{
	return (uint64_t) le32dec(p + 4) << 32 | le32dec(p);
}

static inline void le64enc_p(unsigned char *p, uint64_t x)
{
	le32enc(p, (uint32_t) x);
	le32enc(p + 4, (uint32_t) (x >> 32));
}

/* XOR len bytes into the state from lane 0 on; a partial lane is fine */
static void keccak_absorb(uint64_t s[25], const unsigned char *in, size_t len)
{
	size_t i;

	for (i = 0; i + 8 <= len; i += 8)
		s[i / 8] ^= le64dec_p(in + i);
	for (; i < len; i++)
		s[i / 8] ^= (uint64_t) in[i] << (8 * (i % 8));
}

/* the SHA3 padding of a last block holding len bytes, rate bytes a block */
static inline void sha3_pad(uint64_t s[25], size_t len, size_t rate)
{
	s[len / 8] ^= (uint64_t) 0x06 << (8 * (len % 8));
	s[rate / 8 - 1] ^= 0x8000000000000000ULL;
}

static void keccak_squeeze(const uint64_t s[25], unsigned char *out, size_t len)
{
	size_t i;

	for (i = 0; i < len; i += 8)
		le64enc_p(out + i, s[i / 8]);
}

/* SHA3-256 of at most 135 bytes */
static void sha3_256_short(unsigned char out[32], const void *in, size_t len)
{
	uint64_t s[25] = { 0 };

	keccak_absorb(s, in, len);
	sha3_pad(s, len, 136);
	keccakf1600(s);
	keccak_squeeze(s, out, 32);
}

/* ------------------------------------------------------------------------
 * The data file: nodes of SpaceMint's Xi graph, each the SHA3-256 of a key,
 * its own number, and the nodes it depends on. This follows h1.c of
 * vertcoin-project/verthash-pospace and vertcoinhash-python, node for node
 * (node n goes at offset (n - 2^26) * 32), in memory instead of on disk.
 */

struct vh_graph {
	unsigned char *data;
	uint64_t pow2;			/* the number of the first node */
	uint64_t count;			/* of the next node */
	unsigned char pk[32];		/* SHA3-256 of the key */
	int threads;			/* to build big loops with */
};

static inline unsigned char *vh_node(const struct vh_graph *g, uint64_t id)
{
	return g->data + (id & ~g->pow2) * 32;
}

/* a node from its number and up to 2 parents (NULL if fewer) */
static void vh_new_node(const struct vh_graph *g, uint64_t id,
			const unsigned char *p0, const unsigned char *p1)
{
	unsigned char in[4 * 32], *v = in + 32;
	uint64_t zz = id << 1;		/* a zigzag varint, as Go's PutVarint */
	size_t len = 64;

	memcpy(in, g->pk, 32);
	memset(v, 0, 32);
	while (zz >= 0x80) {
		*v++ = (unsigned char) zz | 0x80;
		zz >>= 7;
	}
	*v = (unsigned char) zz;
	if (p0) {
		memcpy(in + len, p0, 32);
		len += 32;
	}
	if (p1) {
		memcpy(in + len, p1, 32);
		len += 32;
	}
	sha3_256_short(vh_node(g, id), in, len);
}

/*
 * The graph is built a loop at a time. The nodes of a loop only depend on
 * nodes made before it, so they can be made in any order: a big loop is
 * shared out among threads.
 */
enum {
	VH_SOURCES,		/* no parents */
	VH_TWO_PARENTS,		/* first + i: a + i and a + i + half */
	VH_ONE_PARENT,		/* first + i: first - half + i */
	VH_PAIRS,		/* first + i and first + i + half: first - half + i,
				 * and a + i or a + i + half */
	VH_BUTTERFLY,		/* first + i: a + i and a + (i with bit shift flipped) */
};

struct vh_loop {
	int kind;
	uint64_t first, n;	/* its first node, and how many i */
	uint64_t a, half, shift;
};

static void vh_loop_part(const struct vh_graph *g, const struct vh_loop *L,
			 uint64_t from, uint64_t to)
{
	uint64_t i;

	for (i = from; i < to; i++) {
		const uint64_t id = L->first + i;

		switch (L->kind) {
		case VH_SOURCES:
			vh_new_node(g, id, NULL, NULL);
			break;
		case VH_TWO_PARENTS:
			vh_new_node(g, id, vh_node(g, L->a + i), vh_node(g, L->a + i + L->half));
			break;
		case VH_ONE_PARENT:
			vh_new_node(g, id, vh_node(g, L->first - L->half + i), NULL);
			break;
		case VH_PAIRS: {
			const unsigned char *p0 = vh_node(g, L->first - L->half + i);

			vh_new_node(g, id, p0, vh_node(g, L->a + i));
			vh_new_node(g, id + L->half, p0, vh_node(g, L->a + i + L->half));
			break;
		}
		case VH_BUTTERFLY:
			vh_new_node(g, id, vh_node(g, L->a + (i ^ ((uint64_t) 1 << L->shift))),
				    vh_node(g, L->a + i));
			break;
		}
	}
}

struct vh_part {
	const struct vh_graph *g;
	const struct vh_loop *L;
	uint64_t from, to;
};

static void *vh_part_run(void *arg)
{
	const struct vh_part *p = arg;

	vh_loop_part(p->g, p->L, p->from, p->to);
	return NULL;
}

#define VH_MAX_THREADS 64

/* make a loop's nodes, and count them */
static void vh_run(struct vh_graph *g, const struct vh_loop *L)
{
	int threads = g->threads < VH_MAX_THREADS ? g->threads : VH_MAX_THREADS;

	if (threads < 2 || L->n < 1024)
		vh_loop_part(g, L, 0, L->n);
	else {
		struct vh_part parts[VH_MAX_THREADS];
		pthread_t tids[VH_MAX_THREADS];
		bool started[VH_MAX_THREADS];
		int t;

		for (t = 0; t < threads; t++) {
			parts[t].g = g;
			parts[t].L = L;
			parts[t].from = L->n * t / threads;
			parts[t].to = L->n * (t + 1) / threads;
			started[t] = t && !pthread_create(&tids[t], NULL, vh_part_run, &parts[t]);
		}
		vh_loop_part(g, L, parts[0].from, parts[0].to);
		for (t = 1; t < threads; t++) {
			if (started[t])
				pthread_join(tids[t], NULL);
			else
				vh_loop_part(g, L, parts[t].from, parts[t].to);
		}
	}
	g->count += L->kind == VH_PAIRS ? 2 * L->n : L->n;
}

/* a butterfly graph on the last 2^index nodes: 2 index - 1 levels more */
static void vh_butterfly(struct vh_graph *g, uint64_t index)
{
	uint64_t num_level, per_level, level;
	struct vh_loop L;

	if (index == 0)
		index = 1;
	num_level = 2 * index;
	per_level = (uint64_t) 1 << index;
	for (level = 1; level < num_level; level++) {
		L.kind = VH_BUTTERFLY;
		L.first = g->count;
		L.n = per_level;
		L.a = g->count - per_level;	/* the level before */
		L.half = 0;
		L.shift = level > num_level / 2 ? level - num_level / 2 : index - level;
		vh_run(g, &L);
	}
}

static uint64_t vh_num_xi(uint64_t index)
{
	return ((uint64_t) 1 << index) * (index + 1) * index;
}

static void vh_xi_graph(struct vh_graph *g, uint64_t index)
{
	/* what is left to build, the top first: (index, kind of graph), the
	 * kinds of one Xi graph pushed 4 to 0 so that 0 comes first */
	struct { uint64_t index; int graph; } stack[256];
	struct vh_loop L;
	int top = 0, k;

	for (k = 4; k >= 0; k--) {
		stack[top].index = index;
		stack[top++].graph = k;
	}
	L.kind = VH_SOURCES;
	L.first = g->count;
	L.n = (uint64_t) 1 << index;
	L.a = L.half = L.shift = 0;
	vh_run(g, &L);
	if (index == 1) {
		vh_butterfly(g, index);
		return;
	}

	while (top > 0) {
		uint64_t n;
		int graph;

		top--;
		index = stack[top].index;
		graph = stack[top].graph;
		n = (uint64_t) 1 << index;

		L.first = g->count;
		L.half = n >> 1;
		L.n = n >> 1;
		L.shift = 0;
		if (graph == 0) {
			L.kind = VH_TWO_PARENTS;
			L.a = g->count - n;
		} else if (graph <= 3) {
			/* the halves of the two Xi graphs and the second
			 * butterfly: a node per node of the level before */
			L.kind = VH_ONE_PARENT;
			L.a = 0;
		} else {
			L.kind = VH_PAIRS;
			L.a = g->count + n - vh_num_xi(index);
		}
		vh_run(g, &L);

		if (graph == 0 || graph == 3 || ((graph == 1 || graph == 2) && index == 2))
			vh_butterfly(g, index - 1);
		else if (graph == 1 || graph == 2) {
			/* its inner Xi graph comes next */
			for (k = 4; k >= 0; k--) {
				stack[top].index = index - 1;
				stack[top++].graph = k;
			}
		}
	}
}

/* build the data file's contents (VH_DATA_SIZE bytes), with threads threads */
void verthash_generate(unsigned char *data, int threads)
{
	struct vh_graph g;
	int log2 = 0;
	uint64_t n;

	g.data = data;
	g.threads = threads;
	for (n = VH_NODES; n > 1; n >>= 1)
		log2++;
	g.pow2 = (uint64_t) 1 << (log2 + 1);
	g.count = g.pow2;
	sha3_256_short(g.pk, "Verthash Proof-of-Space Datafile", 32);
	vh_xi_graph(&g, VH_GRAPH_INDEX);
}

/* ------------------------------------------------------------------------
 * Memory for the data file: read at random, 4096 times a hash, so it goes
 * on huge pages if the system has some reserved (Linux hugetlbfs), else on
 * transparent huge pages (Linux), for fewer TLB misses.
 */

enum { VH_MEM_NONE, VH_MEM_HUGETLB, VH_MEM_MMAP, VH_MEM_WIN, VH_MEM_MALLOC };
static void *vh_map;			/* what to unmap or free */
static size_t vh_map_len;

#define VH_HUGE_PAGE	((size_t) 2 << 20)

static unsigned char *vh_alloc(void)
{
	size_t len = (size_t) VH_DATA_SIZE;

	if ((uint64_t) len != VH_DATA_SIZE)
		return NULL;		/* no room in 32 bits */
#if defined(__linux__) && defined(MAP_HUGETLB)
	vh_map_len = (len + VH_HUGE_PAGE - 1) & ~(VH_HUGE_PAGE - 1);
	vh_map = mmap(NULL, vh_map_len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (vh_map != MAP_FAILED) {
		vh_alloc_kind = VH_MEM_HUGETLB;
		return vh_map;
	}
#endif
#if defined(_WIN32)
	vh_map = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	vh_map_len = len;
	if (vh_map) {
		vh_alloc_kind = VH_MEM_WIN;
		return vh_map;
	}
#elif defined(MAP_ANONYMOUS)
	/* a whole number of aligned huge pages inside, for transparent ones */
	vh_map_len = len + VH_HUGE_PAGE;
	vh_map = mmap(NULL, vh_map_len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (vh_map != MAP_FAILED) {
		unsigned char *p = (unsigned char *) (((uintptr_t) vh_map + VH_HUGE_PAGE - 1)
						      & ~(uintptr_t) (VH_HUGE_PAGE - 1));
		vh_alloc_kind = VH_MEM_MMAP;
#ifdef MADV_HUGEPAGE
		madvise(p, len, MADV_HUGEPAGE);
#endif
		return p;
	}
#endif
	vh_map = malloc(len);
	vh_map_len = len;
	if (vh_map)
		vh_alloc_kind = VH_MEM_MALLOC;
	return vh_map;
}

/* drop the data file from memory */
void verthash_free(void)
{
	switch (vh_alloc_kind) {
#ifdef _WIN32
	case VH_MEM_WIN:
		VirtualFree(vh_map, 0, MEM_RELEASE);
		break;
#else
	case VH_MEM_HUGETLB:
	case VH_MEM_MMAP:
		munmap(vh_map, vh_map_len);
		break;
#endif
	case VH_MEM_MALLOC:
		free(vh_map);
		break;
	}
	vh_alloc_kind = VH_MEM_NONE;
	vh_map = NULL;
	vh_data = NULL;
}

/* is data what the data file must be? */
static bool vh_data_ok(const unsigned char *data)
{
	unsigned char hash[32];

	sha256_hash(hash, data, (size_t) VH_DATA_SIZE);
	return !memcmp(hash, vh_data_sha256, 32);
}

static double vh_seconds_since(const struct timeval *start)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return (now.tv_sec - start->tv_sec) + (now.tv_usec - start->tv_usec) * 1e-6;
}

/*
 * Read the data file. 1: loaded (and right); 0: there is no such file;
 * -1: it is not the data file, or there is not the memory.
 */
int verthash_load(const char *path)
{
	const size_t size = (size_t) VH_DATA_SIZE;
	struct timeval start;
	unsigned char *data;
	size_t got = 0;
	bool size_ok;
	FILE *f;

	f = fopen(path, "rb");
	if (!f) {
		if (errno == ENOENT)
			return 0;
		applog(LOG_ERR, "Verthash: cannot read %s: %s", path, strerror(errno));
		return -1;
	}
	gettimeofday(&start, NULL);
	verthash_free();
	data = vh_alloc();
	if (!data) {
		fclose(f);
		applog(LOG_ERR, "Verthash: not enough memory for the data file (%u MiB)",
		       (unsigned) (VH_DATA_SIZE >> 20));
		return -1;
	}
	while (got < size) {
		size_t n = fread(data + got, 1, size - got < (64 << 20) ? size - got : (64 << 20), f);

		if (!n)
			break;
		got += n;
	}
	size_ok = got == size && fgetc(f) == EOF;
	fclose(f);
	if (!size_ok || !vh_data_ok(data)) {
		applog(LOG_ERR, "Verthash: %s is not the data file (%s): delete it, and the miner will make a new one",
		       path, size_ok ? "its contents are wrong" : "its size is wrong");
		verthash_free();
		return -1;
	}
	vh_data = data;
	applog(LOG_INFO, "Verthash: read and checked %s in %.1f s", path, vh_seconds_since(&start));
	return 1;
}

/* Build the data file in memory (with threads threads), check it, and save
 * it as path (unless path is NULL) for next time: 1. (Saving is not needed:
 * 1 if it fails.) 0: not enough memory; -1: the data built is wrong. */
int verthash_create(const char *path, int threads)
{
	struct timeval start;
	unsigned char *data;
	char *tmp;

	gettimeofday(&start, NULL);
	verthash_free();
	data = vh_alloc();
	if (!data) {
		applog(LOG_ERR, "Verthash: not enough memory for the data file (%u MiB)",
		       (unsigned) (VH_DATA_SIZE >> 20));
		return 0;
	}
	verthash_generate(data, threads);
	if (!vh_data_ok(data)) {
		applog(LOG_ERR, "Verthash: the data built is wrong (a bug, or bad memory)");
		verthash_free();
		return -1;
	}
	vh_data = data;
	applog(LOG_INFO, "Verthash: built the data in %.1f s", vh_seconds_since(&start));
	if (!path)
		return 1;

	/* written whole under another name, then renamed: an interrupted write
	 * leaves no bad data file behind */
	tmp = malloc(strlen(path) + 5);
	if (tmp) {
		FILE *f;
		bool ok;

		sprintf(tmp, "%s.tmp", path);
		f = fopen(tmp, "wb");
		ok = f && fwrite(data, 1, (size_t) VH_DATA_SIZE, f) == (size_t) VH_DATA_SIZE;
		if (f && fclose(f))
			ok = false;
		if (ok && !rename(tmp, path))
			applog(LOG_INFO, "Verthash: saved the data as %s", path);
		else {
			applog(LOG_WARNING, "Verthash: could not save the data as %s (%s): it will be built again next time",
			       path, strerror(errno));
			remove(tmp);
		}
		free(tmp);
	}
	return 1;
}

/*
 * Get the data file for mining: path if given (built there if missing);
 * else verthash.dat in the current directory, or Vertcoin Core's (in its
 * data directory), or else built (with threads threads) and saved as
 * verthash.dat.
 */
bool verthash_setup(const char *path, int threads)
{
	char core[1024] = "";
	const char *home;
	int r;

	if (path) {
		r = verthash_load(path);
		if (r == 0) {
			applog(LOG_INFO, "Verthash: no %s: building it, which can take a minute", path);
			return verthash_create(path, threads) > 0;
		}
		return r > 0;
	}
	r = verthash_load("verthash.dat");
	if (r != 0)
		return r > 0;
#ifdef _WIN32
	home = getenv("APPDATA");
	if (home)
		snprintf(core, sizeof(core), "%s\\Vertcoin\\verthash.dat", home);
#elif defined(__APPLE__)
	home = getenv("HOME");
	if (home)
		snprintf(core, sizeof(core), "%s/Library/Application Support/Vertcoin/verthash.dat", home);
#else
	home = getenv("HOME");
	if (home)
		snprintf(core, sizeof(core), "%s/.vertcoin/verthash.dat", home);
#endif
	if (*core && (r = verthash_load(core)) != 0)
		return r > 0;
	applog(LOG_INFO, "Verthash: no verthash.dat here%s: building it, which can take a minute",
	       *core ? " or in Vertcoin Core's data directory" : "");
	return verthash_create("verthash.dat", threads) > 0;
}

/* ------------------------------------------------------------------------
 * The hash, of several headers at once (lanes): each hash's reads depend
 * on what it read before, but the lanes' reads can overlap.
 */

#define VH_LANES 4

/* FNV-1a, one word at a time */
static inline uint32_t fnv1a(uint32_t a, uint32_t b)
{
	return (a ^ b) * 0x1000193;
}

/* the first block of each of the 8 SHA3-512s: the header's first 72 bytes,
 * with 1 to 8 added to its first byte; the nonce is in the second block */
struct vh_midstate {
	uint64_t s[VH_N_ITER][25];
};

static void vh_prehash(struct vh_midstate *m, const unsigned char *header)
{
	unsigned char h[72];
	int i;

	memcpy(h, header, 72);
	for (i = 0; i < VH_N_ITER; i++) {
		h[0]++;
		memset(m->s[i], 0, sizeof(m->s[i]));
		keccak_absorb(m->s[i], h, 72);
		keccakf1600(m->s[i]);
	}
}

/* lanes headers (80 bytes, differing only from byte 72 on) to their hashes,
 * as 8 little-endian words */
static inline void vh_hash_lanes(uint32_t hash[][8], const unsigned char (*header)[80],
				 const struct vh_midstate *mid, const int lanes)
{
	const uint32_t mdiv = (uint32_t) ((VH_DATA_SIZE - VH_HASH_SIZE) / VH_ALIGN + 1);
	const unsigned char *data = vh_data;
	uint32_t p0[VH_LANES][VH_N_SUBSET], acc[VH_LANES];
	uint64_t s[25];
	int l, i, j;

	for (l = 0; l < lanes; l++) {
		unsigned char p1[32];

		/* SHA3-256 of the header: the hash to be */
		sha3_256_short(p1, header[l], VH_HEADER_SIZE);
		for (j = 0; j < 8; j++)
			hash[l][j] = le32dec(p1 + 4 * j);
		/* the 8 SHA3-512s: their second block, bytes 72 to 79 */
		for (i = 0; i < VH_N_ITER; i++) {
			memcpy(s, mid->s[i], sizeof(s));
			s[0] ^= le64dec_p(header[l] + 72);
			sha3_pad(s, 8, 72);
			keccakf1600(s);
			for (j = 0; j < 8; j++) {
				p0[l][16 * i + 2 * j] = (uint32_t) s[j];
				p0[l][16 * i + 2 * j + 1] = (uint32_t) (s[j] >> 32);
			}
		}
		acc[l] = 0x811c9dc5;
	}

	/* the reads: read x of 4096 is where p0's word x % 128, rotated by
	 * x / 128 bits, and all read so far point */
	for (i = 0; i < VH_N_INDEXES; i++) {
		const int w = i % VH_N_SUBSET, rot = i / VH_N_SUBSET;

		for (l = 0; l < lanes; l++) {
			const uint32_t seek = rot ? (p0[l][w] << rot) | (p0[l][w] >> (32 - rot))
						  : p0[l][w];
			const unsigned char *v = data
				+ (size_t) (fnv1a(seek, acc[l]) % mdiv) * VH_ALIGN;
			uint32_t a = acc[l];

			for (j = 0; j < 8; j++) {
				const uint32_t x = le32dec(v + 4 * j);

				hash[l][j] = fnv1a(hash[l][j], x);
				a = fnv1a(a, x);
			}
			acc[l] = a;
		}
	}
}

/* the hash of an 80-byte block header (needs the data file) */
void verthash_hash(void *output, const void *input)
{
	unsigned char header[1][80];
	struct vh_midstate mid;
	uint32_t hash[1][8];
	int j;

	if (!vh_data) {
		memset(output, 0xff, 32);	/* never a share */
		return;
	}
	memcpy(header[0], input, 80);
	vh_prehash(&mid, header[0]);
	vh_hash_lanes(hash, (const unsigned char (*)[80]) header, &mid, 1);
	for (j = 0; j < 8; j++)
		le32enc((unsigned char *) output + 4 * j, hash[0][j]);
}

int scanhash_verthash(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
		      uint32_t max_nonce, uint64_t *hashes_done)
{
	unsigned char header[VH_LANES][80];
	struct vh_midstate mid;
	uint32_t hash[VH_LANES][8];
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t n = first_nonce;
	int l, k;

	if (!vh_data) {
		*hashes_done = 0;
		return 0;
	}
	/* pdata holds the header as big-endian words */
	for (k = 0; k < 19; k++)
		be32enc(header[0] + 4 * k, pdata[k]);
	for (l = 1; l < VH_LANES; l++)
		memcpy(header[l], header[0], 76);
	vh_prehash(&mid, header[0]);

	for (;;) {
		for (l = 0; l < VH_LANES; l++)
			be32enc(header[l] + 76, n + l);
		vh_hash_lanes(hash, (const unsigned char (*)[80]) header, &mid, VH_LANES);
		for (l = 0; l < VH_LANES; l++) {
			if (unlikely(hash[l][7] <= Htarg) && fulltest(hash[l], ptarget)) {
				pdata[19] = n + l;
				*hashes_done = (uint64_t) (n + l - first_nonce) + 1;
				return 1;
			}
		}
		n += VH_LANES;
		/* (n < first_nonce: it went round) */
		if (n > max_nonce || n < first_nonce || work_restart[thr_id].restart)
			break;
	}
	*hashes_done = (uint64_t) (n - first_nonce);
	pdata[19] = n - 1;
	return 0;
}
