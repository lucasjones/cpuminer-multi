/*
 * yescrypt 0.5 and yespower 1.0 proofs of work, computed by Openwall's
 * yespower code (yespower/): this file picks the parameters.
 *
 *   yescrypt     0.5  N=2048  r=8   key: the block header  Myriad, GlobalBoost-Y
 *   yescryptr8   0.5  N=2048  r=8   key: "Client Key"
 *   yescryptr16  0.5  N=4096  r=16  key: "Client Key"
 *   yescryptr32  0.5  N=4096  r=32  key: "WaviBanana"
 *   yespower     1.0  N=2048  r=32  no key (--param-n, -r, -key change them)
 *   yespowerr16  1.0  N=4096  r=16  no key                 Yenten
 *
 * (The "key" is yespower's personalization string. yescrypt 0.5 used the
 * salt, which is the block header, where yespower has one; so does
 * cpuminer-opt's yescrypt.)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdio.h>
#include <string.h>

#include "yespower/yespower.h"

static yespower_params_t yp_params[] = {
	[YESCRYPT] =     { YESPOWER_0_5, 2048, 8, NULL, 0 },
	[YESCRYPT_R8] =  { YESPOWER_0_5, 2048, 8, (const uint8_t *) "Client Key", 10 },
	[YESCRYPT_R16] = { YESPOWER_0_5, 4096, 16, (const uint8_t *) "Client Key", 10 },
	[YESCRYPT_R32] = { YESPOWER_0_5, 4096, 32, (const uint8_t *) "WaviBanana", 10 },
	[YESPOWER] =     { YESPOWER_1_0, 2048, 32, NULL, 0 },
	[YESPOWER_R16] = { YESPOWER_1_0, 4096, 16, NULL, 0 },
};

/*
 * Change a variant's parameters (--param-n, --param-r, --param-key), before
 * mining starts: N 0 or r 0 keep the variant's, key NULL keeps its key.
 * False if they are out of yespower's range.
 */
bool yespower_set_params(int variant, uint32_t N, uint32_t r, const char *key)
{
	yespower_params_t *p = &yp_params[variant];

	if (N && (N < 1024 || N > 512 * 1024 || (N & (N - 1))))
		return false;
	if (r && (r < 8 || r > 32))
		return false;
	if (N)
		p->N = N;
	if (r)
		p->r = r;
	if (key) {
		p->pers = (const uint8_t *) key;
		p->perslen = strlen(key);
	}
	return true;
}

/* the parameters in words, for the log */
void yespower_describe(int variant, char *buf, size_t len)
{
	const yespower_params_t *p = &yp_params[variant];

	if (p->pers)
		snprintf(buf, len, "version %s, N=%u, r=%u, key \"%.*s%s\"",
			 p->version == YESPOWER_0_5 ? "0.5" : "1.0", p->N, p->r,
			 (int) (p->perslen < 60 ? p->perslen : 60), (const char *) p->pers,
			 p->perslen > 60 ? "..." : "");
	else
		snprintf(buf, len, "version %s, N=%u, r=%u, %s",
			 p->version == YESPOWER_0_5 ? "0.5" : "1.0", p->N, p->r,
			 variant == YESCRYPT ? "the header as key" : "no key");
}

/* the hash of an 80-byte block header */
static int yp_hash(uint8_t out[32], const uint8_t *header, int variant)
{
	yespower_params_t p = yp_params[variant];

	/* yescrypt without a key: the header is */
	if (variant == YESCRYPT && !p.pers) {
		p.pers = header;
		p.perslen = 80;
	}
	return yespower_tls(header, 80, &p, (yespower_binary_t *) out);
}

void yespower_hash(void *output, const void *input, int variant)
{
	yp_hash(output, input, variant);
}

int scanhash_yespower(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	int variant, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint8_t header[80], out[32];
	uint32_t hash[8];
	int k;

	/* pdata holds the header as big-endian words */
	for (k = 0; k < 19; k++)
		be32enc(header + 4 * k, pdata[k]);

	do {
		pdata[19] = ++n;
		be32enc(header + 76, n);
		if (yp_hash(out, header, variant)) {
			applog(LOG_ERR, "yespower: out of memory");
			break;
		}
		hash[7] = le32dec(out + 28);
		if (hash[7] <= Htarg) {
			for (k = 0; k < 7; k++)
				hash[k] = le32dec(out + 4 * k);
			if (fulltest(hash, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
