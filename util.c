/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include "cpuminer-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <jansson.h>
#include <curl/curl.h>
#include <time.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#include "compat.h"
#include "miner.h"
#include "elist.h"

struct data_buffer {
	void		*buf;
	size_t		len;
	size_t		allocated;
};

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;
		
		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		char *f;
		int len;
		time_t now;
		struct tm tm, *tm_p;

		time(&now);

		pthread_mutex_lock(&applog_lock);
		tm_p = localtime(&now);
		memcpy(&tm, tm_p, sizeof(tm));
		pthread_mutex_unlock(&applog_lock);

		len = 40 + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d] %s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			fmt);
		pthread_mutex_lock(&applog_lock);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
		fflush(stderr);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

/* No JSON-RPC reply comes anywhere near this (a block template for a 32 MB
 * block is about 70 MB of JSON); a server sending more is broken or hostile. */
#define MAX_RESPONSE_SIZE ((size_t) 256 * 1024 * 1024)

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = user_data;
	size_t len = size * nmemb;

	if (len > MAX_RESPONSE_SIZE - db->len) {
		applog(LOG_ERR, "HTTP reply larger than %zu MB, giving up",
		       MAX_RESPONSE_SIZE >> 20);
		return 0;	/* makes curl fail the transfer */
	}
	/* Grow geometrically: growing the buffer to the exact size for every
	 * chunk copied a multi-megabyte block template over and over (O(n^2)). */
	if (db->len + len + 1 > db->allocated) {
		size_t newalloc = db->allocated ? db->allocated : 16384;
		void *newmem;

		while (newalloc < db->len + len + 1)
			newalloc *= 2;
		newmem = realloc(db->buf, newalloc);
		if (!newmem)
			return 0;
		db->buf = newmem;
		db->allocated = newalloc;
	}
	memcpy((char *) db->buf + db->len, ptr, len);
	db->len += len;
	((char *) db->buf)[db->len] = '\0';

	return len;
}

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct header_info *hi = user_data;
	size_t remlen, slen, ptrlen = size * nmemb;
	char *rem, *val = NULL, *key = NULL;
	void *tmp;

	val = calloc(1, ptrlen);
	key = calloc(1, ptrlen);
	if (!key || !val)
		goto out;

	tmp = memchr(ptr, ':', ptrlen);
	if (!tmp || (tmp == ptr))	/* skip empty keys / blanks */
		goto out;
	slen = tmp - ptr;
	if ((slen + 1) == ptrlen)	/* skip key w/ no value */
		goto out;
	memcpy(key, ptr, slen);		/* store & nul term key */
	key[slen] = 0;

	rem = ptr + slen + 1;		/* trim value's leading whitespace */
	remlen = ptrlen - slen - 1;
	while ((remlen > 0) && (isspace(*rem))) {
		remlen--;
		rem++;
	}

	memcpy(val, rem, remlen);	/* store value, trim trailing ws */
	val[remlen] = 0;
	while ((*val) && (isspace(val[strlen(val) - 1]))) {
		val[strlen(val) - 1] = 0;
	}

	if (!strcasecmp("X-Long-Polling", key)) {
		hi->lp_path = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Reject-Reason", key)) {
		hi->reason = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Stratum", key)) {
		hi->stratum_url = val;	/* steal memory reference */
		val = NULL;
	}

out:
	free(key);
	free(val);
	return ptrlen;
}

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd,
	curlsocktype purpose)
{
	int keepalive = 1;
	int tcp_keepcnt = 3;
	int tcp_keepidle = 50;
	int tcp_keepintvl = 50;

#ifndef _WIN32
	if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive))))
		return 1;
#ifdef __linux
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
		&tcp_keepcnt, sizeof(tcp_keepcnt))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
		&tcp_keepidle, sizeof(tcp_keepidle))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
	if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __APPLE_CC__ */
#else /* _WIN32 */
	struct tcp_keepalive vals;
	vals.onoff = 1;
	vals.keepalivetime = tcp_keepidle * 1000;
	vals.keepaliveinterval = tcp_keepintvl * 1000;
	DWORD outputBytes;
	if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals),
		NULL, 0, &outputBytes, NULL, NULL)))
		return 1;
#endif /* _WIN32 */

	return 0;
}
#endif

/* Log a JSON-RPC error object: bitcoind-style {"code": n, "message": s}, or
 * whatever else the server sent. */
static void log_rpc_error(const json_t *err_val)
{
	const char *msg = json_string_value(json_object_get(err_val, "message"));
	json_t *code = json_object_get(err_val, "code");

	if (msg && json_is_integer(code))
		applog(LOG_ERR, "JSON-RPC call failed: %s (code %d)", msg,
		       (int) json_integer_value(code));
	else if (msg)
		applog(LOG_ERR, "JSON-RPC call failed: %s", msg);
	else {
		char *s = json_dumps(err_val, JSON_INDENT(3) | JSON_ENCODE_ANY);
		applog(LOG_ERR, "JSON-RPC call failed: %s", s ? s : "(unknown reason)");
		free(s);
	}
}

json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req,
		      int *curl_err, int flags)
{
	json_t *val = NULL, *err_val, *res_val;
	int rc;
	long http_rc = 0;
	struct data_buffer all_data = {0};
	json_error_t err;
	struct curl_slist *headers = NULL;
	char curl_err_str[CURL_ERROR_SIZE];
	long timeout = (flags & JSON_RPC_LONGPOLL) ? opt_timeout : 30;
	struct header_info hi = {0};
	bool quiet;

	/* it is assumed that 'curl' is freshly [re]initialized at this pt */

	curl_err_str[0] = '\0';
	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if (opt_cert)
		curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	if (opt_redirect)
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, resp_hdr_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hi);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	if (flags & JSON_RPC_LONGPOLL)
		curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
	/* curl sends the body, and its Content-Length, itself */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, rpc_req);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) strlen(rpc_req));

	if (opt_protocol)
		applog(LOG_DEBUG, "JSON protocol request:\n%s\n", rpc_req);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
	headers = curl_slist_append(headers, "X-Mining-Extensions: midstate");
	/* no "Expect: 100-continue" round trip before big requests (blocks) */
	headers = curl_slist_append(headers, "Expect:");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
	if (curl_err != NULL)
		*curl_err = rc;
	if (rc) {
		if (!((flags & JSON_RPC_LONGPOLL) && rc == CURLE_OPERATION_TIMEDOUT))
			applog(LOG_ERR, "HTTP request failed: %s",
			       curl_err_str[0] ? curl_err_str : curl_easy_strerror(rc));
		goto err_out;
	}

	/* A 404 is how a server says it does not know the method; callers
	 * that probe for a method (getblocktemplate) pass JSON_RPC_QUIET_404
	 * and see *curl_err == CURLE_OK with a NULL result. */
	quiet = (flags & JSON_RPC_QUIET_404) && http_rc == 404;
	if (http_rc >= 400 && curl_err != NULL && !quiet)
		*curl_err = CURLE_HTTP_RETURNED_ERROR;

	if (all_data.buf)
		val = JSON_LOADS(all_data.buf, &err);
	if (!val) {
		if (http_rc >= 400) {
			if (!quiet)
				applog(LOG_ERR, "HTTP request failed: HTTP status %ld%s", http_rc,
				       http_rc == 401 ? " (check the user name and password)" : "");
		} else if (!all_data.buf)
			applog(LOG_ERR, "Empty data received in json_rpc_call.");
		else
			applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}

	if (opt_protocol) {
		char *s = json_dumps(val, JSON_INDENT(3));
		applog(LOG_DEBUG, "JSON protocol response:\n%s", s);
		free(s);
	}

	/* JSON-RPC valid response returns a 'result' and a null 'error'.
	 * Servers report errors as an HTTP error status with such a reply
	 * (the reason used to be thrown away with the reply). */
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	if (!(flags & JSON_RPC_IGNOREERR) &&
	    (!res_val || http_rc >= 400 || (err_val && !json_is_null(err_val)))) {
		if (!quiet) {
			if (err_val && !json_is_null(err_val))
				log_rpc_error(err_val);
			else
				applog(LOG_ERR, "JSON-RPC call failed: %s",
				       http_rc >= 400 ? "HTTP error status" : "no result");
		}
		goto err_out;
	}

	if (http_rc < 400) {
		/* If X-Stratum was found, activate Stratum */
		if (want_stratum && hi.stratum_url &&
		    !strncasecmp(hi.stratum_url, "stratum+tcp://", 14)) {
			have_stratum = true;
			tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
			hi.stratum_url = NULL;
		}

		/* If X-Long-Polling was found, activate long polling (not for
		 * getblocktemplate: a template says where to long poll) */
		if (!have_longpoll && want_longpoll && hi.lp_path &&
		    (jsonrpc_2 || !have_gbt) && !have_stratum) {
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, hi.lp_path);
			hi.lp_path = NULL;
		}
	}

	if (hi.reason)
		json_object_set_new(val, "reject-reason", json_string(hi.reason));

	goto out;

err_out:
	if (val)
		json_decref(val);
	val = NULL;
out:
	free(hi.lp_path);
	free(hi.reason);
	free(hi.stratum_url);
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;
}

/* write 2 * len hex digits and a terminating NUL to s */
void bin2hex_buf(char *s, const unsigned char *p, size_t len)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		s[2 * i] = digits[p[i] >> 4];
		s[2 * i + 1] = digits[p[i] & 0xf];
	}
	s[2 * len] = '\0';
}

char *bin2hex(const unsigned char *p, size_t len)
{
	char *s = malloc((len * 2) + 1);
	if (s)
		bin2hex_buf(s, p, len);
	return s;
}

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Decode exactly len bytes of hex; fails on anything that is not a hex digit
 * (strtol() used to accept signs and spaces) or on a string of any other
 * length. */
bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	while (*hexstr && len) {
		int hi, lo;

		if (!hexstr[1]) {
			applog(LOG_ERR, "hex2bin str truncated");
			return false;
		}
		hi = hex_digit(hexstr[0]);
		lo = hex_digit(hexstr[1]);
		if (hi < 0 || lo < 0) {
			applog(LOG_ERR, "hex2bin failed on '%.2s'", hexstr);
			return false;
		}
		*p++ = (unsigned char) (hi << 4 | lo);
		hexstr += 2;
		len--;
	}

	return len == 0 && *hexstr == 0;
}

/* true if s is a string of hex digits */
static bool is_hex(const char *s)
{
	for (; *s; s++)
		if (hex_digit(*s) < 0)
			return false;
	return true;
}

void memrev(unsigned char *p, size_t len)
{
	unsigned char c, *q;

	if (!len)
		return;
	for (q = p + len - 1; p < q; p++, q--) {
		c = *p;
		*p = *q;
		*q = c;
	}
}

/* Bitcoin's CompactSize integer encoding; returns the length (1-9 bytes). */
int varint_encode(unsigned char *p, uint64_t n)
{
	int i, len;

	if (n < 0xfd) {
		p[0] = (unsigned char) n;
		return 1;
	}
	if (n <= 0xffff) {
		p[0] = 0xfd;
		len = 2;
	} else if (n <= 0xffffffff) {
		p[0] = 0xfe;
		len = 4;
	} else {
		p[0] = 0xff;
		len = 8;
	}
	for (i = 1; i <= len; i++, n >>= 8)
		p[i] = n & 0xff;
	return len + 1;
}

static const char b58digits[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Decode base58 into exactly binsz bytes; leading '1's are zero bytes. */
static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char num[64];
	size_t i, j, zeros = 0;

	if (binsz > sizeof(num))
		return false;
	memset(num, 0, binsz);
	while (b58[zeros] == '1')
		zeros++;
	for (i = zeros; b58[i]; i++) {
		const char *d = strchr(b58digits, b58[i]);
		unsigned int carry;

		if (!d)
			return false;
		carry = (unsigned int) (d - b58digits);
		for (j = binsz; j--; ) {
			carry += 58u * num[j];
			num[j] = carry & 0xff;
			carry >>= 8;
		}
		if (carry)
			return false;	/* does not fit in binsz bytes */
	}
	for (j = 0; j < binsz && !num[j]; j++)
		;
	if (j != zeros)
		return false;	/* not the canonical encoding of binsz bytes */
	memcpy(bin, num, binsz);
	return true;
}

static uint32_t bech32_polymod_step(uint32_t pre)
{
	uint8_t b = pre >> 25;

	return ((pre & 0x1ffffff) << 5) ^
		(-((b >> 0) & 1) & 0x3b6a57b2UL) ^
		(-((b >> 1) & 1) & 0x26508e6dUL) ^
		(-((b >> 2) & 1) & 0x1ea119faUL) ^
		(-((b >> 3) & 1) & 0x3d4233ddUL) ^
		(-((b >> 4) & 1) & 0x2a1462b3UL);
}

/* A segwit address (BIP 173 bech32 for witness version 0, BIP 350 bech32m
 * for versions 1-16, any human-readable part) to its output script. */
static size_t segwit_addr_to_script(unsigned char *out, size_t outsz,
				    const char *addr)
{
	static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	const size_t len = strlen(addr);
	const char *sep = strrchr(addr, '1');
	unsigned char v[90], prog[40];
	size_t hrp_len, nv, i, plen = 0;
	uint32_t chk = 1, acc = 0;
	int lower = 0, upper = 0, bits = 0, ver;

	if (len < 8 || len > 90 || !sep || sep == addr)
		return 0;
	hrp_len = sep - addr;
	nv = len - hrp_len - 1;		/* version, program, 6 checksum chars */
	if (nv < 7)
		return 0;
	for (i = 0; i < len; i++) {
		if (addr[i] < 33 || addr[i] > 126)
			return 0;
		lower |= addr[i] >= 'a' && addr[i] <= 'z';
		upper |= addr[i] >= 'A' && addr[i] <= 'Z';
	}
	if (lower && upper)
		return 0;
	for (i = 0; i < hrp_len; i++)
		chk = bech32_polymod_step(chk) ^ (tolower((unsigned char) addr[i]) >> 5);
	chk = bech32_polymod_step(chk);
	for (i = 0; i < hrp_len; i++)
		chk = bech32_polymod_step(chk) ^ (tolower((unsigned char) addr[i]) & 0x1f);
	for (i = 0; i < nv; i++) {
		const char *d = strchr(charset, tolower((unsigned char) sep[1 + i]));
		if (!d)
			return 0;
		v[i] = (unsigned char) (d - charset);
		chk = bech32_polymod_step(chk) ^ v[i];
	}
	ver = v[0];
	if (ver > 16 || chk != (ver == 0 ? 1 : 0x2bc830a3))
		return 0;
	/* regroup the program from 5-bit to 8-bit groups */
	for (i = 1; i < nv - 6; i++) {
		acc = ((acc << 5) | v[i]) & 0xfff;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			if (plen == sizeof(prog))
				return 0;
			prog[plen++] = (acc >> bits) & 0xff;
		}
	}
	if (bits >= 5 || (acc & ((1u << bits) - 1)))
		return 0;	/* bad padding */
	if (plen < 2 || (ver == 0 && plen != 20 && plen != 32) || outsz < plen + 2)
		return 0;
	out[0] = ver ? 0x50 + ver : 0;	/* OP_0, OP_1 .. OP_16 */
	out[1] = (unsigned char) plen;
	memcpy(out + 2, prog, plen);
	return plen + 2;
}

/*
 * The output script paying to a Bitcoin-style address, decoded locally:
 * base58check pay-to-pubkey-hash / pay-to-script-hash, or segwit.
 * Base58 version bytes are per coin, so this only knows the script-hash
 * versions of well-known coins; ask the coin's node (validateaddress)
 * when possible. Returns the script length, or 0 if addr is not valid.
 */
size_t address_to_script(unsigned char *out, size_t outsz, const char *addr)
{
	/* BTC, BTC testnet (also DOGE testnet), LTC, LTC testnet, DOGE,
	 * DASH, DASH testnet, DGB, DGB testnet */
	static const unsigned char p2sh_versions[] = {
		5, 196, 50, 58, 22, 16, 19, 63, 140
	};
	unsigned char bin[25], hash[32];

	if (!b58dec(bin, sizeof(bin), addr))
		return segwit_addr_to_script(out, outsz, addr);
	sha256d(hash, bin, 21);
	if (memcmp(hash, bin + 21, 4))
		return 0;
	if (memchr(p2sh_versions, bin[0], sizeof(p2sh_versions))) {
		if (outsz < 23)
			return 0;
		out[0] = 0xa9;		/* OP_HASH160 */
		out[1] = 0x14;		/* push 20 bytes */
		memcpy(out + 2, bin + 1, 20);
		out[22] = 0x87;		/* OP_EQUAL */
		return 23;
	}
	if (outsz < 25)
		return 0;
	out[0] = 0x76;			/* OP_DUP */
	out[1] = 0xa9;			/* OP_HASH160 */
	out[2] = 0x14;			/* push 20 bytes */
	memcpy(out + 3, bin + 1, 20);
	out[23] = 0x88;			/* OP_EQUALVERIFY */
	out[24] = 0xac;			/* OP_CHECKSIG */
	return 25;
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;
	bool rc = true;
	
	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		uint32_t hash_be[8], target_be[8];
		char *hash_str, *target_str;
		
		for (i = 0; i < 8; i++) {
			be32enc(hash_be + i, hash[7 - i]);
			be32enc(target_be + i, target[7 - i]);
		}
		hash_str = bin2hex((unsigned char *)hash_be, 32);
		target_str = bin2hex((unsigned char *)target_be, 32);

		applog(LOG_DEBUG, "DEBUG: %s\nHash:   %s\nTarget: %s",
			rc ? "hash <= target"
			   : "hash > target (false positive)",
			hash_str,
			target_str);

		free(hash_str);
		free(target_str);
	}

	return rc;
}

void diff_to_target(uint32_t *target, double diff)
{
	uint64_t m;
	int k;

	/* callers reject diff <= 0; keep NaN or absurdly small values from
	 * turning into an undefined float-to-integer conversion */
	if (!(diff >= 4294901760.0 / 18446744073709551615.0)) {
		memset(target, 0xff, 32);
		return;
	}
	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;
	m = 4294901760.0 / diff;
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k] = (uint32_t)m;
		target[k + 1] = (uint32_t)(m >> 32);
	}
}

#ifdef _WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

/* how long to wait for room in a full socket send buffer */
#define STRATUM_SEND_TIMEOUT 30

/* Send s and a newline (appended in place: s must have room for one more
 * character; the terminating NUL is restored before returning). */
static bool send_line(curl_socket_t sock, char *s)
{
	size_t len, sent = 0;
	time_t start = time(NULL);
	bool ret = true;

	len = strlen(s);
	s[len++] = '\n';

	while (sent < len) {
		struct timeval timeout = {1, 0};
		ssize_t n;
		fd_set wd;

		/* the socket is non-blocking: wait until the kernel takes more */
		FD_ZERO(&wd);
		FD_SET(sock, &wd);
		n = select(sock + 1, NULL, &wd, NULL, &timeout);
		if (n < 1) {
#ifndef _WIN32
			if (n < 0 && errno == EINTR)
				continue;
#endif
			if (n == 0 && time(NULL) - start < STRATUM_SEND_TIMEOUT)
				continue;
			ret = false;
			break;
		}
		n = send(sock, s + sent, len - sent, 0);
		if (n < 0) {
			if (!socket_blocks()) {
				ret = false;
				break;
			}
			n = 0;
		}
		sent += n;
	}

	s[len - 1] = '\0';
	return ret;
}

#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH	/* Windows */
#endif

bool stratum_send_line(struct stratum_ctx *sctx, char *s)
{
	bool ret = false;

	if (opt_protocol)
		applog(LOG_DEBUG, "> %s", s);

	pthread_mutex_lock(&sctx->sock_lock);
	/* after a disconnect sctx->sock is a closed (maybe reused) descriptor */
	if (sctx->curl) {
		ret = send_line(sctx->sock, s);
		/* Part of the line may have gone out, so the connection is
		 * unusable: shut it down, and the stratum thread (waiting in
		 * select/recv on it) sees that at once and reconnects. */
		if (!ret)
			shutdown(sctx->sock, SHUT_RDWR);
	}
	pthread_mutex_unlock(&sctx->sock_lock);

	return ret;
}

static bool socket_full(curl_socket_t sock, int timeout)
{
	struct timeval tv;
	fd_set rd;

	FD_ZERO(&rd);
	FD_SET(sock, &rd);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select(sock + 1, &rd, NULL, NULL, &tv) > 0)
		return true;
	return false;
}

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
	return strlen(sctx->sockbuf) || socket_full(sctx->sock, timeout);
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_buffer_append(struct stratum_ctx *sctx, const char *s)
{
	size_t old, new;

	old = strlen(sctx->sockbuf);
	new = old + strlen(s) + 1;
	if (new >= sctx->sockbuf_size) {
		sctx->sockbuf_size = new + (RBUFSIZE - (new % RBUFSIZE));
		sctx->sockbuf = realloc(sctx->sockbuf, sctx->sockbuf_size);
	}
	strcpy(sctx->sockbuf + old, s);
}

/* longest stratum message we accept (mining.notify with a big merkle branch
 * is a few kilobytes) */
#define STRATUM_MAX_LINE (1 << 20)

char *stratum_recv_line(struct stratum_ctx *sctx)
{
	char *sret = NULL;
	time_t rstart;

	time(&rstart);
	while (1) {
		char *line = sctx->sockbuf, *nl;
		size_t skip = 0;

		/* drop empty lines: some servers send bare newlines to keep the connection alive */
		while (line[skip] == '\n' || (line[skip] == '\r' && line[skip + 1] == '\n'))
			skip += line[skip] == '\r' ? 2 : 1;
		if (skip)
			memmove(line, line + skip, strlen(line + skip) + 1);

		nl = strchr(line, '\n');
		if (nl) {
			size_t len = nl - line;
			sret = malloc(len + 1);
			if (sret) {
				memcpy(sret, line, len);
				sret[len] = '\0';
			}
			memmove(line, nl + 1, strlen(nl + 1) + 1);
			break;
		}
		if (strlen(line) > STRATUM_MAX_LINE) {
			applog(LOG_ERR, "stratum_recv_line: line too long");
			break;
		}
		if (time(NULL) - rstart >= 60 || !socket_full(sctx->sock, 60)) {
			applog(LOG_ERR, "stratum_recv_line timed out");
			break;
		}
		{
			char s[RBUFSIZE];
			ssize_t n;

			memset(s, 0, RBUFSIZE);
			n = recv(sctx->sock, s, RECVSIZE, 0);
			if (!n) {
				applog(LOG_ERR, "stratum_recv_line failed");
				break;
			}
			if (n < 0) {
				if (!socket_blocks() || !socket_full(sctx->sock, 1)) {
					applog(LOG_ERR, "stratum_recv_line failed");
					break;
				}
			} else
				stratum_buffer_append(sctx, s);
		}
	}

	if (sret && opt_protocol)
		applog(LOG_DEBUG, "< %s", sret);
	return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr)
{
	curl_socket_t *sock = clientp;
	*sock = socket(addr->family, addr->socktype, addr->protocol);
	return *sock;
}
#endif

bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
	CURL *curl;
	curl_socket_t sock = CURL_SOCKET_BAD;
	const char *hostport;
	int rc;

	curl = curl_easy_init();
	if (!curl) {
		applog(LOG_ERR, "CURL initialization failed");
		return false;
	}

	if (url != sctx->url) {
		free(sctx->url);
		sctx->url = strdup(url);
	}
	/* curl only needs host and port: pass it as http://HOST:PORT */
	hostport = strstr(url, "://");
	hostport = hostport ? hostport + 3 : url;
	free(sctx->curl_url);
	sctx->curl_url = malloc(strlen(hostport) + 8);
	if (!sctx->curl_url) {
		curl_easy_cleanup(curl);
		return false;
	}
	sprintf(sctx->curl_url, "http://%s", hostport);

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
#if LIBCURL_VERSION_NUM >= 0x070f06
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sock);
#endif
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
		curl_easy_cleanup(curl);
		return false;
	}

#if LIBCURL_VERSION_NUM < 0x071101
	/* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
	{
		long last;

		curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &last);
		sock = (curl_socket_t) last;
	}
#endif

	/* Make the connection visible to the other threads (share submission)
	 * only now that it is up. It used to be published before connecting,
	 * so a share could be sent on a socket still being set up. */
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl)
		curl_easy_cleanup(sctx->curl);
	sctx->curl = curl;
	sctx->sock = sock;
	if (!sctx->sockbuf) {
		sctx->sockbuf = calloc(RBUFSIZE, 1);
		sctx->sockbuf_size = RBUFSIZE;
	}
	sctx->sockbuf[0] = '\0';
	sctx->conn_gen++;
	pthread_mutex_unlock(&sctx->sock_lock);

	return true;
}

void stratum_disconnect(struct stratum_ctx *sctx)
{
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl) {
		curl_easy_cleanup(sctx->curl);
		sctx->curl = NULL;
		sctx->sockbuf[0] = '\0';
	}
	pthread_mutex_unlock(&sctx->sock_lock);

	/* The next connection may come with a different extranonce1 and
	 * extranonce2 size, and job ids are only meaningful per connection:
	 * never mine a job left over from this one. */
	pthread_mutex_lock(&sctx->work_lock);
	free(sctx->job.job_id);
	sctx->job.job_id = NULL;
	free(sctx->work.job_id);
	sctx->work.job_id = NULL;
	pthread_mutex_unlock(&sctx->work_lock);
}

static const char *get_stratum_session_id(json_t *val)
{
	json_t *arr_val;
	int i, n;

	arr_val = json_array_get(val, 0);
	if (!arr_val || !json_is_array(arr_val))
		return NULL;
	n = json_array_size(arr_val);
	for (i = 0; i < n; i++) {
		const char *notify;
		json_t *arr = json_array_get(arr_val, i);

		if (!arr || !json_is_array(arr))
			break;
		notify = json_string_value(json_array_get(arr, 0));
		if (!notify)
			continue;
		if (!strcasecmp(notify, "mining.notify"))
			return json_string_value(json_array_get(arr, 1));
	}
	return NULL;
}

bool stratum_subscribe(struct stratum_ctx *sctx)
{
	char *s = NULL, *sret = NULL;
	const char *sid, *xnonce1;
	json_int_t xn2_size;
	json_t *req, *val = NULL, *res_val, *err_val;
	json_error_t err;
	bool ret = false, retry = false, answered;

	if (jsonrpc_2)
		return true;

start:
	/* try to resume the previous session; if the pool rejects that, retry
	 * once with no parameters at all (some old pools want exactly that) */
	answered = false;
	if (retry)
		req = json_pack("{s:i, s:s, s:[]}", "id", 1,
				"method", "mining.subscribe", "params");
	else if (sctx->session_id)
		req = json_pack("{s:i, s:s, s:[s, s]}", "id", 1,
				"method", "mining.subscribe",
				"params", USER_AGENT, sctx->session_id);
	else
		req = json_pack("{s:i, s:s, s:[s]}", "id", 1,
				"method", "mining.subscribe", "params", USER_AGENT);
	s = req ? json_dumps(req, 0) : NULL;
	json_decref(req);

	if (!s || !stratum_send_line(sctx, s)) {
		applog(LOG_ERR, "stratum_subscribe send failed");
		goto out;
	}

	if (!socket_full(sctx->sock, 30)) {
		applog(LOG_ERR, "stratum_subscribe timed out");
		goto out;
	}

	sret = stratum_recv_line(sctx);
	if (!sret)
		goto out;
	answered = true;

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_null(res_val) ||
	    (err_val && !json_is_null(err_val))) {
		if (opt_debug || retry) {
			char *reason = err_val ? json_dumps(err_val, JSON_INDENT(3)) : NULL;
			applog(LOG_ERR, "JSON-RPC call failed: %s",
			       reason ? reason : "(unknown reason)");
			free(reason);
		}
		goto out;
	}

	sid = get_stratum_session_id(res_val);
	if (opt_debug && !sid)
		applog(LOG_DEBUG, "Failed to get Stratum session id");
	xnonce1 = json_string_value(json_array_get(res_val, 1));
	if (!xnonce1) {
		applog(LOG_ERR, "Failed to get extranonce1");
		goto out;
	}
	xn2_size = json_integer_value(json_array_get(res_val, 2));
	if (xn2_size < 1 || xn2_size > 16) {
		applog(LOG_ERR, "Invalid extranonce2_size %.0f", (double) xn2_size);
		goto out;
	}
	if (strlen(xnonce1) % 2 || strlen(xnonce1) > 64 || !is_hex(xnonce1)) {
		applog(LOG_ERR, "Invalid extranonce1");
		goto out;
	}

	pthread_mutex_lock(&sctx->work_lock);
	free(sctx->session_id);
	free(sctx->xnonce1);
	sctx->session_id = sid ? strdup(sid) : NULL;
	sctx->xnonce1_size = strlen(xnonce1) / 2;
	sctx->xnonce1 = malloc(sctx->xnonce1_size + 1);
	if (sctx->xnonce1)
		hex2bin(sctx->xnonce1, xnonce1, sctx->xnonce1_size);
	sctx->xnonce2_size = (int) xn2_size;
	sctx->next_diff = 1.0;
	pthread_mutex_unlock(&sctx->work_lock);
	if (!sctx->xnonce1)
		goto out;

	if (opt_debug && sid)
		applog(LOG_DEBUG, "Stratum session id: %s", sid);

	ret = true;

out:
	free(s);
	s = NULL;
	if (val)
		json_decref(val);
	val = NULL;

	if (!ret && answered && !retry) {
		retry = true;
		goto start;
	}

	return ret;
}

bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
	json_t *val = NULL, *res_val, *err_val, *req;
	char *s = NULL, *sret;
	json_error_t err;
	bool ret = false;

	/* built with jansson so quotes or backslashes in credentials are escaped */
	if (jsonrpc_2)
		s = rpc2_login_req(user, pass);
	else {
		req = json_pack("{s:i, s:s, s:[s, s]}",
				"id", 2, "method", "mining.authorize",
				"params", user, pass);
		if (req)
			s = json_dumps(req, 0);
		json_decref(req);
	}
	if (!s || !stratum_send_line(sctx, s))
		goto out;

	while (1) {
		sret = stratum_recv_line(sctx);
		if (!sret)
			goto out;
		if (!stratum_handle_method(sctx, sret))
			break;
		free(sret);
	}

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_false(res_val) ||
	    (err_val && !json_is_null(err_val)))  {
		applog(LOG_ERR, "Stratum authentication failed");
		goto out;
	}

    if(jsonrpc_2) {
        json_t *job_val = json_object_get(res_val, "job");
        if (!rpc2_login_decode(val)) {
            applog(LOG_ERR, "Stratum authentication failed");
            goto out;
        }
        pthread_mutex_lock(&sctx->work_lock);
        if(job_val) rpc2_job_decode(job_val, &sctx->work);
        pthread_mutex_unlock(&sctx->work_lock);
    }

	ret = true;

out:
	free(s);
	if (val)
		json_decref(val);

	return ret;
}

static bool stratum_2_job(struct stratum_ctx *sctx, json_t *params)
{
    bool ret = false;
    pthread_mutex_lock(&sctx->work_lock);
    ret = rpc2_job_decode(params, &sctx->work);
    pthread_mutex_unlock(&sctx->work_lock);
    return ret;
}

static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *ntime;
	size_t coinb1_size, coinb2_size, coinbase_size, xn2_off;
	unsigned char *coinbase, **merkle;
	bool clean, same_job;
	int merkle_count, i;
	json_t *merkle_arr;

	job_id = json_string_value(json_array_get(params, 0));
	prevhash = json_string_value(json_array_get(params, 1));
	coinb1 = json_string_value(json_array_get(params, 2));
	coinb2 = json_string_value(json_array_get(params, 3));
	merkle_arr = json_array_get(params, 4);
	version = json_string_value(json_array_get(params, 5));
	nbits = json_string_value(json_array_get(params, 6));
	ntime = json_string_value(json_array_get(params, 7));
	clean = json_is_true(json_array_get(params, 8));

	/* validate everything before touching the current job */
	if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !ntime ||
	    !json_is_array(merkle_arr) ||
	    strlen(prevhash) != 64 || strlen(version) != 8 ||
	    strlen(nbits) != 8 || strlen(ntime) != 8 ||
	    strlen(coinb1) % 2 || strlen(coinb2) % 2 ||
	    !is_hex(prevhash) || !is_hex(coinb1) || !is_hex(coinb2) ||
	    !is_hex(version) || !is_hex(nbits) || !is_hex(ntime)) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		return false;
	}
	merkle_count = (int) json_array_size(merkle_arr);
	merkle = calloc(merkle_count ? merkle_count : 1, sizeof(*merkle));
	if (!merkle)
		return false;
	for (i = 0; i < merkle_count; i++) {
		const char *s = json_string_value(json_array_get(merkle_arr, i));
		if (!s || strlen(s) != 64 || !is_hex(s) || !(merkle[i] = malloc(32))) {
			applog(LOG_ERR, "Stratum notify: invalid Merkle branch");
			goto err;
		}
		hex2bin(merkle[i], s, 32);
	}
	coinb1_size = strlen(coinb1) / 2;
	coinb2_size = strlen(coinb2) / 2;

	pthread_mutex_lock(&sctx->work_lock);

	/* coinbase = coinb1 | extranonce1 | extranonce2 | coinb2 */
	xn2_off = coinb1_size + sctx->xnonce1_size;
	coinbase_size = xn2_off + sctx->xnonce2_size + coinb2_size;
	coinbase = malloc(coinbase_size);
	if (!coinbase) {
		pthread_mutex_unlock(&sctx->work_lock);
		goto err;
	}
	hex2bin(coinbase, coinb1, coinb1_size);
	memcpy(coinbase + coinb1_size, sctx->xnonce1, sctx->xnonce1_size);
	/* When the pool re-sends the job we are working on (for instance
	 * along with a new difficulty) keep rolling extranonce2 from where we
	 * are, or the shares we already sent would be found and sent again. */
	same_job = sctx->job.job_id && sctx->job.xnonce2 &&
	           !strcmp(sctx->job.job_id, job_id);
	if (same_job)
		memcpy(coinbase + xn2_off, sctx->job.xnonce2, sctx->xnonce2_size);
	else
		memset(coinbase + xn2_off, 0, sctx->xnonce2_size);
	hex2bin(coinbase + xn2_off + sctx->xnonce2_size, coinb2, coinb2_size);

	free(sctx->job.coinbase);
	sctx->job.coinbase = coinbase;
	sctx->job.coinbase_size = coinbase_size;
	sctx->job.xnonce2 = coinbase + xn2_off;

	if (!same_job) {
		free(sctx->job.job_id);
		sctx->job.job_id = strdup(job_id);
	}
	hex2bin(sctx->job.prevhash, prevhash, 32);

	for (i = 0; i < sctx->job.merkle_count; i++)
		free(sctx->job.merkle[i]);
	free(sctx->job.merkle);
	sctx->job.merkle = merkle;
	sctx->job.merkle_count = merkle_count;

	hex2bin(sctx->job.version, version, 4);
	hex2bin(sctx->job.nbits, nbits, 4);
	hex2bin(sctx->job.ntime, ntime, 4);
	sctx->job.clean = clean;

	sctx->job.diff = sctx->next_diff;

	pthread_mutex_unlock(&sctx->work_lock);

	return true;

err:
	for (i = 0; i < merkle_count; i++)
		free(merkle[i]);
	free(merkle);
	return false;
}

static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
	double diff;

	diff = json_number_value(json_array_get(params, 0));
	/* a zero, negative or non-finite difficulty would make every hash a
	 * "share" and flood the pool */
	if (!(diff > 0.) || diff > 1e30) {
		applog(LOG_ERR, "Stratum: ignoring invalid difficulty %g", diff);
		return false;
	}

	pthread_mutex_lock(&sctx->work_lock);
	sctx->next_diff = diff;
	pthread_mutex_unlock(&sctx->work_lock);

	if (opt_debug)
		applog(LOG_DEBUG, "Stratum difficulty set to %g", diff);

	return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
	json_t *port_val;
	char *url;
	const char *host;
	int port;

	host = json_string_value(json_array_get(params, 0));
	port_val = json_array_get(params, 1);
	if (json_is_string(port_val))
		port = atoi(json_string_value(port_val));
	else
		port = json_integer_value(port_val);
	if (!host || !port)
		return false;

	url = malloc(32 + strlen(host));
	sprintf(url, "stratum+tcp://%s:%d", host, port);

	if (!opt_redirect) {
		applog(LOG_INFO, "Ignoring request to reconnect to %s", url);
		free(url);
		return true;
	}

	applog(LOG_NOTICE, "Server requested reconnection to %s", url);

	free(sctx->url);
	sctx->url = url;
	stratum_disconnect(sctx);

	return true;
}

static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret;
	
	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(USER_AGENT));
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	val = json_array_get(params, 0);
	if (val)
		applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", json_string_value(val));
	
	if (!id || json_is_null(id))
		return true;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_true());
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

bool stratum_handle_method(struct stratum_ctx *sctx, const char *s)
{
	json_t *val, *id, *params;
	json_error_t err;
	const char *method;
	bool ret = false;

	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	method = json_string_value(json_object_get(val, "method"));
	if (!method)
		goto out;
	id = json_object_get(val, "id");
	params = json_object_get(val, "params");

    if (jsonrpc_2) {
        if (!strcasecmp(method, "job")) {
            ret = stratum_2_job(sctx, params);
            goto out;
        }
    } else {
        if (!strcasecmp(method, "mining.notify")) {
            ret = stratum_notify(sctx, params);
            goto out;
        }
        if (!strcasecmp(method, "mining.set_difficulty")) {
            ret = stratum_set_difficulty(sctx, params);
            goto out;
        }
        if (!strcasecmp(method, "client.reconnect")) {
            ret = stratum_reconnect(sctx, params);
            goto out;
        }
        if (!strcasecmp(method, "client.get_version")) {
            ret = stratum_get_version(sctx, id);
            goto out;
        }
        if (!strcasecmp(method, "client.show_message")) {
            ret = stratum_show_message(sctx, id, params);
            goto out;
        }
    }

out:
	if (val)
		json_decref(val);

	return ret;
}

struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;

	list_for_each_entry_safe(ent, iter, &tq->q, q_node) {
		list_del(&ent->q_node);
		free(ent);
	}

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	/* Condition variables may wake up spuriously: wait again unless there
	 * is something to pop or the queue was frozen. Returning NULL on such
	 * a wakeup made its caller (the workio or a miner thread) exit. */
	while (list_empty(&tq->q) && !tq->frozen) {
		if (abstime)
			rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
		else
			rc = pthread_cond_wait(&tq->cond, &tq->mutex);
		if (rc)
			goto out;	/* timed out */
	}
	if (list_empty(&tq->q))
		goto out;	/* frozen */

	ent = list_entry(tq->q.next, struct tq_ent, q_node);
	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}
