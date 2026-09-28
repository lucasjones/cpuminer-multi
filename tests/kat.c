/*
 * Known-answer tests for the proof-of-work code in libalgos.a.
 *
 * Every expected value was cross-checked against an independent source:
 *  - sha256d, scrypt: Python's hashlib
 *  - x11: the Dash genesis block hash
 *  - sha256d, scrypt, skein, qubit, odo: real DigiByte blocks (block_vectors)
 *  - neoscrypt: real Feathercoin blocks, and Feathercoin Core's code
 *  - argon2d*: RFC 9106's test vector, and the reference implementation
 *    (as Myriad ships it)
 *  - yescrypt*, yespower*: Openwall's test vectors, Openwall's reference
 *    implementation, and (yescrypt) Myriad's own yescrypt code
 *  - odo: DigiByte Core's cipher test vectors, and its implementation for
 *    the synthetic headers
 *  - cryptonight: the CryptoNote/Monero "slow hash" test vectors
 *  - randomx: tevador's test vectors (RandomX's tests.cpp); fast mode must
 *    agree with light mode
 *  - verthash: the data file's SHA-256 and the test vector published by
 *    Vertcoin (vertcoinhash-python), and its reference implementation for
 *    the synthetic headers
 *  - all other sph-based algorithms: tpruvot/cpuminer-multi
 *
 * Usage:
 *   kat                      run all tests (exit status 1 on any failure)
 *   kat --hash ALGO HEX      print ALGO's hash of HEX (used by tests/mockpool.py)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower/yespower.h"

#include <stdarg.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Symbols libalgos.a expects the miner to provide. */
static struct work_restart restart_flags[1];
struct work_restart *work_restart = restart_flags;
bool aes_ni_supported = false;
bool opt_debug = false;

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	(void) prio;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;

	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i])
			return false;
		if (hash[i] < target[i])
			return true;
	}
	return true;
}

/* 80-byte block headers, in the byte order they are hashed. */
static const char *const header_hex[] = {
	/* Bitcoin genesis block */
	"0100000000000000000000000000000000000000000000000000000000000000"
	"000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
	"4b1e5e4a29ab5f49ffff001d1dac2b7c",
	/* Dash (X11) genesis block */
	"0100000000000000000000000000000000000000000000000000000000000000"
	"00000000c762a6567f3cc092f0684bb62b7e00a84890b990f07cc71a6bb58d64"
	"b98e02e0022ddb52f0ff0f1ec23fb901",
	/* fixed pseudo-random bytes */
	"f7c7701d0117e9f1f0ce9508abb11519c45a3c0407fcc90458a59f7b9d762617"
	"2eb61dd803807ce1f73f10aa8ae9771199ac1683940b45d38e10a54d7bd95a44"
	"3fa7ee3374e087aa04f18212015524b5",
};
#define N_HEADERS (sizeof(header_hex) / sizeof(header_hex[0]))

typedef void (*hash80_fn)(void *out, const void *in);
typedef int (*scan_fn)(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done);

static int s_scrypt(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	static unsigned char *scratchbuf;

	if (!scratchbuf)
		scratchbuf = scrypt_buffer_alloc(1024);
	return scanhash_scrypt(thr_id, pdata, scratchbuf, ptarget, max_nonce,
			hashes_done, 1024);
}

static void h_sha256d(void *out, const void *in) { sha256d(out, in, 80); }
static void h_scrypt(void *out, const void *in) { scrypt_hash(out, in, 1024); }
static void h_fresh(void *out, const void *in) { freshhash(out, in, 80); }

/* Argon2d, each variant */
#define ARGON2D_FNS(V, N) \
static void h_argon2d##N(void *out, const void *in) { argon2d_hash(out, in, V); } \
static int s_argon2d##N(int thr_id, uint32_t *pdata, const uint32_t *ptarget, \
	uint32_t max_nonce, uint64_t *hashes_done) \
{ \
	return scanhash_argon2d(thr_id, pdata, ptarget, V, max_nonce, hashes_done); \
}
ARGON2D_FNS(ARGON2D_4096, 4096)
ARGON2D_FNS(ARGON2D_500, 500)
ARGON2D_FNS(ARGON2D_250, 250)
ARGON2D_FNS(ARGON2D_16000, 16000)

/* yescrypt and yespower, each variant */
#define YESPOWER_FNS(V, N) \
static void h_##N(void *out, const void *in) { yespower_hash(out, in, V); } \
static int s_##N(int thr_id, uint32_t *pdata, const uint32_t *ptarget, \
	uint32_t max_nonce, uint64_t *hashes_done) \
{ \
	return scanhash_yespower(thr_id, pdata, ptarget, V, max_nonce, hashes_done); \
}
YESPOWER_FNS(YESCRYPT, yescrypt)
YESPOWER_FNS(YESCRYPT_R8, yescryptr8)
YESPOWER_FNS(YESCRYPT_R16, yescryptr16)
YESPOWER_FNS(YESCRYPT_R32, yescryptr32)
YESPOWER_FNS(YESPOWER, yespower)
YESPOWER_FNS(YESPOWER_R16, yespowerr16)

/* Odocrypt with the main network's key for the header's time, as odohash() */
static int s_odo(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	return scanhash_odo(thr_id, pdata, ptarget,
			    odo_key(swab32(pdata[17]), ODO_INTERVAL_MAINNET),
			    max_nonce, hashes_done);
}

static const struct {
	const char *name;
	bool sha;		/* uses SHA-256: tested with and without SHA-NI */
	hash80_fn fn;
	scan_fn scan;
	const char *expected[N_HEADERS];	/* one per header above */
	bool verthash;		/* needs Verthash's data file */
} algos[] = {
	{ "sha256d", true, h_sha256d, scanhash_sha256d, {
		"6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
		"a4b09ec60478ce10b2bda154b349e5222e3b9a5fa8fdd9700fdd6eb044c49f08",
		"a95394b3a0fe69387a1c35badd4fce9a6e69ff38ecd4a3410ebf3861b18cd1b0" } },
	{ "scrypt", true, h_scrypt, s_scrypt, {
		"59053665189c5d648b11d47540603441c1eee666291879db5eb8e604a0d65856",
		"ac8d208a1c3f09932640257bed49f99ab191c6eced1c761c087dbce204c9ece8",
		"46bb54095dbc520928360df81c491fd3ba6ecddeed05f5070aa37f6f431d3774" } },
	{ "keccak", false, keccakhash, scanhash_keccak, {
		"1288180027a46738fca19f18d5bf419ac78bfd9d90a62122bb93787fa842105e",
		"20462a11d0b74f88b5d16cefa0fa2fb124f4f9e11e09a4f4b132f5785babda3f",
		"d27207d5fa967489709a51afc3bef9d889bd4191393f7f1f13cf63f28a94b5c7" } },
	{ "quark", false, quarkhash, scanhash_quark, {
		"ed68b5108e55f5361f4dfbcfeb40d976dc540a51619bc34c2c6f5b132c7213b2",
		"c608e6eefa3b298cfa864de5f71e0dc40d2ae8009d95b9c0a3d889c2a1d21a2b",
		"0bf07abe4f44776ef799543a3d4e8ca39588f66012fb14847ad90ac7c5f2dd87" } },
	{ "skein", true, skeinhash, scanhash_skein, {
		"d020fec8cd79ad48e5dd62d99521a64835c5692f79d9e1bcbda33d6580ed1271",
		"971c55d900af2196afa6e00d3345af017126f61186cef7fed25ae4510065f163",
		"6c3a072e11f3eb7971c3104f74a4e3f76330fc0fd0115f4c6ef6f9bde7fc16cb" } },
	{ "shavite3", false, inkhash, scanhash_ink, {
		"4213d207898171aa654c147cf8b6ae4c05f085da78ac45471e4dd7476114367e",
		"2c5eae99b7dc0716001764f1a4233dcdbab7ca12db46267d7bd4cffda9b81eb3",
		"9f82257a1ebd0d50bec720a15c1ca2bd8dba3b6c6ed4b430fbdea2c0f583c23f" } },
	{ "blake", false, blakehash, scanhash_blake, {
		"7f2b62ef43531a0ba5b34ae0ccd07671a38651943ddfec09cc80e5fa3424742b",
		"981c656a38986aea08eeecd4668d404c11c623b624c439bb51ad2ae4ed238c01",
		"bca5c682aba75d351ba5b5361534694299dc34bd3cdadc564bf58922ae8cadf0" } },
	{ "fresh", false, h_fresh, scanhash_fresh, {
		"f16be95bcff8abdef61a6fe73217fec622c136ffb85b9139026f7da86c066128",
		"8582ea22c018c2ac8317f231c09e8676e8c04a75a9475623d53d3fe843b17a52",
		"bdefaab230a7c4307437a8761dd35a099ddede447f247a0589fbfda842242dfe" } },
	{ "x11", false, x11hash, scanhash_x11, {
		"d90dbd33602755a7e3e6dab75b190405a73a596201a3db5af2172a0ac0153804",
		"b67a40f3cd5804437a108f105533739c37e6229bc1adcab385140b59fd0f0000",
		"a4ef5bc464437fafc7d54aec066a61a0ec016be327549655e35882c1fa7af88c" } },
	{ "x13", false, x13hash, scanhash_x13, {
		"c99f91e5dbd8158a1cee67797044972094df0afc4d5140f270e2c6f9bba520be",
		"bd7b68f858fceb974434d3147b27a05c4a4b8fad4cf1683c624acb3aff467564",
		"d66440fffb1963f7a8da54c6fbedb492439ba82149882ef8c529faf739eda079" } },
	{ "x14", false, x14hash, scanhash_x14, {
		"21bf0ddfe3117f203094cc1c8fc004fad4caf3e52141b52052b3419443a4328c",
		"53508d81d8d927ebbc468974126918056cd9faf720bbce4825d74cd6466a724c",
		"e9779dc652bc0d4e42151b89a96c33f1eb14b89d4870cd440e5536ca9bdee502" } },
	{ "x15", false, x15hash, scanhash_x15, {
		"215d26975dfcbd0045cbb5f3ee611124e1eaa15952dd8be86801b4f20133ad69",
		"a53723d85835af68793e08d00e3658f12ec476fe6f42121cd3b5c58e19386164",
		"b63178162027734fb758332d696cfd74675a093aaf0d426818905b0b12438755" } },
	{ "qubit", false, qubithash, scanhash_qubit, {
		"24b015e6b3c7d19e4a9b5ad7dce01bb589086e1fad098f8f3d891a3eca3ec641",
		"f53c0bcbc5ba8db1792c74ea5a1eb7ee66783e24e4f4bffaccf591f86a49d842",
		"1fd95112326c4118bdc8326ffb859513092b1aff568769aa1b304e7c5aaad095" } },
	{ "odo", false, odohash, s_odo, {
		"ffdbde284c06c8187d104267fcf15228dc309299228daf62baa92b904c1048d3",
		"74972069d57a94bc2a750e726944f2c52249534434c7411f1bcb201d5b1635a9",
		"1dac4cbb5d3d1d1aed0f59d3469a4bf59173dfb320a0f36f002e23a4a9362b3e" } },
	{ "neoscrypt", false, neoscrypt_hash, scanhash_neoscrypt, {
		"d5565bd5b3875f583ca4eb212ea4ab15809f0895f0ff128bd1068da9e4bddb27",
		"8f8eea00585b98a86599601ef37a5554161562086c6342f4d4e2fcddadae4deb",
		"8c14059f6fde4f7f965164f22eb2ffdd14fed07551e192081d473b40b6a21ff8" } },
	{ "argon2d4096", false, h_argon2d4096, s_argon2d4096, {
		"209b8d5156e86decbf1c4976560c4e3f2ee1b146b5d955431ee403377b0ef8eb",
		"efcf784b1ae5a95dd15a1c6a9b52fe44c59ecd6f966c2e6a3d8355b1b49bab5b",
		"47a79c2c8d6290e319c187e32f1942e125c40aa65e7227d03b2453c2ba2a195c" } },
	{ "argon2d500", false, h_argon2d500, s_argon2d500, {
		"d63432f651456b36a27ee8c98e146b005c80e499d0931f2c9ca6ead68b3ff48f",
		"effc9ced570f3dead9906e606dd77cfa06a76400e1a9fc0e6632b66056ffbc1b",
		"0809cb55e03c7f642394f912b0a82ff840ae9844444394878510ddd8790e0118" } },
	{ "argon2d250", false, h_argon2d250, s_argon2d250, {
		"f4a2511de45745f14ca86031687a7e74f9ca3603959d88d6656112d922435f56",
		"d9467200bbdd84684b6cb7dd4088ffe7ca3a30b0785960f933a9771a50e9e937",
		"1748ece06fb1447f5868f0c2a13cdba60ab78182c90243db410567f0c20ce3e6" } },
	{ "argon2d16000", false, h_argon2d16000, s_argon2d16000, {
		"45d545f96a4d96344db68554279e8c865ed32e457539d853c9e9a7e48659d087",
		"3be5bb6383840ca90f18b5704114cd83d9fbffc1b7e80b90febb0a6ece05d1dc",
		"5304cf9ac518dd6fe2cdf3ad5be6a8556632ca0eeffd06e83e382eb8a3312e2f" } },
	{ "yescrypt", false, h_yescrypt, s_yescrypt, {
		"f71f7dc502c2e7cceea26246317a6ea9ac35ce7560977616857016b15d748780",
		"630d10d05127e8df3be9b9df6ece6a9249177fd7b66036082de2b456f6506057",
		"e3131418b0e133da8ccd3746e0cad8606abd096178ed0c0aed814684d31765d0" } },
	{ "yescryptr8", false, h_yescryptr8, s_yescryptr8, {
		"e30eefac5cef503230a3990fb3f9abc375e20ec1b103c7c5a010d1c5c34e9631",
		"5145ce4f6f70d13f0f656f4e294379a81d0fc319fabcdfdac2dc0cd6d0714c8d",
		"6e31d8db34279bd0c8dce19958e1db7b85f54daf3b0911da6fe1904f6f7d9a09" } },
	{ "yescryptr16", false, h_yescryptr16, s_yescryptr16, {
		"4e6b5319ffa98e34203f50006e48daf13e4bd17f10fc36f0c92948df00aa8052",
		"83241bba5a7017e08ad67c717a865633b736d57700e722144df3448e6b09491c",
		"328a1e3092cd88f6a171580b49fc97d0f53ae2503135b06dcc30dc09e8bee833" } },
	{ "yescryptr32", false, h_yescryptr32, s_yescryptr32, {
		"b46abc6481c660189f7a7a818c580dcdd4a3397f23378d63336bbc11fe896226",
		"dba6a8f72b03e1ff1ecb2495a63f92e007a8af0f01d8d210f0bfc4707285c583",
		"ae99864b318b2cfd5cc87aa3df04f23c1840033e80787a053d15595501982987" } },
	{ "yespower", false, h_yespower, s_yespower, {
		"bfb216c5c103f05572696dba8740ee5044016add2ea6fa227bcf364d99a0ec33",
		"65958d5c338043a68ef2e7cb43cadc480331e1b9d0b799b8763d37d5248b5b51",
		"41c63eb313cea2a34998222eafe86eb63dfe3e4ab998207e3d40f7efdc95393f" } },
	{ "yespowerr16", false, h_yespowerr16, s_yespowerr16, {
		"463e0b93e624a5897f0400823dc5db83f3b2afb8cc0ee550630587f8c7611e95",
		"1118ec2a153f726b39fac9d8fcb3447a52935af6cfe78bca37930e880c72e0df",
		"6f51e2a7ddc260523c47821920983523c4b936b04e3cbbe77fe779a5ed8a0d3d" } },
	{ "verthash", false, verthash_hash, scanhash_verthash, {
		"e9241c23491e9fa68e726c8fdcafb168812cc09fca719478335bbb128137af95",
		"1fdf4f33ec5df2ef9e4a86de9c4be27e73d8414aa00f3a62c2067bc0ea482098",
		"b2a9013a15d48a731529b030c1496dbb89674ce0771c5ad6716fed7c465b3ca0" },
	  true },
};
#define N_ALGOS (sizeof(algos) / sizeof(algos[0]))

/*
 * Real blocks: the header, and its proof-of-work hash, most significant
 * byte first as block explorers show hashes. The headers were checked
 * against their block hashes, which chain from one block to the next.
 * Explorers do not show Feathercoin's NeoScrypt hashes: those come from
 * Feathercoin Core's code, and each is below its block's target.
 */
static const struct {
	const char *what;
	const char *algo;
	const char *header;
	const char *pow;
} block_vectors[] = {
	{ "DigiByte block 12000000", "sha256d",
	  "02024020b4280e4d968527e4594b59ed4abad908a13657faa658ad633576d278"
	  "59226bbc43badc7960e2d361d5fb43070b13cbf47d68cd3b5c9a2622c59c3201"
	  "e4f1ecabcc13c85f4f9b0219c3dab44e",
	  "0000000000000000e231d6676909d4d54296d640d996453b6778cc8081239c1f" },
	{ "DigiByte block 11999999", "skein",
	  "0206002070a984f0cb24c667ff85a3f0038a54d109be25725a437ddbf7abc5f4"
	  "e77fe5a793fccdfa37bc5a987ae9b343fb51409ce44f4a35712af2fd156774aa"
	  "1d9cf9c3ca13c85f5a82031aaa244868",
	  "0000000000000149b07f6790b110c0d19a04e43aca08c460cb2aa30084eb2caa" },
	{ "DigiByte block 11999998", "qubit",
	  "02080020d87606b7ef16aeb26e3bb328b17a595a3198a985ae0da9a5e7e3eb43"
	  "e54b7ff2b650e5d37b588e6e4e4fbbd1b6228c8ab7a388e261e04863fd063589"
	  "bb19f071c613c85f4aa0041af1b5373d",
	  "0000000000000068c50fbf773bced2ae319ebc461f7635c59dd712835165344e" },
	{ "DigiByte block 11999997", "scrypt",
	  "0200002086d5a20406d7530ffc2998004a14e2a8ef618b79d54b203401000000"
	  "000000009760d9bc89809f459161fecfe70c46673aac2f2980df4143e46029be"
	  "2f2cff55c313c85fe7d2001b89c70c09",
	  "0000000000003fae858e91a5636704d4f1aa665db53c0cddf175b9cc5ecf9a86" },
	{ "DigiByte block 11999995", "odo",
	  "020e00203670628c63869e9135e07a4d3dea0f9d4e2a203848236d8c01000000"
	  "00000000965873e67854ef5a56dc315911f26c4222d2bd2c9741fc1ed1c5254e"
	  "cf11136cae13c85fd061181af8a005a6",
	  "000000000000072b3027c9ade646147ae57d1bab5cd6c1b2bfde9d7423bf2a50" },
	{ "Feathercoin block 6369117", "neoscrypt",
	  "040000209f6c175876f3896edc62293147eaf961aac07160134b8ff41256669d"
	  "236ab3e3f94ac17342f310122f6da79aed5443d6b743e811c709ef1f519e15ca"
	  "152762789735b86a3c4a481c0128aa1b",
	  "000000000d1bd0e9ddc982d3dcbfc021fabeca8e062056d9310dacf1a8a13dc8" },
	{ "Feathercoin block 6369118", "neoscrypt",
	  "0400002051c70d29c21b30b880b2b59a8319e5b2f49cec4b07baad3c093c3605"
	  "2d010e9a807b491fc3362dabfcad4ad03032b76e715a42a708698f8a982594aa"
	  "18f40f03b435b86a5ce1451c00182c39",
	  "0000000001e2c90039b3030ffe853761db261eda2d29b00c68dc94887b948ca3" },
	{ "Feathercoin block 6369119", "neoscrypt",
	  "00000020728f50ab7fc00c7254f8ca4e9c50f48a223aac6a59afa3509a7f976a"
	  "c9dd75e71d0c9d0661be8d8bc902e22ce3712417872edc05204c55279c1116da"
	  "716aef74be35b86a0c8d431c9cd9eff6",
	  "000000003b7a84f2e1b0dd11e724834c79e92b8aad72c2a072836615b1f3bc05" },
};

/* DigiByte Core's Odocrypt cipher vectors (src/test/crypto_tests.cpp);
 * NULL input: 80 bytes of its LongTestString() from offset 0x4ffb0 */
static const struct {
	uint32_t key;
	const char *input;
	const char *expected;
} odo_vectors[] = {
	{ 0, "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
	  "9724ebfef40d7808bc21b212d8645a1df4d7fc4a0d91ee8e7f747ca1383eaeb1bb264b3a3b1b1f19"
	  "a8d458616e9a19572e3ceb2f58773076e829a288c8fdb61ab619ffaa84a4ee752fea52dbb359620e" },
	{ 1, "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
	  "c659c70bd9335a0bec67e526cdf99569543ca7e258fad19d439fb8ada1bc68efa5553d270d236cf0"
	  "3b1c179c684cfc93ae15b3c239c11e384303785cc0d828114c28e08091f42ec707aba712fe999c68" },
	{ 0x80808080u, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrsqrstrstustuvtuvw",
	  "dc5d9757b16bfa425f527817ee88a070595a662474d06bb96b439e25bc3097fc7068ab9d934fcd19"
	  "c9587478dd9ab8f79f2c85175c51e49306135e561561725b0aa7a44366a1135ff93194da22d1e9ba" },
	{ 0x12345678, "As DigiByte relies on 80 byte header hashes, we want to have an example for that",
	  "13dddebb0d65daa0f3e4a5bd9a1b74af7ca5a7b32ef118fb1684b200e377ce504346adcd2354e818"
	  "bf530dd870386104f706f4fecde1cec5cee804aae2569821aa5b2db3ac048607be36714e2bce48c6" },
	{ 1729, NULL,
	  "de79362f40cf0c755b21cf30798fa828b21cba61222ebeccc5a1ee385183ff2a981926403529080f"
	  "6c5a650bb299770222e7dbc0bdd559f479fac21d08044d306513067f2bf6accdb8b55942a5430e1c" },
	{ 0xD59, "Mora labelled me Unknown Sample, which the overseer translated as Odo'ital......",
	  "a7dd19a7fcdf3b7c0a8da1765553d903ff42687fe2f36c3930b82d7a68e426a90f49f1fc4b06263d"
	  "cf95d70a1b436337586955ef61c976f97785da2d2c8144b6767f824d53dd518c2cfdce1e9bd74fe1" },
};

/* Openwall's yespower test vectors (TESTS-OK): the input is i * 3 for
 * i = 0 .. 79; key NULL: none, "": the input itself (BSTY) */
static const struct {
	int version;
	uint32_t N, r;
	const char *key;
	const char *expected;
} yespower_vectors[] = {
	{ YESPOWER_0_5, 2048, 8, "Client Key",
	  "a59fec4c4fdda16e3b1405adda66d525b68e7cadfcfe6ac066c7ad118cd80590" },
	{ YESPOWER_0_5, 2048, 8, "",
	  "5ea2b2956a9eace30a3237ff1d441edee1dc25aab8f0ea15c12165f83a7bc265" },
	{ YESPOWER_0_5, 4096, 32, "WaviBanana",
	  "3ae05abb3c5cf6f75415a92554c98d50e38ec9552cfa78373616f480b24e559f" },
	{ YESPOWER_0_5, 2048, 8, NULL,
	  "5ecbd8e8d7c90baed4bbf8916a1225dcc3c65f5c9165bae81cdde3cffad128e8" },
	{ YESPOWER_1_0, 2048, 8, NULL,
	  "69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46" },
	{ YESPOWER_1_0, 4096, 16, NULL,
	  "33fb8f063824a4a020f63dca535f5ca66ab5576468c75d1ccaac7542f76495ac" },
	{ YESPOWER_1_0, 1024, 32, "personality test",
	  "1f0269acf565c49adc0ef9b8f26ab3808cdc38394a254fddeedcc3aacff6ad9d" },
};

/* FIPS 180-2 SHA-256 test vectors (the last one needs two blocks, and
 * one with 55 bytes, the most that fits in one block with its padding) */
static const struct {
	const char *input;
	const char *expected;
} sha256_vectors[] = {
	{ "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
	{ "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
};

/* SHA-256 of n times "a": the lengths where the padding changes (Python's
 * hashlib) */
static const struct {
	size_t n;
	const char *expected;
} sha256_a_vectors[] = {
	{ 55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
	{ 63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34" },
	{ 64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" },
	{ 65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0" },
	{ 119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb" },
	{ 1000, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3" },
};

/* CryptoNote "slow hash" vectors (variable-length input) */
static const struct {
	const char *input;
	const char *expected;
} cn_vectors[] = {
	{ "This is a test",
	  "a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605" },
	{ "de omnibus dubitandum",
	  "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5" },
	{ "abundans cautela non nocet",
	  "722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4" },
	{ "caveat emptor",
	  "bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87" },
	{ "ex nihilo nihil fit",
	  "b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05" },
};

static int parse_hex(const char *hex, unsigned char *out, size_t max)
{
	size_t n = strlen(hex);

	if (n % 2 || n / 2 > max)
		return -1;
	for (size_t i = 0; i < n / 2; i++) {
		unsigned int b;
		if (sscanf(hex + 2 * i, "%2x", &b) != 1)
			return -1;
		out[i] = (unsigned char)b;
	}
	return (int)(n / 2);
}

static void to_hex(const unsigned char *in, size_t len, char *out)
{
	for (size_t i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", in[i]);
}

static int check(const char *what, const unsigned char *hash, const char *expected)
{
	char got[65];

	to_hex(hash, 32, got);
	if (strcmp(got, expected)) {
		printf("FAIL %s\n     expected %s\n     got      %s\n", what, expected, got);
		return 1;
	}
	printf("ok   %s\n", what);
	return 0;
}

/* compare two 256-bit little-endian numbers */
static int hash_cmp(const unsigned char *x, const unsigned char *y)
{
	for (int i = 31; i >= 0; i--)
		if (x[i] != y[i])
			return x[i] < y[i] ? -1 : 1;
	return 0;
}

static uint32_t le32(const unsigned char *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
}

/*
 * Scan-loop test: pick the nonce with the lowest hash in a window, set
 * the share target to exactly that hash and check the scan loop reports
 * that nonce; then lower the target by one and check it reports nothing.
 * This catches wrong byte order, wrong nonce handling and any shortcut
 * filter that drops valid shares.
 */
static int scan_test(size_t a, const unsigned char *header)
{
	unsigned char h[80], hash[32], best[32];
	uint32_t pdata[32], target[8], base, best_nonce = 0;
	uint64_t done;
	char what[64];
	int i, rc, failures = 0;

	memcpy(h, header, 80);
	base = 0x10000000;
	memset(best, 0xff, 32);
	/* lowest hash among nonces base .. base+127 */
	for (uint32_t n = base; n < base + 128; n++) {
		be32enc(h + 76, n);
		algos[a].fn(hash, h);
		if (hash_cmp(hash, best) < 0) {
			memcpy(best, hash, 32);
			best_nonce = n;
		}
	}
	/* multi-lane scan loops may hash up to 31 nonces past max_nonce: none of
	 * them may be at or below the target either (rare; skip if so) */
	for (uint32_t n = best_nonce + 1; n <= best_nonce + 32; n++) {
		be32enc(h + 76, n);
		algos[a].fn(hash, h);
		if (hash_cmp(hash, best) <= 0) {
			printf("SKIP %s scan: ambiguous window\n", algos[a].name);
			return 0;
		}
	}

	be32enc(h + 76, best_nonce);
	for (i = 0; i < 20; i++)
		pdata[i] = be32dec(h + 4 * i);
	pdata[20] = 0x80000000;
	for (i = 21; i < 31; i++)
		pdata[i] = 0;
	pdata[31] = 0x00000280;
	for (i = 0; i < 8; i++)
		target[i] = le32(best + 4 * i);

	rc = algos[a].scan(0, pdata, target, best_nonce, &done);
	snprintf(what, sizeof(what), "%s scan finds share at target", algos[a].name);
	if (!rc || pdata[19] != best_nonce) {
		printf("FAIL %s (rc=%d nonce=%08x want %08x)\n", what, rc, pdata[19], best_nonce);
		failures++;
	} else
		printf("ok   %s\n", what);

	/* target - 1 */
	for (i = 0; i < 8; i++)
		if (target[i]-- != 0)
			break;
	for (i = 0; i < 20; i++)
		pdata[i] = be32dec(h + 4 * i);
	rc = algos[a].scan(0, pdata, target, best_nonce, &done);
	snprintf(what, sizeof(what), "%s scan rejects target - 1", algos[a].name);
	if (rc) {
		printf("FAIL %s (reported nonce %08x)\n", what, pdata[19]);
		failures++;
	} else
		printf("ok   %s\n", what);
	return failures;
}

/* CryptoNight scan: 64-bit target, nonce at bytes 39..42, any blob length */
static int cn_scan_test(size_t len)
{
	unsigned char blob[RPC2_MAX_BLOB], hash[32], found[32];
	uint32_t pdata[32], target[8], nonce = 0x12345678;
	uint64_t top, done;
	char what[64];
	int rc, failures = 0;

	for (size_t i = 0; i < len; i++)
		blob[i] = (unsigned char)(i * 7 + 3);
	le32enc(blob + 39, nonce);
	cryptonight_hash(hash, blob, len);
	top = ((uint64_t)le32(hash + 28) << 32) | le32(hash + 24);

	memset(pdata, 0, sizeof(pdata));
	memcpy(pdata, blob, len);
	memset(target, 0xff, sizeof(target));
	target[6] = (uint32_t)(top + 1);
	target[7] = (uint32_t)((top + 1) >> 32);
	rc = scanhash_cryptonight(0, pdata, len, target, nonce, &done, found);
	snprintf(what, sizeof(what), "cryptonight scan (%zu-byte blob) finds share", len);
	if (!rc || le32dec((unsigned char *)pdata + 39) != nonce || memcmp(found, hash, 32)) {
		printf("FAIL %s\n", what);
		failures++;
	} else
		printf("ok   %s\n", what);

	memcpy(pdata, blob, len);
	target[6] = (uint32_t)top;
	target[7] = (uint32_t)(top >> 32);
	rc = scanhash_cryptonight(0, pdata, len, target, nonce, &done, found);
	snprintf(what, sizeof(what), "cryptonight scan (%zu-byte blob) rejects target = hash", len);
	if (rc) {
		printf("FAIL %s\n", what);
		failures++;
	} else
		printf("ok   %s\n", what);
	return failures;
}

/* RandomX (rx/0): tevador's test vectors (keys and inputs in text or hex) */
static const struct {
	const char *key, *input, *expected;
	bool hex_key, hex_input;
} rx_vectors[] = {
	{ "test key 000", "This is a test",
	  "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f", false, false },
	{ "test key 000", "Lorem ipsum dolor sit amet",
	  "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969", false, false },
	{ "test key 000", "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
	  "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8", false, false },
	{ "test key 001", "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
	  "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc", false, false },
	/* a Monero block hashing blob */
	{ "test key 001",
	  "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b"
	  "00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416",
	  "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1", false, true },
	/* an ISUB_R edge case */
	{ "7797373ea4633194640bf8d8c3b66724d6aa7bd2dc20e009df2f8f1710abe8",
	  "1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e1f6821fed84dae58"
	  "d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6514d90689721c4aac5a9bb0d",
	  "78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8", true, true },
};

/*
 * RandomX scan loop: 64-bit targets and the nonce at bytes 39..42, like
 * CryptoNight. It finishes one nonce's hash while starting the next, so
 * each hash it reports is checked against a single hash. In fast mode the
 * hashes must also be light mode's (which the test vectors checked).
 */
#define RX_WINDOW 6
static unsigned char rx_blob[76], rx_seed[32], rx_light[RX_WINDOW][32];

static uint64_t top64(const unsigned char *h)
{
	return (uint64_t)le32(h + 28) << 32 | le32(h + 24);
}

/* scanhash_randomx(), again if it only caught up with a new dataset */
static int rx_scan(uint32_t *pdata, uint32_t first, const uint32_t *target,
		   uint32_t max_nonce, uint64_t *done, unsigned char *found)
{
	int rc, tries = 0;

	do {
		memset(pdata, 0, 32 * sizeof(*pdata));
		memcpy(pdata, rx_blob, sizeof(rx_blob));
		le32enc((unsigned char *)pdata + 39, first);
		rc = scanhash_randomx(0, pdata, sizeof(rx_blob), rx_seed, target,
				      max_nonce, done, found);
	} while (!rc && !*done && ++tries < 3);
	return rc;
}

static int rx_scan_test(const char *mode, bool fast)
{
	unsigned char blob[sizeof(rx_blob)], hash[32], found[32];
	uint32_t pdata[32], target[8], best = 0, n;
	const uint32_t base = 0x7fffff00;
	uint64_t done, low = UINT64_MAX;
	char what[96];
	int rc, i, failures = 0;

	for (i = 0; i < RX_WINDOW; i++) {
		memcpy(blob, rx_blob, sizeof(blob));
		le32enc(blob + 39, base + i);
		if (!rx_hash(0, hash, rx_seed, sizeof(rx_seed), blob, sizeof(blob))) {
			printf("FAIL randomx (%s): no virtual machine\n", mode);
			return 1;
		}
		if (!fast)
			memcpy(rx_light[i], hash, 32);
		else if (memcmp(hash, rx_light[i], 32)) {
			printf("FAIL randomx (%s): nonce %08x hashes differently than in light mode\n",
			       mode, base + i);
			failures++;
		}
		if (top64(rx_light[i]) < low) {
			low = top64(rx_light[i]);
			best = base + i;
		}
	}
	if (fast && !failures)
		printf("ok   randomx (%s) hashes as light mode does\n", mode);

	/* any hash is a share: each call reports its first nonce */
	memset(target, 0xff, sizeof(target));
	for (i = 0; i < 3; i++) {
		rc = rx_scan(pdata, base + i, target, base + RX_WINDOW - 1, &done, found);
		n = le32dec((unsigned char *)pdata + 39);
		snprintf(what, sizeof(what), "randomx (%s) scan reports nonce %08x's hash", mode, base + i);
		if (!rc || n != base + i || memcmp(found, rx_light[i], 32)) {
			printf("FAIL %s (rc=%d nonce=%08x)\n", what, rc, n);
			failures++;
		} else
			printf("ok   %s\n", what);
	}

	/* the lowest hash in the window, at a target just above it */
	target[6] = (uint32_t)(low + 1);
	target[7] = (uint32_t)((low + 1) >> 32);
	rc = rx_scan(pdata, base, target, base + RX_WINDOW - 1, &done, found);
	n = le32dec((unsigned char *)pdata + 39);
	snprintf(what, sizeof(what), "randomx (%s) scan finds share at target", mode);
	if (!rc || n != best || memcmp(found, rx_light[best - base], 32)) {
		printf("FAIL %s (rc=%d nonce=%08x want %08x)\n", what, rc, n, best);
		failures++;
	} else
		printf("ok   %s\n", what);

	/* and none at a target equal to it (a share is below the target) */
	target[6] = (uint32_t)low;
	target[7] = (uint32_t)(low >> 32);
	rc = rx_scan(pdata, base, target, base + RX_WINDOW - 1, &done, found);
	n = le32dec((unsigned char *)pdata + 39);
	snprintf(what, sizeof(what), "randomx (%s) scan rejects target = hash", mode);
	if (rc || n != base + RX_WINDOW - 1 || done != RX_WINDOW) {
		printf("FAIL %s (rc=%d nonce=%08x, %llu hashes)\n", what, rc, n,
		       (unsigned long long)done);
		failures++;
	} else
		printf("ok   %s\n", what);
	return failures;
}

static int processors(void)
{
#ifdef _WIN32
	SYSTEM_INFO info;

	GetSystemInfo(&info);
	return (int)info.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	return n > 0 ? (int)n : 1;
#else
	return 1;
#endif
}

/* RandomX in light mode, then fast mode if the machine has the memory
 * (as the miner decides); KAT_RANDOMX_FAST=no skips fast mode, which takes
 * 2.3 GiB and a while to set up */
static int randomx_tests(void)
{
	const char *env = getenv("KAT_RANDOMX_FAST");
	unsigned char key[64], in[128], hash[32];
	char what[128];
	int failures = 0, keylen, len;
	size_t v;

#ifndef USE_RANDOMX
	printf("skip randomx: not built (no C++11 compiler)\n");
	return 0;
#endif
	if (!rx_setup(RX_MODE_LIGHT, 1, processors())) {
		printf("FAIL randomx: no memory for light mode\n");
		return 1;
	}
	printf("     randomx: %s\n", rx_describe());
	for (v = 0; v < sizeof(rx_vectors) / sizeof(rx_vectors[0]); v++) {
		if (rx_vectors[v].hex_key)
			keylen = parse_hex(rx_vectors[v].key, key, sizeof(key));
		else {
			keylen = (int)strlen(rx_vectors[v].key);
			memcpy(key, rx_vectors[v].key, keylen);
		}
		if (rx_vectors[v].hex_input)
			len = parse_hex(rx_vectors[v].input, in, sizeof(in));
		else {
			len = (int)strlen(rx_vectors[v].input);
			memcpy(in, rx_vectors[v].input, len);
		}
		snprintf(what, sizeof(what), "randomx (light) key \"%.12s\", \"%.20s\"",
			 rx_vectors[v].key, rx_vectors[v].input);
		if (keylen < 0 || len < 0 || !rx_hash(0, hash, key, keylen, in, len)) {
			printf("FAIL %s: no result\n", what);
			failures++;
		} else
			failures += check(what, hash, rx_vectors[v].expected);
	}

	/* a Monero-style job blob (the fifth vector's input) with a 32-byte key */
	parse_hex(rx_vectors[4].input, rx_blob, sizeof(rx_blob));
	for (v = 0; v < sizeof(rx_seed); v++)
		rx_seed[v] = (unsigned char)(v * 11 + 5);
	failures += rx_scan_test("light", false);
	rx_cleanup();

	if (sizeof(void *) < 8)
		printf("skip randomx (fast): fast mode is for 64-bit builds\n");
	else if (env && !strcmp(env, "no"))
		printf("skip randomx (fast): KAT_RANDOMX_FAST=no\n");
	else if (!rx_setup(RX_MODE_AUTO, 1, processors()))
		printf("skip randomx (fast): not enough memory\n");
	else if (!rx_is_fast())
		printf("skip randomx (fast): not enough memory for the dataset\n");
	else {
		printf("     randomx: %s\n", rx_describe());
		failures += rx_scan_test("fast", true);
	}
	rx_cleanup();
	return failures;
}

/*
 * Verthash's data file: read from KAT_VERTHASH_DATA if set, else built,
 * which tests the builder (the data's SHA-256 must be the published one).
 * KAT_VERTHASH=no skips Verthash, which takes 1.2 GB of memory.
 */
static bool verthash_ready;

static int verthash_setup_tests(void)
{
	const char *env = getenv("KAT_VERTHASH"), *path = getenv("KAT_VERTHASH_DATA");
	uint64_t mem = system_memory();
	int r;

	if (env && !strcmp(env, "no")) {
		printf("skip verthash: KAT_VERTHASH=no\n");
		return 0;
	}
	if (mem && mem < (3ULL << 29)) {
		printf("skip verthash: not enough memory for the data file\n");
		return 0;
	}
	if (path) {
		r = verthash_load(path);
		if (r != 1) {
			printf("FAIL verthash: %s is not the data file\n", path);
			return 1;
		}
		printf("ok   verthash data file %s\n", path);
	} else {
		r = verthash_create(NULL, processors());
		if (r == 0) {
			printf("skip verthash: not enough memory for the data file\n");
			return 0;
		}
		if (r < 0) {
			printf("FAIL verthash data file built: wrong SHA-256\n");
			return 1;
		}
		printf("ok   verthash data file built, SHA-256 a55531e8...21aa48\n");
	}
	verthash_ready = true;
	return 0;
}

/* index in algos[] of the algorithm called name; N_ALGOS if none */
static size_t find_algo(const char *name)
{
	size_t i;

	for (i = 0; i < N_ALGOS; i++)
		if (!strcmp(algos[i].name, name))
			break;
	return i;
}

/* a real block's proof-of-work hash */
static int block_test(size_t v, const char *impl)
{
	unsigned char header[80], hash[32], pow[32];
	char what[128], expected[65];
	size_t a = find_algo(block_vectors[v].algo);
	int i;

	if (a == N_ALGOS || parse_hex(block_vectors[v].header, header, 80) != 80
	    || parse_hex(block_vectors[v].pow, pow, 32) != 32) {
		printf("FAIL %s: bad test vector\n", block_vectors[v].what);
		return 1;
	}
	for (i = 0; i < 32; i++)	/* least significant byte first */
		sprintf(expected + 2 * i, "%02x", pow[31 - i]);
	algos[a].fn(hash, header);
	snprintf(what, sizeof(what), "%s, %s%s", block_vectors[v].what,
		 block_vectors[v].algo, impl);
	return check(what, hash, expected);
}

static int hash_cli(const char *algo, const char *hex)
{
	unsigned char in[256], out[64];
	char buf[129];
	int len = parse_hex(hex, in, sizeof(in));

	if (len < 0) {
		fprintf(stderr, "bad hex input\n");
		return 2;
	}
	if (!strcmp(algo, "cryptonight")) {
		cryptonight_hash(out, in, len);
	} else {
		size_t i = find_algo(algo);

		if (i == N_ALGOS || len != 80) {
			fprintf(stderr, "unknown algorithm or input is not 80 bytes\n");
			return 2;
		}
		/* loaded (1), or missing (0) or unreadable (-1) */
		if (algos[i].verthash && (getenv("KAT_VERTHASH_DATA")
				? verthash_load(getenv("KAT_VERTHASH_DATA"))
				: verthash_create(NULL, processors())) != 1) {
			fprintf(stderr, "no Verthash data file\n");
			return 2;
		}
		algos[i].fn(out, in);
	}
	to_hex(out, 32, buf);
	puts(buf);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char header[N_HEADERS][80], hash[64];
	char what[128];
	int failures = 0;
	size_t a, h, v;

	init_quarkhash_contexts();
	init_blakehash_contexts();

	if (argc == 4 && !strcmp(argv[1], "--hash"))
		return hash_cli(argv[2], argv[3]);

	for (h = 0; h < N_HEADERS; h++)
		if (parse_hex(header_hex[h], header[h], 80) != 80)
			return 2;

	/* first, as it needs SHA-256 (its data file's checksum) */
	failures += verthash_setup_tests();

	/* everything built on SHA-256 twice: with the portable code, and
	 * with the x86 SHA extensions when the CPU has them */
	for (int impl = 0; impl < 2; impl++) {
		const char *name = impl ? " (SHA-NI)" : "";

		if (sha256_use_shani(impl) != impl) {
			printf("skip SHA-256 (SHA-NI): this CPU or build has no SHA extensions\n");
			break;
		}
		for (v = 0; v < sizeof(sha256_vectors) / sizeof(sha256_vectors[0]); v++) {
			sha256_hash(hash, (const unsigned char *) sha256_vectors[v].input,
				    (int) strlen(sha256_vectors[v].input));
			snprintf(what, sizeof(what), "sha256%s \"%.20s\"", name,
				 sha256_vectors[v].input);
			failures += check(what, hash, sha256_vectors[v].expected);
		}
		for (v = 0; v < sizeof(sha256_a_vectors) / sizeof(sha256_a_vectors[0]); v++) {
			unsigned char a1000[1000];

			memset(a1000, 'a', sha256_a_vectors[v].n);
			sha256_hash(hash, a1000, sha256_a_vectors[v].n);
			snprintf(what, sizeof(what), "sha256%s %zu times \"a\"", name,
				 sha256_a_vectors[v].n);
			failures += check(what, hash, sha256_a_vectors[v].expected);
		}
		for (a = 0; a < N_ALGOS; a++) {
			if ((impl && !algos[a].sha) || (algos[a].verthash && !verthash_ready))
				continue;
			for (h = 0; h < N_HEADERS; h++) {
				memset(hash, 0, sizeof(hash));
				algos[a].fn(hash, header[h]);
				snprintf(what, sizeof(what), "%s%s header #%zu",
					 algos[a].name, name, h);
				failures += check(what, hash, algos[a].expected[h]);
			}
		}
		for (v = 0; v < sizeof(block_vectors) / sizeof(block_vectors[0]); v++) {
			a = find_algo(block_vectors[v].algo);
			if ((!impl || algos[a].sha) && (!algos[a].verthash || verthash_ready))
				failures += block_test(v, name);
		}
		for (a = 0; a < N_ALGOS; a++)
			if ((!impl || algos[a].sha) && (!algos[a].verthash || verthash_ready))
				failures += scan_test(a, header[2]);
	}
	sha256_use_shani(true);

	for (v = 0; v < sizeof(odo_vectors) / sizeof(odo_vectors[0]); v++) {
		unsigned char in[80], out[80], want[80];

		if (odo_vectors[v].input)
			memcpy(in, odo_vectors[v].input, 80);
		else	/* LongTestString(): i, i >> 4, ... i >> 16, from i = 65520 */
			for (h = 0; h < 80; h++)
				in[h] = (unsigned char) ((65520 + h / 5) >> (4 * (h % 5)));
		odo_encrypt_block(out, in, odo_vectors[v].key);
		parse_hex(odo_vectors[v].expected, want, 80);
		snprintf(what, sizeof(what), "odocrypt cipher, key %08x",
			 (unsigned) odo_vectors[v].key);
		if (memcmp(out, want, 80)) {
			printf("FAIL %s\n", what);
			failures++;
		} else
			printf("ok   %s\n", what);
	}

	/* both CryptoNight implementations: portable C, and AES-NI when the
	 * CPU has it */
	for (int impl = 0; impl < 2; impl++) {
		const char *name = impl ? "AES-NI" : "portable";

		if (impl && !cryptonight_cpu_has_aesni()) {
			printf("skip cryptonight (AES-NI): this CPU or build has no AES-NI\n");
			break;
		}
		aes_ni_supported = impl;
		for (v = 0; v < sizeof(cn_vectors) / sizeof(cn_vectors[0]); v++) {
			cryptonight_hash(hash, cn_vectors[v].input, strlen(cn_vectors[v].input));
			snprintf(what, sizeof(what), "cryptonight (%s) \"%s\"", name,
				 cn_vectors[v].input);
			failures += check(what, hash, cn_vectors[v].expected);
		}
		failures += cn_scan_test(76);
		failures += cn_scan_test(77);
	}
	aes_ni_supported = false;

	/* every other NeoScrypt implementation this processor can run (the
	 * best one ran above) */
	{
		static const char *const impl_names[] = {
			"portable", "SSE2", "AVX2", "AVX-512"
		};
		size_t neo = find_algo("neoscrypt");
		int best = neoscrypt_use_impl(-1);

		for (int impl = 0; impl < best; impl++) {
			char label[32];

			snprintf(label, sizeof(label), " (%s)", impl_names[impl]);
			if (neoscrypt_use_impl(impl) != impl) {
				printf("skip neoscrypt (%s): not for this processor or build\n",
				       impl_names[impl]);
				continue;
			}
			for (h = 0; h < N_HEADERS; h++) {
				algos[neo].fn(hash, header[h]);
				snprintf(what, sizeof(what), "neoscrypt%s header #%zu",
					 label, h);
				failures += check(what, hash, algos[neo].expected[h]);
			}
			for (v = 0; v < sizeof(block_vectors) / sizeof(block_vectors[0]); v++)
				if (!strcmp(block_vectors[v].algo, "neoscrypt"))
					failures += block_test(v, label);
			failures += scan_test(neo, header[2]);
		}
		neoscrypt_use_impl(-1);
	}

	/* Argon2d: RFC 9106's test vector, and every implementation this
	 * processor can run (the best one ran above) */
	{
		static const char *const impl_names[] = { "plain", "AVX2" };
		static const char *const variants[] = {
			"argon2d4096", "argon2d500", "argon2d250", "argon2d16000"
		};
		uint8_t pwd[32], salt[16], secret[8], ad[12];
		int best = argon2d_use_impl(-1);

		memset(pwd, 1, sizeof(pwd));
		memset(salt, 2, sizeof(salt));
		memset(secret, 3, sizeof(secret));
		memset(ad, 4, sizeof(ad));
		for (int impl = best; impl >= 0; impl--) {
			char label[32];

			if (argon2d_use_impl(impl) != impl) {
				printf("skip argon2d (%s): not for this processor or build\n",
				       impl_names[impl]);
				continue;
			}
			snprintf(label, sizeof(label), " (%s)", impl_names[impl]);
			argon2d_raw(hash, 32, pwd, 32, salt, 16, secret, 8, ad, 12,
				    3, 32, 4, 0x13);
			snprintf(what, sizeof(what), "argon2d%s RFC 9106", label);
			failures += check(what, hash,
				"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
			if (impl == best)
				continue;
			for (v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
				a = find_algo(variants[v]);
				for (h = 0; h < N_HEADERS; h++) {
					algos[a].fn(hash, header[h]);
					snprintf(what, sizeof(what), "%s%s header #%zu",
						 algos[a].name, label, h);
					failures += check(what, hash, algos[a].expected[h]);
				}
			}
			failures += scan_test(find_algo("argon2d4096"), header[2]);
		}
		argon2d_use_impl(-1);
	}

	/* yespower's own test vectors */
	for (v = 0; v < sizeof(yespower_vectors) / sizeof(yespower_vectors[0]); v++) {
		uint8_t src[80];
		yespower_params_t p;

		for (h = 0; h < 80; h++)
			src[h] = (uint8_t) (h * 3);
		p.version = (yespower_version_t) yespower_vectors[v].version;
		p.N = yespower_vectors[v].N;
		p.r = yespower_vectors[v].r;
		p.pers = (const uint8_t *) yespower_vectors[v].key;
		p.perslen = p.pers ? strlen(yespower_vectors[v].key) : 0;
		if (p.pers && !p.perslen) {
			p.pers = src;
			p.perslen = sizeof(src);
		}
		yespower_tls(src, sizeof(src), &p, (yespower_binary_t *) hash);
		snprintf(what, sizeof(what), "yespower %s N=%u r=%u %s",
			 p.version == YESPOWER_0_5 ? "0.5" : "1.0", p.N, p.r,
			 !yespower_vectors[v].key ? "(no key)" :
			 *yespower_vectors[v].key ? yespower_vectors[v].key : "(BSTY)");
		failures += check(what, hash, yespower_vectors[v].expected);
	}

	/* Verthash: the test vector Vertcoin publishes with the data file */
	if (verthash_ready) {
		unsigned char vh_header[80];

		parse_hex("000000203a297b4b7685170d7644b43e5a6056234cc2414edde454a87580e1967d"
			  "14c1078c13ea916117b0608732f3f65c2e03b81322efc0a62bcee77d8a937126"
			  "1970a58a5a715da80e031b02560ad8", vh_header, 80);
		verthash_hash(hash, vh_header);
		failures += check("verthash, vertcoinhash-python's test vector", hash,
				  "e0f6c10b4a38f35a6cdcc26d32a7ed8c3bfc5d827a9bc72647afa324b70d0463");
		verthash_free();
	}

	failures += randomx_tests();

	printf("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
