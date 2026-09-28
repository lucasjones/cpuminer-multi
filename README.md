cpuminer-multi
==============

[![build](https://github.com/Justinwold88/cpuminer-multi/actions/workflows/build.yml/badge.svg)](https://github.com/Justinwold88/cpuminer-multi/actions/workflows/build.yml)

A multi-threaded CPU miner for many proof-of-work algorithms, Monero's
RandomX and Vertcoin's Verthash among them, for Linux, macOS and Windows on
x86-64, 32-bit x86, ARM64, 32-bit ARM and RISC-V.

This is a maintained fork of [Lucas Jones's cpuminer-multi](https://github.com/lucasjones/cpuminer-multi),
itself a fork of [pooler's cpuminer](https://github.com/pooler/cpuminer)
(see [AUTHORS](AUTHORS)). It fixes the bugs that stopped several algorithms and
all solo mining from working, replaces what had died since 2015 (getwork,
Travis CI, the Dockerfile), and is tested on every platform on every change.
See [NEWS](NEWS) for what changed.

#### Contents

* [Algorithms](#algorithms)
* [Download](#download)
* [Building](#building)
* [Usage](#usage)
* [Credits](#credits)
* [License](#license)

Algorithms
==========

| `-a` | Coins | Status |
|------|-------|--------|
| `randomx` (`rx/0`) | Monero, and other coins on RandomX's rx/0 | works (new in this fork) |
| `verthash` | Vertcoin | works (new in this fork) |
| `sha256d` | Bitcoin, Bitcoin Cash, Peercoin, ... | works |
| `scrypt` | Litecoin, Dogecoin | works |
| `x11` | Dash | works |
| `blake` | Blakecoin, and the coins merge-mined with it (Photon, Electron, Universal Molecule, Lithium, BlakeBitcoin) | works (fixed in this fork) |
| `skein` | DigiByte (Skein) | works (fixed in this fork) |
| `qubit` | DigiByte (Qubit) | works (new in this fork) |
| `odo` | DigiByte (Odocrypt) | works (new in this fork) |
| `neoscrypt` | Feathercoin, and other NeoScrypt coins | works (new in this fork) |
| `argon2d4096` | Myriad (Argon2d), Unitus | works (new in this fork) |
| `argon2d500` | Dynamic | works (new in this fork) |
| `argon2d250` | Credits | works (new in this fork) |
| `argon2d16000` | Alterdot | works (new in this fork) |
| `yescrypt` | Myriad (Yescrypt), GlobalBoost-Y | works (new in this fork) |
| `yescryptr8`, `yescryptr16`, `yescryptr32` | coins on yescrypt with a key (WAVI: r32) | works (new in this fork) |
| `yespower`, `yespowerr16` | yespower 1.0 coins (Yenten: r16; others with `--param-*`) | works (new in this fork) |
| `cryptonight` | Bytecoin and other coins on the original CryptoNight | works (fixed in this fork) |
| `scrypt:N` | scrypt with N other than 1024 (Vertcoin used it until 2014) | legacy |
| `keccak` | Maxcoin | legacy |
| `quark` | Quarkcoin | legacy |
| `x13`, `x14`, `x15` | Sherlockcoin, X14coin, RadianceCoin, ... | legacy |
| `fresh` | FreshCoin | legacy |
| `shavite3` | INKcoin | legacy |

**Works**: tested end to end, from the pool's messages to the shares or
blocks it accepts. **Legacy**: the hashing is tested, but we know of no
active network that still uses the algorithm; it is kept for completeness.

Bitcoin, Litecoin, Dogecoin, Dash and DigiByte are mined with ASICs or GPUs
today, so a CPU earns next to nothing on them. They are useful for testing
and for testnets.

Monero left CryptoNight for RandomX in 2019, and Vertcoin, Feathercoin and
Myriad moved to other algorithms too; their current ones are all here.

RandomX variants with other parameters (Wownero's `rx/wow`, ArQmA's
`rx/arq`, ...) are not supported: the miner refuses their jobs rather than
send shares a pool would reject.

Removed: Heavycoin's `heavy` (its network is gone, and the implementation was
broken) and the unused scrypt-jane sources.

Download
========

From the [Releases page](https://github.com/Justinwold88/cpuminer-multi/releases):

* Windows (64-bit): `cpuminer-multi-VERSION-windows-x86_64.zip`. Unzip it and
  run `minerd.exe` from a command prompt (see [Usage](#usage)). Antivirus
  programs often flag CPU miners, this one included, as "potentially unwanted
  software"; the zip is built by GitHub Actions from this repository's source,
  and `SHA256SUMS` on the same page has its checksum.
* Source: `cpuminer-multi-VERSION.tar.gz` builds with `./configure && make`
  (no autoconf or automake needed; see [Building](#building) for the
  libraries), or `git clone https://github.com/Justinwold88/cpuminer-multi`.

Every build on GitHub Actions also keeps a Windows `minerd.exe` with the DLLs
it needs, under *Actions → build → a run → Artifacts* (for people signed in to
GitHub).

Building
========

You need a C compiler, GNU make, autoconf, automake, pkg-config,
[libcurl](https://curl.se/libcurl/) and [jansson](https://github.com/akheron/jansson) 2.7 or newer, and for
RandomX a C++11 compiler (without one, configure leaves RandomX out, and says
so; `--disable-randomx` leaves it out on purpose).

Then, in the source directory:

    ./autogen.sh
    ./configure CFLAGS="-O2 -march=native"
    make
    make check

`-march=native` makes the fastest code for the machine you build on, but the
binary may not run on other CPUs; leave it out for a portable binary.
`make check` runs the known-answer tests: every algorithm must reproduce
reference hashes and find a planted share. `make install` installs `minerd`
and its man page.

#### Linux

Install the tools and libraries first:

* Debian, Ubuntu: `sudo apt install build-essential autoconf automake pkg-config libcurl4-openssl-dev libjansson-dev`
* Fedora: `sudo dnf install gcc gcc-c++ make autoconf automake pkgconf-pkg-config libcurl-devel jansson-devel`
* Arch: `sudo pacman -S --needed base-devel curl jansson`

#### macOS

With [Homebrew](https://brew.sh): `brew install autoconf automake pkgconf jansson`.
macOS comes with libcurl. This works on Apple Silicon and on Intel Macs.

#### Windows

Use [MSYS2](https://www.msys2.org). In its **UCRT64** shell:

    pacman -S --needed autoconf automake make mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-curl mingw-w64-ucrt-x86_64-jansson mingw-w64-ucrt-x86_64-pkgconf

Then build as above. To run `minerd.exe` outside the MSYS2 shell, copy the DLLs
it needs next to it:

    ldd minerd.exe | awk '$3 ~ /\/ucrt64\// { print $3 }' | xargs cp -t .

#### Docker

    docker build -t cpuminer-multi .
    docker run --rm cpuminer-multi -a sha256d -o stratum+tcp://POOL:PORT -u USER -p PASS

The image is built for the platform it is built on (amd64 or arm64). For the
fastest code on one machine, build there with
`--build-arg CFLAGS="-O2 -march=native"`.

#### Notes by architecture

* **x86-64**: uses SSE2, AVX, AVX2 and XOP assembly for scrypt and SHA-256d
  when both the CPU and the operating system support them (Linux 2.6.30,
  FreeBSD 9.1, OS X 10.6.8, Windows 7 SP1 and later). configure warns if the
  assembler lacks an instruction set; the miner still builds without it.
* **32-bit x86**: SSE2 assembly for scrypt and SHA-256d, picked at run time.
* **x86-64**: NeoScrypt uses AVX2 or AVX-512 when the CPU has them, and
  hashes 4 nonces at a time; Argon2d uses AVX2.
* **x86, 32 and 64-bit**: CryptoNight uses AES-NI when the CPU has it. On
  Linux, its 2 MiB scratchpad goes on a transparent huge page when the
  kernel allows it (`/sys/kernel/mm/transparent_hugepage/enabled` set to
  `madvise` or `always`, the default on most distributions).
* **ARM64** (Raspberry Pi 3 and later with a 64-bit OS, Apple Silicon, AWS
  Graviton): portable C code, but for RandomX (below).
* **32-bit ARM**: assembly for ARMv5E and later, chosen when compiling. Add
  `-mfpu=neon` to `CFLAGS` to use NEON.
* **RandomX** compiles its programs to machine code (JIT) on x86-64, ARM64
  and 64-bit RISC-V (which needs GCC 14 or Clang 17 or newer to build), and
  interprets them elsewhere, several times slower. It uses hardware AES
  (AES-NI, the ARMv8 crypto extensions, RISC-V's Zvkned) and SSSE3 or AVX2
  for Argon2 when the processor has them.
* `./configure --disable-assembly` builds everything from portable C, but for
  RandomX's JIT compilers.
* AIX: export `OBJECT_MODE=64` for a 64-bit build. Long options are only
  available through a configuration file.

Usage
=====

Run `minerd --help` for all the options, or see `man minerd`.

#### Pool mining (stratum)

    minerd -a scrypt -o stratum+tcp://pool.example.com:3333 -u USER.WORKER -p x

`-t N` sets the number of threads (default: one per processor). If the pool
expresses difficulty for a different "difficulty 1" than the miner expects,
`-f N` divides the pool's difficulty by N.

#### Solo mining (getblocktemplate)

Mine against your own node for any Bitcoin-style coin that uses one of the
algorithms above. Enable its RPC server (`server=1`, `rpcuser`, `rpcpassword`
in its configuration file), let it sync, then:

    minerd -a sha256d -o http://127.0.0.1:8332 -u RPCUSER -p RPCPASS --coinbase-addr=YOUR_ADDRESS

The reward goes to `--coinbase-addr`. The miner asks the node what output
script that address pays to (so any address type the node knows works:
legacy, P2SH, segwit, taproot), and refuses to start if the node says the
address belongs to another coin or network. `--coinbase-sig=TEXT` adds text to
your blocks. Long polling, segwit (BIP 141) and the BIP 34 height rule are
supported. A coin whose node requires a rule this miner does not implement
(Litecoin's MWEB, for example) is refused with a message: mine it through a
pool. Dash-style masternode payments are not supported either.

DigiByte's node makes block templates for one of its algorithms at a time
(its `algo=` setting, scrypt by default); the miner asks it for the one it
mines (`sha256d`, `scrypt`, `skein`, `qubit` or `odo`), so the node needs no
particular setting. Myriad's node cannot be asked: set its `algo=` to the
algorithm you mine (`algo=argon2d` for `-a argon2d4096`, `algo=yescrypt`
for `-a yescrypt`).

Servers that only speak getwork, the protocol getblocktemplate replaced, are
still supported; `--no-gbt` and `--no-getwork` choose between the two.

#### RandomX (Monero)

    minerd -a randomx -o stratum+tcp://pool.example.com:3333 -u WALLET_ADDRESS -p x

Or mine on your own [P2Pool](https://p2pool.io) node, which pays you directly
(start `p2pool` with your wallet address, then point the miner at it):

    minerd -a randomx -o stratum+tcp://127.0.0.1:3333 -u x -p x

RandomX has two modes (`--randomx-mode`):

* **fast** (the default when the machine has the memory): the threads share
  a 2080 MiB dataset, built from a 256 MiB cache when mining starts, and
  again whenever the pool's *seed hash* changes (every 2048 blocks, about
  2.8 days on Monero). Building it takes from a few seconds to a minute or
  two, using every processor; mining pauses meanwhile.
* **light**: only the 256 MiB cache, for machines without 2.5 GB to spare, or
  32-bit systems. Several times slower.

`auto` picks fast mode when the machine (or the container it runs in) has
the dataset, the cache and a gigabyte more. Each thread also needs a 2 MiB
scratchpad, which should fit in the processor's L3 cache: unless `-t` says
otherwise, the miner starts no more threads than the L3 cache holds
scratchpads (and says so), as for CryptoNight.

Large pages make RandomX faster, and on Linux the miner asks for them
(transparent huge pages, which most distributions allow). To reserve real
huge pages instead (a few percent faster again), before starting the miner:

    sudo sysctl -w vm.nr_hugepages=1280

On Windows, large pages need the "Lock pages in memory" user right (*Local
Security Policy → Local Policies → User Rights Assignment*, then sign out and
in again), and the miner then uses them.

The miner tells the pool it mines `rx/0`, refuses jobs for other
algorithms, keeps the top byte of the nonce that NiceHash-style proxies
(xmrig-proxy) set, and sends a keep-alive after a minute of silence from the
pool (giving up on the connection after five).

#### Verthash (Vertcoin)

    minerd -a verthash -o stratum+tcp://pool.example.com:3333 -u ADDRESS -p x

Verthash reads a 1.2 GB data file, `verthash.dat`, at random 4096 times a
hash, so the whole file has to be in memory (1.3 GB with the program). The
miner reads it from `--verthash-data=FILE`, or from `verthash.dat` in the
current directory, or from Vertcoin Core's data directory (`~/.vertcoin`,
`~/Library/Application Support/Vertcoin` or `%APPDATA%\Vertcoin`). If there
is none, it builds one (in 10 to 30 seconds on a typical machine) and saves
it as `verthash.dat` for next time. Either way it checks the data's SHA-256
(`a55531e843cd56b010114aaf6325b0d529ecf88f8ad47639b6ededafd721aa48`), and
refuses a file that does not match.

Each hash waits on memory, not on the processor, so the miner works on four
nonces at a time in each thread (three times the speed of one), and on Linux
puts the data on huge pages: transparent huge pages, or pages reserved with
`sudo sysctl -w vm.nr_hugepages=650`. GPUs mine most of Vertcoin's blocks.
Solo mining works with Vertcoin Core's getblocktemplate, as for Bitcoin.

#### CryptoNight

    minerd -a cryptonight -o stratum+tcp://pool.example.com:3333 -u WALLET_ADDRESS -p x

#### Odocrypt

Odocrypt changes its cipher every 10 days: its key is the block time rounded
down to a multiple of 10 days. Solo mining uses the key the node gives, so
it works on every DigiByte network; with a pool, the key comes from the
block time with the main network's period (testnet's is 1 day).

#### yespower

Coins on yespower 1.0 differ in their N, r and key (personalization
string): give them with `--param-n`, `--param-r` and `--param-key`, as for
cpuminer-opt. Sugarchain, for example:

    minerd -a yespower --param-n=2048 --param-r=32 \
        --param-key="Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote" \
        -o stratum+tcp://POOL:PORT -u ADDRESS -p x

#### Benchmark

    minerd -a x11 --benchmark

#### Configuration file

`-c FILE` reads options from a JSON file that maps long option names to their
values; see [example-cfg.json](example-cfg.json).

#### Connecting through a proxy

Use the `--proxy` option. For a SOCKS proxy, add a `socks4://` or `socks5://`
prefix to the proxy host; `socks4a://` and `socks5h://` resolve host names
through the proxy. Without a prefix, the proxy is taken to be an HTTP proxy.
Without `--proxy`, the `http_proxy` and `all_proxy` environment variables are
honoured.

Credits
=======

cpuminer-multi was forked from pooler's cpuminer and developed by Lucas Jones.

* [tpruvot](https://github.com/tpruvot) added features and the SHA-3 based algorithms
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight
* getblocktemplate support is based on pooler's cpuminer 2.5

Lucas Jones accepted donations for his work on cpuminer-multi at:

* XMR: `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`
* BTC: `139QWoktddChHsZMWZFxmBva4FM96X2dhE`

License
=======

GPLv2 or later. See [COPYING](COPYING) for details.
