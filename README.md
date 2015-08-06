CPUMiner-Multi
==============

[![Build Status](https://travis-ci.org/lucasjones/cpuminer-multi.svg?branch=master)](https://travis-ci.org/lucasjones/cpuminer-multi)

This is a multi-threaded CPU miner,
fork of [pooler](//github.com/pooler)'s cpuminer (see AUTHORS for list of contributors).

#### Table of contents

* [Algorithms](#algorithms)
* [Dependencies](#dependencies)
* [Download](#download)
* [Build](#build)
* [Usage instructions](#usage-instructions)
* [Donations](#donations)
* [Credits](#credits)
* [License](#license)

Algorithms
==========
#### Currently supported
 * ✓ __scrypt__ (Litecoin, Dogecoin, Feathercoin, etc..)
 * ✓ __scrypt:N__ (Vertcoin [VTC])
 * ✓ __sha256d__ (Bitcoin, Freicoin, Peercoin/PPCoin, Terracoin, etc..)
 * ✓ __x11__ (Darkcoin [DRK], Hirocoin, Limecoin)
 * ✓ __x13__ (Sherlockcoin, [ACE], [B2B], [GRC], [XHC], etc..)
 * ✓ __x14__ (X14, Webcoin [WEB])
 * ✓ __x15__ (RadianceCoin [RCE])
 * ✓ __cryptonight__ (Bytecoin [BCN], Monero)
 * ✓ __fresh__ (FreshCoin)

#### Implemented, but untested
 * ? keccak (Maxcoin  HelixCoin, CryptoMeth, Galleon, 365coin, Slothcoin, BitcointalkCoin)
 * ? hefty1 (Heavycoin)
 * ? quark (Quarkcoin)
 * ? skein (Skeincoin, Myriadcoin)
 * ? shavite3 (INKcoin)
 * ? blake (Blakecoin)

#### Planned support for
 * *scrypt-jane* (YaCoin, CopperBars, Pennies, Tickets, etc..)
 * *qubit* (Qubitcoin, Myriadcoin)
 * *groestl* (Groestlcoin)

Dependencies
============
* libcurl			http://curl.haxx.se/libcurl/
* jansson			http://www.digip.org/jansson/ (jansson is included in-tree)
* openssl           https://www.openssl.org/

Download
========
* Binary releases: https://github.com/LucasJones/cpuminer-multi/releases
* Git tree:   https://github.com/LucasJones/cpuminer-multi
  * Clone with `git clone https://github.com/LucasJones/cpuminer-multi`

Build
=====

#### Basic *nix build instructions:
 * ./autogen.sh	# only needed if building from git repo
 * ./nomacro.pl	# only needed if building on Mac OS X or with Clang
 * ./configure CFLAGS="*-march=native*"
   * # Use -march=native if building for a single machine
 * make

#### Notes for AIX users:
 * To build a 64-bit binary, export OBJECT_MODE=64
 * GNU-style long options are not supported, but are accessible via configuration file

#### Basic Windows build instructions, using MinGW:
 * Install MinGW and the MSYS Developer Tool Kit (http://www.mingw.org/)
   * Make sure you have mstcpip.h in MinGW\include
 * If using MinGW-w64, install pthreads-w64
 * Install libcurl devel (http://curl.haxx.se/download.html)
   * Make sure you have libcurl.m4 in MinGW\share\aclocal
   * Make sure you have curl-config in MinGW\bin
 * Install openssl devel (https://www.openssl.org/related/binaries.html)
 * In the MSYS shell, run:
   * ./autogen.sh	# only needed if building from git repo
   * LIBCURL="-lcurldll" ./configure CFLAGS="*-march=native*"
     * # Use -march=native if building for a single machine
   * make

#### Architecture-specific notes:
 * ARM:
   * No runtime CPU detection. The miner can take advantage of some instructions specific to ARMv5E and later processors, but the decision whether to use them is made at compile time, based on compiler-defined macros.
   * To use NEON instructions, add "-mfpu=neon" to CFLAGS.
 * x86:
   * The miner checks for SSE2 instructions support at runtime, and uses them if they are available.
 * x86-64:	
   * The miner can take advantage of AVX, AVX2 and XOP instructions, but only if both the CPU and the operating system support them.
     * Linux supports AVX starting from kernel version 2.6.30.
     * FreeBSD supports AVX starting with 9.1-RELEASE.
     * Mac OS X added AVX support in the 10.6.8 update.
     * Windows supports AVX starting from Windows 7 SP1 and Windows Server 2008 R2 SP1.
   * The configure script outputs a warning if the assembler doesn't support some instruction sets. In that case, the miner can still be built, but unavailable optimizations are left off.

Usage instructions
==================
Run "minerd --help" to see options.

### Connecting through a proxy

Use the --proxy option.

To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host  
Protocols socks4a and socks5h, allowing remote name resolving, are also available since libcurl 7.18.0.

If no protocol is specified, the proxy is assumed to be a HTTP proxy.  
When the --proxy option is not used, the program honors the http_proxy and all_proxy environment variables.

Donations
=========
Donations for the work done in this fork are accepted at
* MRO: `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`
* BTC: `139QWoktddChHsZMWZFxmBva4FM96X2dhE`

Credits
=======
CPUMiner-multi was forked from pooler's CPUMiner, and has been developed by Lucas Jones.
* [tpruvot](https://github.com/tpruvot) added some features and recent SHA3 based algorythmns
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight

License
=======
GPLv2.  See COPYING for details.
