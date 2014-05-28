CPUMiner-Multi
==============

This is a multi-threaded CPU miner, fork of [LucasJones](//github.com/lucasjones)' cpuminer-multi.

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
 * ✓ __sha256d__ (Bitcoin, Freicoin, Peercoin/PPCoin, Terracoin, etc..)
 * ✓ __x11__ (Darkcoin [DRK], Hirocoin, Limecoin)
 * ✓ __cryptonight__ (Bytecoin [BCN], Monero)

#### Implemented, but untested
 * ? keccak (Maxcoin  HelixCoin, CryptoMeth, Galleon, 365coin, Slothcoin, BitcointalkCoin)
 * ? hefty1 (Heavycoin)
 * ? quark (Quarkcoin)
 * ? skein (Skeincoin, Myriadcoin)
 * ? shavite3 (INKcoin)
 * ? blake (Blakecoin)

Dependencies
============
* libcurl			http://curl.haxx.se/libcurl/
* jansson			http://www.digip.org/jansson/ (jansson is included in-tree)
* openssl			https://www.openssl.org/

Download
========
* Binary releases: None yet
* Git tree:   https://github.com/wolf9466/cpuminer-multi
* Clone with `git clone https://github.com/wolf9466/cpuminer-multi`

Build
=====

#### Basic *nix build instructions:
 * ./autogen.sh	# only needed if building from git repo
 * Optimal GCC flags are built in - you only need to use -march=native if you want it
 * ./configure CFLAGS="*-march=native*"
   * # Use -march=native if building for a single machine
 * make

#### Architecture-specific notes:
 * CryptoNight works only on x86 and x86-64.
 * If you don't have AES-NI, it's slow. This implementation is deprecated and will not be improved.
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
* MRO: `43jtN2e88d4ayn7gxsLwB94fmYzLuXymuGdJxotnvYsCaK3UuhvQRNgKrZUD4i5kxTRtpz49FrB1e2KYiXu4TNyEEGUwu9E`
* BTC: `1WoLFumNUvjCgaCyjFzvFrbGfDddYrKNR`

Credits
=======
This faster CPUMiner-multi was forked from LucasJones', and has been developed by Wolf.
Special thanks to Intel for helping me with the usage of the AESKEYGENASSIST instruction, which I used to replace the calls to the slow, unoptimized oaes_lib.

License
=======
GPLv2.  See COPYING for details.
