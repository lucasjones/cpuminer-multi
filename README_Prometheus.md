# Prometheus: Add README for cpuminer-multi

## Project Overview

CPUMiner-Multi is a high-performance, multi-threaded CPU cryptocurrency mining software designed to support multiple mining algorithms across various cryptocurrencies.

### Key Features
- Multi-algorithm support for cryptocurrencies, including:
  * Scrypt-based coins (Litecoin, Dogecoin)
  * SHA256d-based coins (Bitcoin, Peercoin)
  * X11, X13, X14, X15 algorithm coins
  * CryptoNight coins (Bytecoin, Monero)
  * And many more specialized algorithms

### Purpose
The primary purpose of this miner is to provide an efficient, open-source solution for CPU-based cryptocurrency mining. It allows miners to:
- Mine multiple cryptocurrency types using a single tool
- Optimize mining performance through multi-threading
- Support a wide range of CPU architectures (x86, x86-64, ARM)

### Benefits
- Highly compatible with various cryptocurrency algorithms
- Supports advanced CPU instruction sets (SSE2, AVX, AVX2, XOP)
- Open-source and actively maintained
- Flexible configuration options
- Cross-platform support (Linux, Windows, potentially others)

Forked from the original CPUMiner by pooler and further developed by Lucas Jones and contributors, this tool continues to evolve to meet the needs of cryptocurrency miners.

## Getting Started, Installation, and Setup

### Prerequisites

Before installing CPUMiner-Multi, ensure you have the following dependencies:
- libcurl (development libraries)
- OpenSSL (development libraries)
- GCC or Clang compiler
- autoconf and automake (for building from source)

### Installation Options

#### Linux/Unix Installation

1. Clone the repository:
```bash
git clone https://github.com/LucasJones/cpuminer-multi.git
cd cpuminer-multi
```

2. Prepare the build environment:
```bash
./autogen.sh
```

3. Configure the build (optional optimization):
```bash
./configure CFLAGS="-march=native"
```
   Note: Use `-march=native` only if building for the current machine.

4. Compile the miner:
```bash
make
```

#### Windows Installation (MinGW)

1. Install MinGW and MSYS Developer Tool Kit
2. Install dependencies:
   - pthreads-w64
   - libcurl development libraries
   - OpenSSL development libraries

3. In the MSYS shell, build the miner:
```bash
./autogen.sh
LIBCURL="-lcurldll" ./configure CFLAGS="-march=native"
make
```

### Quick Start

Run the miner with basic configuration:
```bash
./minerd -a algorithm -o mining_pool_url -u username -p password
```

Replace the following:
- `algorithm`: mining algorithm (e.g., scrypt, sha256d, x11)
- `mining_pool_url`: URL of the mining pool
- `username`: your mining account username
- `password`: your mining account password

#### Example Usage
```bash
# Mine Litecoin using Scrypt algorithm
./minerd -a scrypt -o stratum+tcp://litecoin.pool.com:3333 -u username -p password
```

### Advanced Configuration

For detailed configuration options, run:
```bash
./minerd --help
```

### Platform-Specific Notes

#### ARM
- No runtime CPU detection
- To use NEON instructions, add `-mfpu=neon` to CFLAGS during configuration

#### x86/x86-64
- Supports SSE2, AVX, AVX2, and XOP instructions where available
- Checks CPU and OS support for advanced instruction sets