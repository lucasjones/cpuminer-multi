# Prometheus: Add README for cpuminer-multi

## Project Overview

CPUMiner-Multi is a high-performance, multi-threaded CPU cryptocurrency mining software designed to support a wide range of mining algorithms. This open-source miner provides an efficient solution for miners looking to leverage their CPU's computational power across multiple cryptocurrency networks.

#### Key Features
- Multi-threaded architecture for optimal CPU utilization
- Support for multiple cryptocurrency mining algorithms, including:
  * Scrypt (Litecoin, Dogecoin)
  * SHA256d (Bitcoin)
  * X11, X13, X14, X15 (Various altcoins)
  * CryptoNight (Bytecoin, Monero)
  * And many more specialized algorithms

#### Benefits
- Cross-platform compatibility (Linux, Windows, macOS)
- Supports various CPU architectures (x86, x86-64, ARM)
- Advanced instruction set optimization (SSE2, AVX, AVX2, XOP)
- Flexible proxy support for network configuration
- Open-source and community-driven development

The miner is particularly useful for cryptocurrency enthusiasts and miners who want to utilize their CPU's processing power efficiently across different mining algorithms and blockchain networks.

## Getting Started, Installation, and Setup

### Prerequisites

Before installing, ensure you have the following dependencies:
- libcurl (http://curl.haxx.se/libcurl/)
- OpenSSL (https://www.openssl.org/)

### Installation Methods

#### Linux/Unix Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/LucasJones/cpuminer-multi
   cd cpuminer-multi
   ```

2. Prepare the build environment:
   ```bash
   ./autogen.sh
   ```

3. Configure the build:
   ```bash
   ./configure CFLAGS="-march=native"
   ```
   Note: Use `-march=native` if building for the current machine.

4. Compile the miner:
   ```bash
   make
   ```

#### Windows Installation (MinGW)
1. Install:
   - MinGW
   - MSYS Developer Tool Kit
   - pthreads-w64 (for MinGW-w64)
   - libcurl development files
   - OpenSSL development files

2. In the MSYS shell, run:
   ```bash
   ./autogen.sh
   LIBCURL="-lcurldll" ./configure CFLAGS="-march=native"
   make
   ```

### Quick Start

Run the miner with basic configuration:
```bash
./minerd --help  # View all available options
```

### Platform-Specific Notes

#### ARM
- No runtime CPU detection
- To use NEON instructions, add `-mfpu=neon` to CFLAGS during configuration

#### x86/x86-64
- Supports SSE2, AVX, AVX2, and XOP instructions
- Instruction support depends on CPU and operating system
- Checks for SSE2 support at runtime

### Proxy Support

Connect through a proxy using the `--proxy` option:
```bash
./minerd --proxy socks5://proxyhost:port
```

Supports:
- HTTP proxies
- SOCKS4 and SOCKS5 proxies
- Environment variables `http_proxy` and `all_proxy`