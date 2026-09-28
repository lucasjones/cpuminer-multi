/*
 * Which instruction set extensions the processor has, and the operating
 * system supports, for the code that picks its implementation at run time.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#if (defined(__x86_64__) || defined(__i386__)) && \
	(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
#include <cpuid.h>

#define CPU_X86 1

/* cpuid leaf 1 ecx/edx, leaf 7 ebx, and XCR0 (the registers the system
 * saves) */
static void cpu_x86_features(unsigned *ecx1, unsigned *edx1, unsigned *ebx7,
		unsigned *xcr0)
{
	unsigned eax, ebx, ecx, edx, lo = 0, hi = 0;

	*ecx1 = *edx1 = *ebx7 = *xcr0 = 0;
	if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
		return;
	*ecx1 = ecx;
	*edx1 = edx;
	if (ecx & (1u << 27)) {		/* OSXSAVE: XGETBV works */
		__asm__ ("xgetbv" : "=a" (lo), "=d" (hi) : "c" (0));
		*xcr0 = lo;
	}
	if (__get_cpuid_max(0, NULL) >= 7) {
		__cpuid_count(7, 0, eax, ebx, ecx, edx);
		*ebx7 = ebx;
	}
	(void) hi;
}
#endif

bool cpu_has_sse2(void)
{
#if defined(__SSE2__)
	return true;
#elif defined(CPU_X86)
	unsigned ecx1, edx1, ebx7, xcr0;

	cpu_x86_features(&ecx1, &edx1, &ebx7, &xcr0);
	return (edx1 & (1u << 26)) != 0;
#else
	return false;
#endif
}

/* AVX2, with the AVX registers saved by the system */
bool cpu_has_avx2(void)
{
#ifdef CPU_X86
	unsigned ecx1, edx1, ebx7, xcr0;

	cpu_x86_features(&ecx1, &edx1, &ebx7, &xcr0);
	return (ecx1 & (1u << 28))		/* AVX */
		&& (xcr0 & 0x6) == 0x6		/* XMM and YMM state */
		&& (ebx7 & (1u << 5));		/* AVX2 */
#else
	return false;
#endif
}

/* AVX-512 Foundation and Vector Length extensions (and AVX2), with the
 * AVX-512 registers saved by the system */
bool cpu_has_avx512vl(void)
{
#ifdef CPU_X86
	unsigned ecx1, edx1, ebx7, xcr0;

	cpu_x86_features(&ecx1, &edx1, &ebx7, &xcr0);
	return cpu_has_avx2()
		&& (xcr0 & 0xe6) == 0xe6	/* and opmask, ZMM state */
		&& (ebx7 & (1u << 16))		/* AVX512F */
		&& (ebx7 & (1u << 31));		/* AVX512VL */
#else
	return false;
#endif
}

#ifdef __linux__
/* the first line of a small file, without its newline; false if none */
static bool read_line(const char *path, char *buf, size_t len)
{
	FILE *f = fopen(path, "r");
	bool ok;

	if (!f)
		return false;
	ok = fgets(buf, (int) len, f) != NULL;
	fclose(f);
	if (ok)
		buf[strcspn(buf, "\n")] = '\0';
	return ok;
}

/* how many processors a list such as "0-3,8-11" names */
static int cpu_list_count(const char *list)
{
	int n = 0;

	while (*list) {
		char *end;
		long first = strtol(list, &end, 10), last = first;

		if (end == list)
			break;
		if (*end == '-')
			last = strtol(end + 1, &end, 10);
		if (last >= first)
			n += (int) (last - first + 1);
		list = *end == ',' ? end + 1 : end;
		if (*end != ',')
			break;
	}
	return n;
}
#endif

/*
 * All the processor's level 3 caches together, in bytes, or 0 if unknown.
 * Algorithms with a 2 MiB scratchpad per thread (CryptoNight, RandomX) are
 * slowed down, not sped up, by threads whose scratchpads do not fit in it.
 */
uint64_t cpu_l3_cache_size(void)
{
#if defined(__linux__)
	uint64_t total = 0;
	char path[96], buf[256];
	int cpu, idx;

	/* each processor's share of each cache it uses */
	for (cpu = 0; cpu < 65536; cpu++) {
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index0/level", cpu);
		if (!read_line(path, buf, sizeof(buf)))
			break;
		for (idx = 0; idx < 16; idx++) {
			unsigned long long size;
			char *unit;
			int sharing;

			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, idx);
			if (!read_line(path, buf, sizeof(buf)))
				break;
			if (atoi(buf) != 3)
				continue;
			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index%d/size", cpu, idx);
			if (!read_line(path, buf, sizeof(buf)))
				continue;
			size = strtoull(buf, &unit, 10);
			if (*unit == 'K')
				size <<= 10;
			else if (*unit == 'M')
				size <<= 20;
			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", cpu, idx);
			sharing = read_line(path, buf, sizeof(buf)) ? cpu_list_count(buf) : 1;
			total += size / (sharing > 0 ? sharing : 1);
		}
	}
	return total;
#elif defined(_WIN32)
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION *info;
	DWORD len = 0, i;
	uint64_t total = 0;

	GetLogicalProcessorInformation(NULL, &len);
	info = len ? malloc(len) : NULL;
	if (!info)
		return 0;
	if (GetLogicalProcessorInformation(info, &len))
		for (i = 0; i < len / sizeof(*info); i++)
			if (info[i].Relationship == RelationCache && info[i].Cache.Level == 3)
				total += info[i].Cache.Size;
	free(info);
	return total;
#elif defined(__APPLE__)
	uint64_t size = 0;
	size_t len = sizeof(size);

	if (sysctlbyname("hw.l3cachesize", &size, &len, NULL, 0) || len != sizeof(size))
		return 0;
	return size;
#else
	return 0;
#endif
}

#ifdef __linux__
/* the memory limit of the container (cgroup) the miner runs in, if any:
 * more than it would get the miner killed */
static uint64_t cgroup_memory_limit(void)
{
	static const char *const files[] = {
		"/sys/fs/cgroup/memory.max",			/* cgroup v2 */
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",	/* cgroup v1 */
	};
	unsigned i;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		FILE *f = fopen(files[i], "r");
		unsigned long long limit;
		int n;

		if (!f)
			continue;
		n = fscanf(f, "%llu", &limit);
		fclose(f);
		/* "max", or v1's "unlimited" (close to 2^63) */
		if (n == 1 && limit < (1ULL << 60))
			return limit;
	}
	return 0;
}
#endif

/* the memory the miner may use, in bytes: the machine's, or its
 * container's limit; 0 if unknown */
uint64_t system_memory(void)
{
#ifdef _WIN32
	MEMORYSTATUSEX ms;

	ms.dwLength = sizeof(ms);
	return GlobalMemoryStatusEx(&ms) ? ms.ullTotalPhys : 0;
#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
	long pages = sysconf(_SC_PHYS_PAGES), size = sysconf(_SC_PAGESIZE);
	uint64_t mem = pages > 0 && size > 0 ? (uint64_t) pages * (uint64_t) size : 0;
#ifdef __linux__
	uint64_t limit = cgroup_memory_limit();

	if (limit && (!mem || limit < mem))
		mem = limit;
#endif
	return mem;
#else
	return 0;
#endif
}
