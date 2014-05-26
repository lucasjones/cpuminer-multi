#include "cpuminer-config.h"

#if defined(__linux__) && defined(__ELF__)
    .section .note.GNU-stack,"",%progbits
#endif

    .text
    .globl mul128
    .globl _mul128
mul128:
_mul128:
#if defined(_WIN64) || defined(__CYGWIN__)
	mov %rcx, %rax
	mul %rdx
	mov %rdx, (%r8)
#else
	mov %rdx, %r8
	mov %rdi, %rax
	mul %rsi
	mov %rdx, (%r8)
#endif
	ret
