#include "cpuminer-config.h"

#if defined(__linux__) && defined(__ELF__)
    .section .note.GNU-stack,"",%progbits
#endif

    .text
    .p2align 6
    .globl fast_aesb_single_round
    .globl _fast_aesb_single_round
fast_aesb_single_round:
_fast_aesb_single_round:
    ret

    .text
    .p2align 6
    .globl fast_aesb_pseudo_round_mut
    .globl _fast_aesb_pseudo_round_mut
fast_aesb_pseudo_round_mut:
_fast_aesb_pseudo_round_mut:
    ret

    .text
    .globl mul128
    .globl _mul128
mul128:
_mul128:
#if defined(_WIN32) || defined(__CYGWIN__)
	mov %rcx, %rax
	mul %rdx
	mov %r8, (%r8)
#else
	mov %rdx, %r8
	mov %rdi, %rax
	mul %rsi
	mov %rdx, (%r8)
#endif
	ret
