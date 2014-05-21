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
#if defined(_WIN64) || defined(__CYGWIN__)
    movdqu (%rcx), %xmm1
    aesenc (%r8), %xmm1
    movdqu %xmm1, (%rdx)
#else
    movdqu (%rdi), %xmm1
    aesenc (%rdx), %xmm1
    movdqu %xmm1, (%rsi)
#endif
    ret

    .text
    .p2align 6
    .globl fast_aesb_pseudo_round_mut
    .globl _fast_aesb_pseudo_round_mut
fast_aesb_pseudo_round_mut:
_fast_aesb_pseudo_round_mut:
#if defined(_WIN64) || defined(__CYGWIN__)
    mov $0, %r9
    mov $10, %r10
    movdqu (%rcx), %xmm1
 
    .LOOP:
            aesenc (%rdx), %xmm1
            add $0x10, %rdx
            inc %r9
            cmp %r10, %r9
            jl .LOOP

    movdqu %xmm1, (%rcx)
#else
    mov $0, %r9
    mov $10, %r10
    movdqu (%rdi), %xmm1
 
    .LOOP:
            aesenc (%rsi), %xmm1
            add $0x10, %rsi
            inc %r9
            cmp %r10, %r9
            jl .LOOP

    movdqu %xmm1, (%rdi)
#endif
    ret
