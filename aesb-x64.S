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
    movdqa (%rcx), %xmm1
    aesenc (%r8), %xmm1
    movdqa %xmm1, (%rdx)
#else
    movdqa (%rdi), %xmm1
    aesenc (%rdx), %xmm1
    movdqa %xmm1, (%rsi)
#endif
    ret

    .text
    .p2align 6
    .globl fast_aesb_pseudo_round_mut
    .globl _fast_aesb_pseudo_round_mut
fast_aesb_pseudo_round_mut:
_fast_aesb_pseudo_round_mut:
#if defined(_WIN64) || defined(__CYGWIN__)
    mov %rdx, %r9
    add $0xA0, %r9
    movdqa (%rcx), %xmm1
 
    .LOOP:
            aesenc (%rdx), %xmm1
            add $0x10, %rdx
			cmp %r9, %rdx
            jl .LOOP

    movdqa %xmm1, (%rcx)
#else
    mov %rsi, %r9
    add $0xA0, %r9
    movdqa (%rdi), %xmm1
 
    .LOOP:
            aesenc (%rsi), %xmm1
            add $0x10, %rsi
            cmp %r9, %rsi
            jl .LOOP

    movdqa %xmm1, (%rdi)
#endif
    ret

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
	
	.text
	.p2align 4
	.globl aesni_parallel_noxor
# void aesni_parallel_noxor(void *output, uint8_t *input, uint8_t *expkey)
aesni_parallel_noxor:
	mov $10, %r9
	movdqa (%rsi), %xmm0
	movdqa 0x10(%rsi), %xmm1
	movdqa 0x20(%rsi), %xmm2
	movdqa 0x30(%rsi), %xmm3
	movdqa 0x40(%rsi), %xmm4
	movdqa 0x50(%rsi), %xmm5
	movdqa 0x60(%rsi), %xmm6
	movdqa 0x70(%rsi), %xmm7
	
	.ENCRYPT:
		aesenc (%rdx), %xmm0
		aesenc (%rdx), %xmm1
		aesenc (%rdx), %xmm2
		aesenc (%rdx), %xmm3
		aesenc (%rdx), %xmm4
		aesenc (%rdx), %xmm5
		aesenc (%rdx), %xmm6
		aesenc (%rdx), %xmm7
		add $0x10, %rdx
		dec %r9
		jnz .ENCRYPT
	
	movdqa %xmm0, (%rdi)
	movdqa %xmm1, 0x10(%rdi)
	movdqa %xmm2, 0x20(%rdi)
	movdqa %xmm3, 0x30(%rdi)
	movdqa %xmm4, 0x40(%rdi)
	movdqa %xmm5, 0x50(%rdi)
	movdqa %xmm6, 0x60(%rdi)
	movdqa %xmm7, 0x70(%rdi)
	
	movdqa %xmm0, (%rsi)
	movdqa %xmm1, 0x10(%rsi)
	movdqa %xmm2, 0x20(%rsi)
	movdqa %xmm3, 0x30(%rsi)
	movdqa %xmm4, 0x40(%rsi)
	movdqa %xmm5, 0x50(%rsi)
	movdqa %xmm6, 0x60(%rsi)
	movdqa %xmm7, 0x70(%rsi)
	
	ret

	.text
	.p2align 4
	.globl aesni_parallel_xor
# void aesni_parallel_xor(void *state, uint8_t *expkey, uint8_t *xorval)
aesni_parallel_xor:
	mov $10, %r9
	movdqa (%rdi), %xmm0
	movdqa 0x10(%rdi), %xmm1
	movdqa 0x20(%rdi), %xmm2
	movdqa 0x30(%rdi), %xmm3
	movdqa 0x40(%rdi), %xmm4
	movdqa 0x50(%rdi), %xmm5
	movdqa 0x60(%rdi), %xmm6
	movdqa 0x70(%rdi), %xmm7
	
	pxor (%rdx), %xmm0
	pxor 0x10(%rdx), %xmm1
	pxor 0x20(%rdx), %xmm2
	pxor 0x30(%rdx), %xmm3
	pxor 0x40(%rdx), %xmm4 
	pxor 0x50(%rdx), %xmm5
	pxor 0x60(%rdx), %xmm6 
	pxor 0x70(%rdx), %xmm7
	
	.ENCRYPT2:
		aesenc (%rsi), %xmm0
		aesenc (%rsi), %xmm1
		aesenc (%rsi), %xmm2
		aesenc (%rsi), %xmm3
		aesenc (%rsi), %xmm4
		aesenc (%rsi), %xmm5
		aesenc (%rsi), %xmm6
		aesenc (%rsi), %xmm7
		add $0x10, %rsi
		dec %r9
		jnz .ENCRYPT2
	
	movdqa %xmm0, (%rdi)
	movdqa %xmm1, 0x10(%rdi)
	movdqa %xmm2, 0x20(%rdi)
	movdqa %xmm3, 0x30(%rdi)
	movdqa %xmm4, 0x40(%rdi)
	movdqa %xmm5, 0x50(%rdi)
	movdqa %xmm6, 0x60(%rdi)
	movdqa %xmm7, 0x70(%rdi)
	
	ret
