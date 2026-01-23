.text

.globl _start

_start:
	mov $0x61, %r9
	push %r9
	mov %rsp, %rsi
	mov $0x1, %rdx
	mov $0x1, %rax
	syscall

