# [pwn.college](https://pwn.college)

cryptohack告一段落，跑回来做与我有一面之缘的`pwn.college`。会跳过intro与一些简单的题

rules要求不能给出完整解答，因此这里依旧是我的思路与提示

# [Intro to Cybersecurity](https://pwn.college/intro-to-cybersecurity)

## [Integrated Security](https://pwn.college/intro-to-cybersecurity/integrated-security)

### ECB-to-Shellcode(hard)

漏洞与利用没什么好说的。唯一值得注意的点是，题目没开aslr，于是栈地址也是固定的；但这份“固定”与argv，argc和环境变量等值有关。我习惯用`gdb.debug`调试，这会导致练习环境与实际环境的栈地址不符。解决办法是手动attach gdb找地址，并使用加上`env={}`参数的process，不要用任何wrapper且不要改动输入payload的方式

这是我第一次使用较新版本的pwndbg，发现每次运行时它都会耗费很多时间下载调试符号。可以在`.gdbinit`文件中加上`set debuginfod enabled off`关闭下载