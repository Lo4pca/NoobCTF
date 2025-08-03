# Pwn学习笔记

这里记录一些平时看的和pwn有关的教程里的知识点

## [教程一](https://www.youtube.com/watch?v=CgGha_zLqlo&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)

1. Reversing Statically-Linked Binaries with Function Signatures
- 当elf文件静态包含libc并stripped时，一些libc内的函数名无法被识别。这时可以利用插件+函数签名的方式还原函数名。ida pro可以用[F.L.I.R.T.](https://hex-rays.com/products/ida/tech/flirt/)，放到ghidra可以用[ApplySig](https://github.com/NWMonster/ApplySig),签名文件可以在[sig-database](https://github.com/push0ebp/sig-database)里找到
2. Exploit Dev Pitfall Corrupted Shellcode
- 运行栈上的shellcode时，一定要注意将shellcode和rip隔离（利用nop多滑几段栈）。否则当shellcode内部执行到push时，push进来的内容有可能会覆盖原本的shellcode，导致执行失败
3. Stack grooming and 100% reliable exploit for format0
- 格式化字符串漏洞payload通过调用程序时提供的参数传入时的一些技巧
    - 不能传入null字节，但是可以用空字符串代替
    - 可通过传入大量参数扩张栈
    - 有时可以尝试跳转到两个指令中间的地址处执行，形成新的指令

个人评价：跳着看的，部分内容有些“年代久远”，不太适用于当前的ctf pwn环境。但是对于初学者认识一下是够了。如果有ctf基础的可以选择不看或根据每个视频的名称跳着看

## 如何getshell

新版libc里的几种getshell方式： https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc 。第五种方式（target exit funcs）的更详细介绍： https://sec.prof.ninja/cuttingedge 以及讲解视频 https://capture.udel.edu/media/Targeting+Exit+Funcs/1_dekb3ciz

## FSOP

经典咏流传：fsop相关文章
- https://blog.kylebot.net/2022/10/22/angry-FSROP
- https://niftic.ca/posts/fsop

## ret2dlresolve

- https://acad.garywei.dev/blog/2022/ctf-zip-parser
- https://blog.csdn.net/qq_51868336/article/details/114644569