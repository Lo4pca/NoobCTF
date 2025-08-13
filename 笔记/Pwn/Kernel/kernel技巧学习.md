# kernel技巧学习

我爱挖坑（heap：你不看看我吗？），但我不填

## Windows

虽然我觉得不会遇见几道windows题……

### [Windows Kernel Address Leaks](https://github.com/sam-b/windows_kernel_address_leaks)

一些泄漏windows kernel地址的方法。部分方法放到最新版windows已经没法用了，比如NtQuerySystemInformation系列。不过要是能伪造当前进程`_EPROCESS`结构里的`_TOKEN`结构还是可以的。见[Process Flipper](https://github.com/MochiNishimiya/Project-Sekai-2024)

一些新版本的改动信息： https://windows-internals.com/kaslr-leaks-restriction

### NtQueryInformationToken 任意地址读

NtQueryInformationToken函数里请求TokenBnoIsolation时，会获取进程的`_TOKEN`结构。后续会将`_TOKEN`结构里的一个buffer内容拷贝给用户。如果能修改或伪造`_TOKEN`结构（主要是修改那个buffer的地址），就能读取任意地址处任意长度的数据。见[Process Flipper](https://github.com/MochiNishimiya/Project-Sekai-2024)

### DiskCounters任意地址读

DiskCounters是`_EPROCESS`结构里的一个字段，为一个指向`PROCESS_DISK_COUNTERS`结构的指针。`PROCESS_DISK_COUNTERS`结构里有个BytesWritten字段，在低权限Medium integrity用户进程中用NtQuerySystemInformation下的SystemProcessInformation可以泄漏里面的内容

似乎也可以用来写，但不确定是否是任意地址（这个确定）写任意内容（可能只能写固定无法控制的值）

## Linux

### [Overwriting modprobe_path](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)

modprobe在install或者uninstall新模块进linux kernel时会被执行。其路径默认为/sbin/modprobe。可通过以下命令获得其路径：
```sh
cat /proc/sys/kernel/modprobe
```
kernel里也有个名为modprobe_path的全局symbol记录其路径。这个symbol位于可写的内存页，可通过/proc/kallsyms获取其地址（kaslr情况下地址每次都不一样）
```sh
cat /proc/kallsyms | grep modprobe_path
```
当我们执行一个未知类型的文件时，该程序会被调用。更准确地说，如果我们对一个系统未知的文件头（file signature，magic header）调用execve()，最终会调用到modprobe
1. do_execve()
2. do_execveat_common()
3. bprm_execve()
4. exec_binprm()
5. search_binary_handler()
6. request_module()
7. call_modprobe()

长话短说，modprobe_path存储的路径所指向的文件会在system尝试调用未知文件类型的文件时被调用。当我们获取到任意地址写时，把modprobe_path覆盖成我们自己写的getshell脚本，然后执行一个未知类型的文件即可获取root权限的rce（rce内容为shell脚本里的内容）。

这个技巧的前置条件：
1. 已知modprobe_path的地址
2. 已知kpti_trampoline的地址（覆盖modprobe_path后返回userland）
3. 拥有任意地址写

modprobe_path和kpti_trampoline均不受FG-KASLR影响。

在大部分linux系统中，/tmp文件夹无论任何user都可以自由读写。因此可以把shell脚本放到这下面。

总结利用手法：
1. 构造ropchain，覆盖modprobe_path（文件名转成小端hex直接放进ropchain即可）并调用kpti_trampoline返回userland的getshell函数
2. getshell函数中用system准备shell脚本（应该提前准备好也行）+未知文件并执行未知文件
```c
system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
system("chmod +x /tmp/x");
system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
system("chmod +x /tmp/dummy");
system("/tmp/dummy");
system("cat /tmp/flag");
```
完整exp：https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/modprobe.c

kernel新版本(6.14.0)后无法再用以上方式触发，但仍存在其他的触发方式： https://naup.mygo.tw/2025/06/30/Linux-Kernel-Patched-exec-remove-legacy-custom-binfmt-modules-autoloading

### [Cross-Cache attack](https://xz.aliyun.com/t/12898)

Cross-Cache attack个人其实没找到明确定义，只在标题的文章中看见作者提了一嘴。大概是：说每个结构体/object都有对应的slab管理器，而kernel中常用的攻击手法——堆喷——目标是让kernel中的某一个重要结构体与我们能控制的内存重合（是吧？）。那要是题目中所有结构体所在的slab里没有可以利用的重要结构体，就寄了？并没有。在这篇[文章](https://brieflyx.me/2020/heap/linux-kernel-slab-101/)中可以看到slab在内存中以页为单位存在。如果我们free某个内存页中所有的结构体，使整个内存页完全空闲，kernel就会回收这个内存页。这时我们分配一个重要结构体，kernel就会把刚才那个回收的内存页用做这个结构体所在的slab。至此我们成功让某个内存页出现在了两个slab中，即“cross”

找到了，详细解析在这： https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary

### [pipe-primitive](https://github.com/veritas501/pipe-primitive)
利用pipe_buffer结构体实现任意文件写。参考 https://kaligulaarmblessed.github.io/post/palindromatic-biosctf2024/ 的DirtyPipe章节。说是pipe_buffer结构体里有个PIPE_BUF_FLAG_CAN_MERGE标志。当某些文件内容被写入pipe_buffer且长度不足以填满一个page时，其内容会被添加到已经存在的page（ring中上一个pipe_buffer的page。至于ring是什么，这里截一段原文：`The actual pipe_buffer object that is allocated is actually a ring of pipe_buffer structs. Initially the object is empty, when its written to for the first time, a pipe_buffer is added to the ring.`）而不是新分配一个，前提是这些pipe_buffer设置了PIPE_BUF_FLAG_CAN_MERGE标志。从pipe读取数据不会取消设置标志

内核里还有个splice函数，可以从两个文件描述符中转移数据。所以我们可以splice一个文件，如`/etc/passwd`，这时会在ring里新增一个pipe_buffer。然后用诸如UAF的方法尝试泄漏这个新增的pipe_buffer，紧接着构造一个假的pipe_buffer，同时设置PIPE_BUF_FLAG_CAN_MERGE标志。然后往这个pipe_buffer里写东西，就会被添加到ring中上一个pipe_buffer的page，即刚才打开的/etc/passwd。这段参考了 https://blog.bi0s.in/2024/02/26/Pwn/bi0sCTF24-palindromatic

好像读写都可以： https://www.interruptlabs.co.uk/articles/pipe-buffer

### [userfaultfd + setxattr universal heap spray](https://duasynt.com/blog/linux-kernel-heap-spray)

链接指向的文章在后半部分才开始介绍这个技巧。前半部分介绍了常用的`msgsnd` spray，也可以看看。利用`msgsnd` spray的缺点在于，无法控制spray的object大小，也没法完全控制object的内容

setxattr函数比较特殊，同时包含了spray需要的kmalloc和kfree，甚至可以控制kmalloc的object的大小和内容。然而kmalloc和kfree在一条路径里，等于说malloc完直接就free了。我们肯定希望object被free的时机由我们控制，因此需要usefaultfd，这玩意可以设置page fault handler。可以分配两个相邻的page，并把目标object（要写入spray object的内容）置于两者之间。使用usefaultfd在第二个page设置page fault handler后，当setxattr函数触发第二个page处的page fault时（其实就是对该page的读、写操作），程序流转入我们设置的page fault handler。假如handler内部是sleep函数，程序流就会卡在这里，也就不会往下走到kfree了。在这期间把UAF的利用路线走完即可

至于为什么要两个page：因为第一个没使用usefaultfd的page中的page fault仍然由kernel处理，里面的内容可以正常拷贝进spray的object中。所以page 1里的内容是我们希望写入spray object中的，page 2里的内容则不重要（纯纯用来触发page fault handler）

这个技巧的重点是卡住程序的执行。所以不一定要用userfaultfd，像[dead-pwners-society](https://kaligulaarmblessed.github.io/post/dead-pwners-society)里一样用FUSE(Filesystem in UserSpacE)也行（前提是kernel配置项`CONFIG_FUSE_FS`启用）。kernel里有个保护项`CONFIG_USERFAULTFD=n`，表示不能使用usefaultfd，这时就要用FUSE了。FUSE允许用户创建自己的文件系统，并在不改动内核代码的前提前编写自己的系统调用handler。于是我们用FUSE文件系统注册一个文件，用这个文件的fd作为mmap函数的参数映射处一块内存，称之为B。然后正常mmap一块内存A。后面的东西就很眼熟了，将目标object放置于两者中间，等到setxattr于内存B执行读操作时，程序流暂停，转入我们给FUSE写的系统调用handler

wp里自定义了FUSE的read操作，用socketpair阻碍程序流运行。只要不往socketpair里写东西，读取操作就会一直卡在那。等UAF利用成功后再往里写东西即可继续程序流的运行

注意要用多线程，因为阻碍程序流时整个线程都是停滞的

### [User Space Mapping Attack (USMA)](https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-YongLiu-USMA-Share-Kernel-Code-wp.pdf)

[dead-pwners-society](https://kaligulaarmblessed.github.io/post/dead-pwners-society)里有这个技巧的简单介绍

此技巧依赖于覆盖packet_mmap函数里的内核堆指针数组pg_vec对象。当在一个socket fd上调用mmap时，kernel内部会调用packet_mmap，从pg_vec数组中获取一个地址。计算完这个地址对应的物理页（physical page）后，将该页传入`vm_insert_page`函数。这个函数的作用是将该页插入当前进程的虚拟地址空间

但是吧，`vm_insert_page`没有检查那个代码页是否是kernel代码页（或者说kernel内部根本就没有对应的代码页类型）。因此我们可以分配一个pg_vec数组，然后在这个object的上方再分配一个object用来覆盖数组里的内核堆指针（只要能覆盖就行，具体什么手段不重要）。最后在一个socket fd上调用mmap，促使kernel将一块内核代码区映射到用户空间即可执行任意shellcode

覆盖的指针需要满足：
1. 所有指针都是有效合法的
2. 所有指针都是页对齐的（page aligned）