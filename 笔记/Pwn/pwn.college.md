# [pwn.college](https://pwn.college)

cryptohack告一段落，跑回来做与我有一面之缘的`pwn.college`。会跳过intro与一些简单的题

rules要求不能给出完整解答，因此这里依旧是我的思路与提示

# [Intro to Cybersecurity](https://pwn.college/intro-to-cybersecurity)

## [Integrated Security](https://pwn.college/intro-to-cybersecurity/integrated-security)

### ECB-to-Shellcode(hard)

漏洞与利用没什么好说的。唯一值得注意的点是，题目没开aslr，于是栈地址也是固定的；但这份“固定”与argv，argc和环境变量等值有关。我习惯用`gdb.debug`调试，这会导致练习环境与实际环境的栈地址不符。解决办法是手动attach gdb找地址，并使用加上`env={}`参数的process，不要用任何wrapper且不要改动输入payload的方式

这是我第一次使用较新版本的pwndbg，发现每次运行时它都会耗费很多时间下载调试符号。可以在`.gdbinit`文件中加上`set debuginfod enabled off`关闭下载

### CIMG Screenshots

deepseek能分析个90%.这是一个图形处理程序，各个handle的大致作用如下：
- handle_1：读取width和height，直接渲染像素到屏幕上
- handle_2：类似handle_1，但是额外读取偏移坐标(x,y)，像素会被渲染到偏移处
- handle_3：读取sprite_id、width、height，存储精灵数据到程序里但暂时不渲染
- handle_4：根据sprite_id和位置参数，将精灵渲染到屏幕上（似乎还支持缩放和偏移。直到做完这题我都不明白它在干啥，都是deepseek分析的）
- handle_5：读取 sprite_id、width、height 及文件名，从文件读取精灵数据并保存。不能读flag文件
- handle_6：渲染当前的屏幕
- handle_7：调用nanosleep延时
- handle_1337：读取 sprite_id、base_x、base_y、width、height，从屏幕指定区域拷贝像素（每像素 1 字节）到栈上的buffer。此处存在溢出
- （我没有验证它说得对不对）

handle_1-3都对读取的数据做了校验，只能在可打印字符的范围内。为了写入shellcode和栈地址，我们只能用无过滤的handle_5读取数据+handle_4写入，然后handle_1337触发漏洞

AI分析的一个弊端是，它总会在犄角旮旯的地方给你塞个坑，而且有时非常犟。以下是我踩的坑，前前后后卡了我两个多小时：
- 文件存在header，格式为`header_magic + version + screen_width + screen_height + len_directives`。len_directives的长度是4字节，但deepseek总觉得是2字节
- handle_4有个参数指定了透明字节，读取的数据中与该字节相同的字节会被替换成空格
- handle_4和handle_1337均有width和height参数，两者一定要匹配。如果不匹配（比如deepseek就给我搞反了，handle_1337传入的width和height是handle_4的height和width），字节被拷贝到栈上时会出现错位
- handle_5的文件名长度必须是255字节

程序提供了两种方式输入cimg文件。一种是在参数中指定文件名，一种是直接从stdin读。为了地址固定，建议选择stdin的方式

### CIMG Screenshots 2

虽然有了win函数，但没有过滤的`handle_5`不见了。没关系，可以用partial overwrite

我以为我的ghidra出错了，不然win函数怎么会长成这个鬼样子——结果win真的是这样的。结合过滤的要求，我猜是为了给我们提供不会被过滤的地址。挑好一个地址后很快就能发现，读取flag时使用了被覆盖的rbp，因此直接跳转只会报错

此刻我开始头脑风暴。难道程序里有其他漏洞？难道我一直没看懂的handle_4里可以修改已输入的字节？我得去社区看一眼

有人说win函数虽然看起来像某段代码的多次循环，但有部分地方修改了rbp。原来是找不同啊。叫ds用pwntools+capstone找到这些地方就行了