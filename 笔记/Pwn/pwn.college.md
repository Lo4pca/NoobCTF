# [pwn.college](https://pwn.college)

cryptohack告一段落，跑回来做与我有一面之缘的`pwn.college`。会跳过intro与一些简单的题

rules要求不能给出完整解答，因此这里依旧是我的思路与提示

# [Intro to Cybersecurity](https://pwn.college/intro-to-cybersecurity)

## [Reverse Engineering](https://pwn.college/intro-to-cybersecurity/reverse-engineering)

整个类别的主题都是自定义图片程序cIMG，就是我做`CIMG Screenshots`时痛苦逆向了很久的玩意。早知道就先做这个了

### The Patch Directive

`handle_34358`是直接读屏，必须输入整个屏幕所需的全部字节，因此不可能通过main函数末尾的total_data检查

`handle_43058`则允许指定`base_x`,`base_y`,width和height，以(`base_x`,`base_y`)为矩形的左上角坐标，绘制`width*height`大小的矩形。由于initialize_framebuffer已经给屏幕填充了空格，利用这个directive可以跳过对`desired_output`中空格的绘制

然后我叫ds编写了个爆破脚本，得到`desired_output`的维度应该是`60*17`；再叫它写了个找最大矩形的算法，擦着1340字节的边过了

借着这题第一次用上了ghidra的创建结构类型功能。从`cimg.c`中可以提取出结构体定义，将这些定义保存成`.h`头文件后，点击菜单栏的File->Parse C Source中`Source files to parse`板块右侧的绿色加号，选中保存的头文件，最后点击`Parse to Program`，后续弹出的`Use Open Archives?`弹窗选`Use Open Archives`（不过我不确定有啥用）就好了。如果导入成功，可以在左下角的Data Type Manager找到导入的类型，后续右键变量就可以将变量的类型改成刚刚导入的类型了

### Optimizing for Space

目标图片似乎一定有一个由短横线和竖线构成的外框，利用这点可以快速推断出图片的维度

上一题我叫ds编写的策略“寻找由同字符构成的最大矩形”放到这题超限制了。自然，新策略应忽略同字符的要求，单个矩形可以由多种字符组成。我就说了这么多，ds自己补全了剩下的逻辑：先用贪心算法找到所有同字符的小矩形，再两两遍历所有矩形并尝试合并。注意到每个指令固定6字节开销（指令码2字节+指定坐标和尺寸4字节），每个像素为4字节。那么两个小矩形A和B的开销为`2*6+(area(A)+area(B))*4`，合并成C（可能包含空白背景）后开销为`6+area(C)*4`。只要后者开销小于前者，合并就是有价值的

ds的算法依旧是一次过。我依稀记得leetcode上有类似的题，不知道ds表现这么好是否和这点有关

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

### Wily Webserver

路径穿越+bof。不过由于我们用socket连接服务器而不是直接与binary交互，简单的sh shellcode弹的shell用不了。或许可以dup fd吧，但orw shellcode简单又好用，注意文件的fd就好

### The Watering Hole

“watering hole attack”是一种攻击策略，攻击者通过攻击一个服务器间接攻击访问这个服务器的用户

server中的bof仍然存在，但程序做了降权，即使劫持控制流也不能读flag。不过victim读了flag文件，把flag放在发往server的请求里。于是我们可以编写shellcode接受victim的fd，然后读取victim的request发到自己的fd里

运行服务器时记得用pwntools的process，方便将env设为空

### Secure Chat 1

漏洞是sql注入和mitm。题目的情景大概是这样：sharon（完整用户名未知）给bob发送了flag，mallory通知alice flag已泄漏（需要我们用sql注入登录成mallory来触发剧情），于是alice和bob决定用DHE-AES沟通flag事宜。这里我们用mitm即可获取DHE-AES的key，解密bob沟通时提到的flag

随后我就在mitm卡了很久，于是我中途跑去把`Intercepting Communication`做完了，发现mitm成功的关键点如下：
- ARP欺骗包要不断地发送，直接发往受害者而不是广播
- 需要用`ip addr add`添加要伪装的目标ip。否则即使ARP欺骗成功，发往本机的包也会因为ip不符而被自动丢弃（可以用tcpdump诊断这个问题）
- 添加目标ip X后，本机无法再与真正的X沟通。我的做法是不断添加又删除这个虚拟ip：与X建立连接和沟通时，删除虚拟ip；与受害者建立连接和沟通时，添加虚拟ip。socket不会因为中途ip不通而断开连接
- 不知为什么，这题如果用flask server绑定，受害者就无法连接；而用raw socket绑定就可以。最后是用raw socket+手动构造http response解决的

### Secure Chat 2

这题和上题的区别是sharon发送flag后删除了自己的账号。看来上一题我用的是非预期解，应该是有办法直接登录sharon的账号看flag的。好消息是我在上一题的解法放在这题一字不改就能用

### Secure Chat 3

给我做力竭了

这次bob与alice的通信没有泄漏flag，只有sharon完整的用户名。我知道如何用sql注入拿到sharon删除账号前与bob的加密对话，也感觉modify_user路由有猫腻，但仍然卡在不知道如何解密。后来去社区逛了一圈后想到了方案：
- sharon删除账号后，之前sharon与bob的聊天中某一个encrypted_username会变成NULL；但只有两个encrypted_username都为null的聊天才会被删除
- 拿到sharon的完整用户名后（称为sharonXXX），bob可以改名为sharonXXX，modify_user会重新加密原本的聊天信息（new_encrypted_contents这段），作用是把最开始的`old_name: `换成`new_name: `
- 此时再以sharonXXX的身份改名就可以控制加密内容的前缀了。典型的aes ecb oracle攻击

然而在仔细阅读modify_user的改名逻辑后，我发现只有admin可以改名；而且拿到admin账号还不行，必须是本地登录。社区里有人提到了xss和csrf，run脚本的browse函数也刻意使用了selenium，似乎预期解就是要我们用xss实现aes ecb oracle攻击

我在搭建xss_server、构造xss payload和与ds扯皮中逐渐燃尽，最后死活找不到为什么跑不起来，又花费了不少的时间跑本地测试。都是很无语的bug，比如python的语法没搞明白，secret前缀抄错了等

ds写payload与server还是能用的，前提是你没有特殊的需求。我给了一段完整攻击链的描述和ecb攻击的雏形，要求它在已有的基础上补全server的其他逻辑。结果在深度思考一段时间后，它竟然因为“看不懂ecb攻击的原理”，给我写了个新的。我说了半天也没把它掰回来（我永远学不会写提示词了），没办法我只能自己写server的代码，然后又因为没搞明白语法+错误静默卡了很久。我们是卧龙凤雏

### Secure Chat 4

在上一题的基础上多加了个bof。注意输入内容的buffer不在期望密码的buffer的下面，因此没法用溢出修改原始密码，直接ret2win就好

另外，不知道为什么，我的xss payload总是运行一会就自己退出了。这个时候重新运行一遍run就好

### Secure Chat 5

这题和上题的唯一区别是cookie变为httponly，意味着没法用js拿cookie了。这时我才注意到modify_user没有强制admin只能在localhost访问，只要拿到admin的session cookie就好。我上一题又绕了远路