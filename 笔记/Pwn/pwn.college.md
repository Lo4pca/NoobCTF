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

### Storage and Retrieval

人工智能与智能工人

这题加了精灵相关的directive。注册精灵时只需给出使用的字符，无需指定颜色，后续渲染精灵时再统一指定整个精灵的颜色。这样便省去了指定字符颜色的大量数据

开始叫ds迭代算法：
- 找全同色最大矩形覆盖每个颜色。然而图片中的图形夹杂着些许空格，这样只能分割出零零散散的精灵，数据量还是太大
- 注意到空格字符的颜色值不会被检查。对每种颜色先尝试求出一个最小外包矩形；若该矩形内只有该颜色和空格，则直接使用这一个矩形；否则退化到严格的同色最大矩形分割
- 省略一堆无效的尝试

ds的算法始终只能生成460字节的cIMG，无论我怎么修改提示词。于是我开始调试ds的算法，发现它在分割矩形时把边框的四条线分成四个不同的矩形了，导致没法重用精灵。我不知道如何向它描述这个问题，因为它看不到实际的图片。想自己实现也不行，因为分割方式会影响精灵的样式：一个局部最优的精灵分割方式不一定全局最优，比如一种局部较差的分割方式可能让相同的样式在图片中出现多次，全局来看可节省更多数据量；这一看就是我高攀不起的困难编程题

最后由于图片不复杂且算法自动分割出的精灵不多，我叫ds加了个交互，人工修正了结果

### Extracting Knowledge

脚本的问题是把每个精灵都渲染在一个坐标，且画布不够大。叫ds写个脚本自动计算坐标并扩大画布就好了……吗？

在自动计算坐标时，需要一个换行的契机，比如单行空间不够用。考虑到cIMG程序限制画布最长为255字节，每255字节换行如何？一旦你这么想了，就会发现字符莫名其妙地叠在一起，换行也不利索。我调试发现精灵数据都没问题，也是真的不明白为什么输出这么奇怪，就叫ds写了一段小型渲染代码打算绕过复杂的cIMG程序。结果“鬼打墙”出现了，我竟然得到了一模一样的乱码输出

最后我通过手动调整渲染的x偏移发现了罪魁祸首：终端的宽度大概只有140字节左右……

### Advanced Sprites

handle_4渲染精灵时加了平铺选项，允许指定精灵在横向和纵向重复的次数。观察目标图片，中间的四个字母显然不适合多次平铺，不过外边框完美符合平铺的需求

叫ds修改了上上题的脚本，上下左右都平铺完后发现竟然超了5个字节。于是我开始摆弄参数，寻找缩减图片大小的方法。这时我才发现屏幕坐标带模运算，只需要在最后一行指定平铺两行，最左边一列指定平铺两列，就能把上下左右都渲染到

### Patching ...

把剩下三题一起写了，结束这个折磨我三天的噩梦

Patching系列的第一题只需要修改cimg程序定义的header。`quest.py`成功跑起来了，迎接我的是一秒四帧左右，不时卡死一会儿的终端动画。游戏的主要内容是操控角色收集flag字符。移动的手感极差，不允许按键的速度过快，否则程序会吞掉一些按键。你的意思是要我手动收集完60个flag字符？

我太懒了，不想浪费太多时间，于是叫ds给我写一个自动化脚本。它用python写了一个指令解析器——没有任何错误——然后剩下的自动交互部分一碰就碎。在喂了6个小时的提示词后，ds从提出最初的A方案到否定A方案换成B方案，中间穿插了不知道多少零零散散的代码片段，最后重新坚持回A方案。这中间必定有我的提示词太简略和提供的信息被遗忘的问题，总之是时候动动脑子了

最初的方案固定读取渲染指令的时间，然而不知道有没有网络卡顿的原因，一段时间后总是会发生未完全读取全部指令的情况，导致解析器处理指令时错位。也许可以通过增加时长的方式修复这一问题，但是在加到3秒问题仍然出现的情况下，或许应该找其他更可靠的方法

在game函数主要的while循环中，读取用户输入前调用了`screen.flush()`，可以将flush指令作为每帧之间的分界线。注意`screen.blank()`也会发送flush指令，所以输入按键后，需要等待两次flush指令才能继续输入

处理每帧的数据时，可以监视`RENDER_PATCH`指令找到炸弹`B`和隐藏字符`?`的坐标，监视`RENDER_SPRITE`可以找到当前角色的坐标，然后bfs得到避开炸弹的路径

有以下两点需要注意：
- 如果用`master_fd, slave_fd = pty.openpty()+os.fork()`创建父进程和子进程，注意要给父进程的终端添上`termios.ONLCR`标志。否则一旦指令中出现`\n`，终端会将其自动换成`\r\n`，破坏解析器
- `revealed_bytes`的(x,y)坐标可能重复

总结起来就这么多内容，花费那么多时间的主要因素是太依赖AI了。剩下两题该怎么patch我完全没看，只要`quest.py`没大改，自动化脚本直接就能处理

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

# [Program Security](https://pwn.college/program-security)

## [Program Security](https://pwn.college/program-security/program-security)

### Can It Fizz?

和这道不复杂的题纠缠了很久。还是老毛病，做着做着头就晕了，不断在细节上浪费时间

checksec显示栈可执行，于是第一反应是利用bof泄漏栈地址，最后一轮再输入shellcode并覆盖返回地址为shellcode的地址。pwndbg发现存储返回地址的上方有两个栈地址，便无脑一堆a填过去。地址确实拿到了，但是程序崩溃了。调试发现死在strcpy处

重新查看栈布局，注意那两个栈地址的上方还有一个地址，指向for循环每轮选中的字符串。看来覆盖时保留这个地址就好。因此我打算先泄漏这个地址

这次程序没有崩溃，但是直接退出了。继续调试，原来那个指针上方存储着for循环的计数器i。因为i是int类型，用四个`\xff`覆盖过去仍能满足for循环的条件

在顺利泄漏出指针且程序能够继续运行后，我卡住了。printf打印的字符串以`\x00`做结尾，那我怎么在保证指针合法的情况下覆盖非零字符来读取栈地址？很明显我之前根本没有考虑到这个问题。不过for循环在i%5==0时会设置一个栈上的指针，相信此时大部分人会想到设置i为-5，这样就能用一样的思路泄漏这个栈指针了

但我没有想到。霎那间负数的概念在我的脑中被抹除了，我只想到了正5。我用一种诡异的方式解决了`\x00`的问题：partial overwrite。回想最开始看到的两个挨在一起的栈地址，我发现两者固定差值为140。不断爆破那个栈地址的lsb，如果连续两个输出的差值为140，说明我们找到了目标栈地址，用这个地址算出shellcode的地址即可

最后的最后，shellcode记得加上`setuid(0)`。pwntools自动生成的shellcode太长了，直接手写要缩短不少

### Does It Buzz?

没有可执行的栈了，但是多了个win函数。负数存在的世界实在是太美好了，轻轻松松泄漏elf地址和栈地址。最后覆盖栈上的两个指针，利用strcpy跳过canary直接修改返回地址

### Make It FizzBuzz

mprotect_stack函数可以将rbp所在的内存页的权限修改成rwx，正好泄漏的栈地址也在同一个内存页。利用上一题的任意地址写，提前在那块内存页里写好shellcode，然后修改返回地址为mprotect_stack+shellcode内存页地址

## [Reverse Engineering](https://pwn.college/program-security/reverse-engineering)

### The Yanalyzer(hard)

自己写yan85反编译脚本太费力了，不如直接站在巨人的肩膀上： https://github.com/robalb/custom-vm-emulator 。脚本额外提供的自定义选项能很好地用于这题

对比easy版本的代码，需要改动的内容如下：
- opcode的定义
- register的定义（参考`FUN_00101415`，寄存器的顺序固定为a,b,c,d,s,i,f）
- syscall的定义
- 指令解析顺序的定义（每个指令固定为3个字节，包含opcode,param1和param2。需决定三个字节与这三个值的对应关系）

我把反编译结果扔给了ds，直接出答案

### Yancraft(easy)

上述脚本同样提供了编译shellcode的功能。yan85调用系统调用时，寄存器A、B和C为系统调用的参数；`SYS`指令的第二个参数指定存储返回值的寄存器

### Yansanity(hard)

easy版本只需要随意组合可能的字节，看程序给出的反编译内容就能得出各个指令与字节的对应关系

hard版本可从exit syscall入手：
- 爆破SYS opcode和exit的syscall编号，若程序以exit code 0退出，说明猜测正确（所有寄存器的初始值都是0）
- 爆破IMM opcode和寄存器A的编号，并调用exit。A寄存器控制exit code，所以如果程序以指定exit code退出，说明猜测正确
- 爆破read_memory的syscall编号和寄存器C的编号。将read_memory的返回值存到A中，然后调用exit。如果程序能够接收输入且以输入的字符数作为exit code退出，说明猜测正确
- 爆破open的syscall编号，并将返回值存在A中，然后调用exit。如果程序以exit code 4退出，说明猜测正确（不知道为什么第一个打开的文件的fd是4而不是3）
- 爆破write的syscall编号

不知道为什么，相同的脚本在privileged环境下没法拿到flag

### When the Cow Says Moo

`gamefile.bin`的格式如下：
- 16字节文件头：uint32缓冲区大小（+8），uint32条目数量（+12）
- 缓冲区：每个条目固定16字节
    - 4字节ID
    - 2字节尝试次数
    - 2字节数字位数
    - 8字节秘密数字

每次猜测时程序打印的Bulls为数字正确且位置正确的个数；Cows为数字正确但位置错误的个数。输入不能包含重复数字，要求正好在最后一次机会猜中数字，猜错或提前猜对都不行

程序使用当前时间作为rand的种子，所以直接预测程序选择的entry就好

### Predictable Migration

`gamefile.bin`的每个条目多了attempts\*6个字节，用于记录猜测历史，格式`XXCYYB`，表示此次猜测需要有XX个Cows，YY个Bulls

在前一题的获胜条件下，此题额外要求每次猜测的Cows和Bulls数量等同于选中的条目里记录的历史。由于数字无重复且数量不多，可以直接爆破出符合要求的数字

### Hashing Heifers

记录的猜测历史不再是明文，而是sha256值。仍然可以用爆破解决：爆破全部可能的猜测值，提取出Cows和Bulls状态后将其sha256值存到字典里，后面就能反查了

### Salty Stampede

每个条目额外记录了key1和key2，在计算猜测历史的sha256值时作为前缀。和上一题的解法一模一样，因为key1和key2都是已知的固定值

## [Return Oriented Programming](https://pwn.college/program-security/return-oriented-programming)

### Guarded Gadgets(Easy)

任意地址读只能读canary，不然没有办法施展rop

main的返回地址是`__libc_start_main`，partial overwrite只能覆盖其周边的区域。看了一会没有发现什么好的gadget，随后在翻阅笔记时想起了一个技巧：vsyscall的地址固定为`0xffffffffff600000`。只需要填4个vsyscall地址就能碰到main的地址

然而直接返回到main会报错，因为此时rax为0，程序中存在解引用rax的操作。我选择partial overwrite到scanf上方（此处需要爆破，注意控制rbp为合理值），再来一次任意地址读。这次读取libc的地址，然后rop setuid+system（两个函数都要求栈对齐）

### Guarded Gadgets(Hard)

我尝试直接复用上一题的exp，然而每次运行到IO函数就报错，无论我跳转到哪里。调试发现由于这题移除了很多辅助函数，执行vsyscall时rdi指向stdout中的一个字段，导致vsyscall破坏了stdout。那就用ropper寻找别的gadget吧，比如一个可以pop三个值进寄存器的gadget。可惜在返回到main后栈没有对齐，导致printf报错。难道`__libc_start_main`里有gadget？但我上一题不是没找到吗？

事实证明我的眼神也不好。在不覆盖栈上数据的情况下调试即可发现，调用main的语句是`__libc_start_main`中的`call rax`。往上看几行，直接跳转到函数内布置rax的地方即可顺利调用main，也没有栈不对齐的问题

### ROP Roulette(Easy)

很经典的题目，感觉我已经做过不下三次类似思路的题了

在fork出来的child里做partial overwrite并观察child的情况可以泄漏canary。由于challenge返回到main，partial overwrite返回地址可以覆盖main周围的目标，比如challenge函数。以child是否能接收到challenge打印的内容做判断条件，可用类似泄漏canary的思路泄漏elf基址。elf里存在`pop rdi` gadget，那么泄漏libc地址再ret2libc即可

可以用`set follow-fork-mode parent/child`指定调试器跟踪的目标

### Libc Lottery(Easy)

这题的漏洞在main函数里，导致返回地址为`__libc_start_main`。然而这题没法用之前找到的`__libc_start_main`里的gadget（rax的值来自`[rsp+0x18]`，之前能用纯粹是运气好，`[rsp+0x18]`正好是main），故不能用partial overwrite泄漏libc地址

返回时rsi指向的内容是null(或者rsi本身是null，我不记得了)，所以我又掏出了vsyscall（vsyscall会把rsi指向的八字节清零），覆盖到栈上遗留的main地址后就能用一样的思路泄漏elf和libc地址了

泄漏libc地址和ret2libc可以分两次做，因fork出来的child的地址完全与parent相同（我之前以为只有elf地址是这样）

### Libc Lottery(Hard)

为什么会这么巧，所有Hard版本都用不了vsyscall，但是都能用`__libc_start_main`里的gadget……总之这题能直接泄漏libc地址，比上一题少了一步

## [Dynamic Allocator Misuse](https://pwn.college/program-security/dynamic-allocator-misuse)

### Fickle Free(Easy)

`tcache_entry`有个key字段，位于已释放chunk的bk处。在新版本（2.29+）key值是进程级的随机值（tcache_key），旧版本（2.27 - 2.28）key值则是指向`tcache_perthread_struct`的指针（比如这道题）。在释放内存块时，若释放的chunk的key值等于当前的tcache_key（或`tcache_perthread_struct`指针），libc会遍历tcache bin列表确认chunk是否已存在。如果存在，则会报错“double free detected“

用uaf修改key值即可绕过double free检查

（我竟然到今天才知道有这么个东西）