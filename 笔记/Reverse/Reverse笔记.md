# Reverse笔记

此篇笔记对应的gist： https://gist.github.com/Lo4pca/a066c450ed5d4c8ffbb0c1328283fe14 。题目对应的关键词将加粗

## Tools

平时见到的乱七八糟的工具

- [Instruction Stomp](https://github.com/ChrisTheCoolHut/Instruction-Stomp)
  - 侧信道逆向工具，支持不同架构的binary。原理是计算程序执行的指令数量来判断当前输入是否为正确输入
- [edb-debugger](https://github.com/eteran/edb-debugger)
  - 和x64dbg很像,但是适用于AArch32/x86/x86-64架构
  - 使用案例见[Now This Will Run on My 486?](https://github.com/gimel-team/ctf-writeups/blob/master/2025/iris-ctf/now-this-will-run-on-my-486)。这题我做的时候用的是pwndbg，然而题目涉及JIT+signal handling，通过报错进设置好的signal handling函数来动态解码执行的代码。pwndbg直接把signal传到我手里来了，continue也动不了……
- [ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin)：WASM逆向。chrome自带的开发者工具可以调试wasm，见 https://developer.chrome.com/docs/devtools/wasm 和 https://developer.chrome.com/docs/devtools/memory-inspector
  - [????????](https://hackmd.io/@fsharp/Hk1cfCwIye)
- [A child's dream](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/pwn_A_childs_dream)
  - [Mesen2](https://github.com/SourMesen/Mesen2)
    - Multi-system emulator (NES, SNES, GB, GBA, PCE, SMS/GG, WS) 
  - ida pro也可以反编译SNES,参考 https://r3kapig-not1on.notion.site/Srdnlen-CTF-2025-Writeup-by-r4kapig-181ec1515fb98004b3e2c42e74ce5fc5
  - 另一个snes调试器：[bsnes-plus](https://github.com/devinacker/bsnes-plus)
- [diaphora](http://diaphora.re)
  - IDA插件；program diffing tool
- [net-msg](https://scuffed.online/x3ctf-2025)
  - 逆向golang。题目的binary没有被去除符号（not stripped），然而gdb在这种情况下会找不到引用的源码文件，导致设置断点时可能出现segault。可以尝试用go原生调试器[Delve](https://github.com/go-delve/delve)。不过这个调试器有个缺点，就是没法自由地修改寄存器的值（见 https://github.com/go-delve/delve/blob/master/Documentation/cli/expr.md ）。这时只能去除binary的调试符号并换回gdb
  - ghidra插件[GolangAnalyzer](https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension)
- [AssetRipper](https://github.com/AssetRipper/AssetRipper)
  - 提取unity游戏的资源

## Game

游戏相关，不过大部分都是unity/godot/game maker

- [Restricted Jumper](https://yun.ng/c/ctf/2024-nitectf/rev/restricted-jumper)
  - [UnityExplorer](https://github.com/sinai-dev/UnityExplorer)：允许在游戏内进行调试，修改的mod。支持IL2CPP和Mono
- [Russian Roulette](https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#russian-roulette)
    - IL2Cpp unity apk逆向： https://palant.info/2021/02/18/reverse-engineering-a-unity-based-android-game 。其实和IL2Cpp exe差不多，都需要用[Il2CppDumper(GUI)](https://github.com/AndnixSH/Il2CppDumper-GUI)。注意工具输出的`Assemble-CSharp.dll`只包含函数签名而没有实际的代码，还需要用ida pro/ghidra配合工具提供的script反编译`libil2cpp.so`
    - 如何用[frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge)调用任意函数

## APK

记录android apk相关题目

- [Crack Me](https://github.com/Pusty/writeups/tree/master/SekaiCTF2024)
  - ReactNative application逆向。这类apk用反编译软件打开后没法在sources文件夹下看到应用的逻辑代码。虽然可以看到`MainActivity.java`和`MainApplication.java`两个文件，但是里面只会出现一些ReactNative字样，没有代码。这类应用的实际代码在`assets/index.android.bundle`文件里，是稍微混淆过的javascript。可以用[React Native Decompiler](https://github.com/numandev1/react-native-decompiler)反混淆
  - python使用pyrebase模块连接firebase。这是个托管后端的平台，题目里（`strings.xml`）看到类似的`firebase.io`字符串大概率有问题。需要authentication的url需要相关登录凭证。也有不需要任何凭证的情况，直接curl网址就能拿到内容。见 https://blog.securitybreached.org/2020/02/04/exploiting-insecure-firebase-database-bugbounty/
  - 发现一个动态调试做法更有趣： https://fexsec.net/variousctfs/crackme-sekaictf2024
  - apktool的`-r`选项可以使apktool不解码资源。如果题目需要patch操作就要加上这个选项，否则没法重新编译这些binary
  - [Android SSL Pinning Bypass](https://www.youtube.com/watch?v=_7J5HrwIr0k)。安卓应用有个SSL Pinning机制，防止攻击者监听数据传输。绕过后就能配合burpsuite抓包了。需要的工具有frida，adb等。原理是用frida注入一段js代码： https://codeshare.frida.re/@akabe1/frida-multiple-unpinning
  - patch原apk做法： https://github.com/acdwas/ctf/tree/master/2024/SekaiCTF%202024/rev/Crack%20Me
  - 在这篇[wp](https://ggcoder.medium.com/solving-crackme-from-sekaictf-9660dc41b0ce)里发现了[HTTP Toolkit](https://httptoolkit.com)，可以直接拦截apk的流量
- [Secure Vault](https://abuctf.github.io/posts/IronCTF)
  - Flutter APK逆向工具[Blutter](https://github.com/worawit/blutter)使用
- [Where's my APK?](https://blog.ryukk.dev/ctfs/write-up/2024/1337up-live-ctf/mobile)
  - 也是使用[Blutter](https://github.com/worawit/blutter)逆向flutter apk，不过更复杂一点
  - 如何将`.aab`后缀文件转成apk： https://stackoverflow.com/a/68752831
  - 使用adb命令生成携带data的activity。有些题目明明做了某些逻辑但是又没有任何触发入口，这时就可以用adb shell
  - patch apk内部的`.so`文件并签名
  - 另一种解法： https://learn-cyber.net/writeup/Where's-my-APK 。利用[httptoolkit](https://httptoolkit.com)分析并修改请求，这样就不需要patch apk了
- [Cold Storage](https://crypto-cat.gitbook.io/ctf-writeups/2024/intigriti/mobile/cold_storage)
  - 逆向[cordova](https://cordova.apache.org) app。cordova允许用html，css和js写应用
  - 这题主要是分析`index.html`里被混淆的逻辑。我就比较特别了，由于这类型app反编译后和一般app不同，直接没找到入口点……
  - 另一篇更详细的wp： https://majix.notion.site/Cold-Storage-13f2c37daa29807a930eed847be939f8 。没经过签名的apk无法运行，不过可以自行生成key并签名
- [Remind's funny stories 3](https://github.com/Qynklee/Public_CTF_Writeups/blob/main/WWFCTF-2024/Remind's%20funny%20stories%203)
  - 继续逆向flutter apk。可以在blutter输出的`pp.txt`中找到程序使用的字符串

## IDA使用

终于能用ida了，我等这一天已经等了几个月了。现在就是个纯纯ida萌新，完全不知道怎么用，故记录一下任何在做题时了解到的技巧。

1. f5键显示当前函数的伪代码。如果f5用不了，鼠标点进汇编代码窗口再tab也是可以的。假如当前已经是伪代码状态那tab键就能看到汇编代码。要是还不行直接菜单栏->View->open subviews->Generate pseudocode
2. g键是跳转任意地址的快捷键。
3. 伪代码内部双击变量可以查看其在栈上的位置。
4. 进入函数伪代码界面，点击函数名（会出现黄色背景自动选中函数名），然后按x可以找到该函数在其他函数中的引用。或者点击函数名右键->Jump to xref也是可以的。函数中的变量名也可以用这种方式找引用。
5. 点进一个函数，无论是汇编还是伪代码状态下，都可以在窗口底部看见当前函数的地址。
6. 选中一个数字类型数据再右键，可以选择数据显示的进制或者方式（比如10进制，16进制等）。
7. 菜单栏View->Open subviews可以打开很多有用的窗口，比如字符串，16进制等。
8. 右键变量可以重命名变量。
9. 想要提取数据，例如byte_array时，可以先双击变量进入data段，再右键变量名选择Jump in a new hex window,选中要复制的内容，shift+e就能提取了。我一般是选择hex string（spaced），粘贴到python里再split成数组。
10. 遇到想要改名的函数时，右键函数名->Rename global item。想改变量名也差不多，都是右键，点Rename就行了。
11. 选中一行代码，右键->Edit comment可以添加注释。或者选中一行代码后直接按`/`键。
12. ida中的数字有时候会带类型后缀。比如10h表示16进制的0x10，0i64表示int_64下的0。做题时注意区分，很容易把16进制看漏导致数据出现问题。
13. 在字符串窗口看见一个字符串并想找其引用时，先双击字符串，就会进入到另一个窗口，可以在字符串右侧看见DATA XREF。最后双击DATA XREF显示的函数名即可。
14. 有时候一些字符串会以hex形式出现在ida中，此时右键转char得到的字符串因为端序问题是反过来的，逆向时要注意手动将字符串倒序回来。
15. 遇见`Reverse技巧`一栏第5点的情况时，也可以考虑右键那个不够长的数组，选择Set Ivar Type，然后改成想要的长度。
16. 基础ida动调。例题:[[FlareOn4]IgniteMe](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/%5BFlareOn4%5DIgniteMe.md)
17. 使用ida分析Android的so文件时，要注意so文件是32位还是64位。如果把32位的文件错用64位ida打开，不会和平时的文件一样提示，而是会直接加载，但是出不来伪代码。反之亦然。
18. 鼠标选中一片区域再按p可以生成函数，然后f5生成伪代码。该操作常用于最开始因为花指令反编译失败的函数。例题:[findKey](../../CTF/BUUCTF/Reverse/findKey.md)
19. ida默认无法反编译过大的函数，要将ida /ctg目录下的hexrays.cfg文件中的MAX_FUNCSIZE=64 改为 MAX_FUNCSIZE=1024后才能正常反编译。
20. idc脚本基础使用（解密简单自加密函数）。例题:[[GWCTF 2019]re3](../../CTF/BUUCTF/Reverse/[GWCTF%202019]re3.md)
21. 菜单栏Search->Search immediate可搜寻汇编里的立即操作数，例如`add ptr 3`里面的3。勾选Find All Occurences可一次性列出全部出现位置。有时候利用这一点可以走捷径。例如一个贪吃蛇游戏，每次吃到东西后速度都会+3。这时就能直接搜寻这个3，patch成0就能让游戏变得很简单。
22. [Flare CAPA](https://github.com/mandiant/capa/tree/master/capa/ida/plugin)插件可以帮助分析程序，例如找到程序里的混淆字符串
23. [Mishap](https://blog.diefunction.io/ctf/bitsctf-reverse-mishap)
  - 如何在ida中提取和应用函数签名
  - 一个rust程序逆向技巧。程序字符串中能看到编译器的版本和使用的第三方库。自己写一个`Cargo.toml`文件并用相同的编译器和第三方库就能编译出带符号的程序。从中提取出签名后即可用于题目文件
  - wp里提到的Flare capa information应该是这个： https://github.com/mandiant/capa

## Jadx使用

1. 直接去[github](https://github.com/skylot/jadx/releases)下载最新release，电脑装了jre的下载`jadx-gui-1.4.5-no-jre-win.exe`，没装的下载`jadx-gui-1.4.5-with-jre-win.zip`。不需要过多配置，如果不确定装没装，就先下载`jadx-gui-1.4.5-no-jre-win.exe`，能运行就是装了，不能运行就是没装。
2. 没有关闭当前项目键，想反编译新文件直接文件->打开文件选个新的，点击不保存当前就可以了。
3. 当程序内很多类名和函数名都是a，b，c这种时，程序很可能被混淆了。菜单栏->工具->反混淆可以将a，b，c这类名字重命名为不重复的名字。不过重命名完会变成类似`f2488d`这种名，还是需要人工进一步区分。
4. 选中函数名按x可以查找该函数的引用。
5. 选中一个变量可以右键->跳到声明找到其声明。

## Ollydbg使用

1. 当遇见循环时，选中循环下面的一句代码，右键->Breakpoint->Run to selection（F4）即可跳出循环。
2. 菜单栏Plugins->中文搜索引擎->智能搜索可以自动搜索程序内的字符串
3. 程序内遇见数据可以在下方右键->Follow address in Dump,在16进制栏跟踪数据。
4. 在16进制栏选中数据，右键->Breakpoint->Memory,on access可以下内存访问断点，当选中数据被访问时就会中断程序。注意一个程序内只能下一个内存断点，如果之后想再别的地方下就要把原来的取消,右键->Breakpoint->Remove memory breakpoint

## x64/32dbg使用
1. 右键地址处（包括寄存器，指令等）可以修改值。意味着我们可以随时修改rip（右键->modify value）以及patch指令(右键指令->binary->edit或者Ctrl+e)。不过这样的patch是一次性的，文件重新加载后就要重新patch。保存patch参考 https://github.com/x64dbg/x64dbg/issues/1861 。不过有个例外，手动脱upx壳后的程序patch后是保存不下来的
2. ctrl+g可以输入并前往指定地址。也可以输入rip，这样就能快速回到正在调试的指令。注意使用ctrl+g跳转地址时，鼠标点到哪个窗口就会跳转到哪个窗口的地址。比如鼠标选到dump窗口，此时跳转地址后会在dump窗口里展示（而代码段不会变）
3. 右键空白处->search for->all modules->string references可以搜索程序内字符串
4. dump窗口可以手动填充地址处的内容。填充内容的长度取决于鼠标选中的内存的长度
5. 同时生效的断点不要超过3个，否则闪退。过了一个断点把它禁用即可
6. 查看程序以及各个模块的加载基地址： https://reverseengineering.stackexchange.com/questions/22494/how-to-use-memory-address-information-from-idafree-to-set-a-breakpoint-in-x32dbg
7. upx手动脱壳： https://cloud.tencent.com/developer/article/2098526 。注意不脱壳的程序在手动脱壳前搜索字符串是搜不到的
8. upx脱壳（程序，非手动）后的程序可能无法运行，使用调试器也不行
9. 反反调试的插件：[ScyllaHide](https://github.com/x64dbg/ScyllaHide)
10. 如果需要在调试exe时附加参数(argv)，可以用这些命令： https://help.x64dbg.com/en/latest/commands/debug-control/InitDebug.html 。输入命令的地方在x64dbg下方的位置（可以用上下箭头浏览输入过的命令）。有一个坑点在于，输入命令的参数默认以逗号分割，而且必须加个空格。比如`init path,param`不行，需要`init path, param`
11. [savedata](https://help.x64dbg.com/en/latest/commands/memory-operations/savedata.html)命令可以将从某个地址开始，长度为n的内存数据保存到一个文件里（太适合那些把代码藏在运行时的程序了）。使用案例：[Flag Checker](https://github.com/acdwas/ctf/tree/master/2024/World%20Wide%20CTF%202024/rev/Flag%20Checker)

## dnSpy
1. 如果遇到莫名其妙的报错导致编辑类后无法compile，可以尝试菜单栏->File->Reload All Assemblies

## Reverse笔记

1. 地址差值混淆。特征：程序先是取了两个地址a和b的差值，如c=a-b。程序后面又b+c取值。此时就要意识到现在取的是a的值。
2. 逆向时多在代码旁写注释，非常有助于分析逻辑。不要觉得多此一举或者懒得写，这个方法可以让小白更有头绪，大佬分析更快。
3. c++逆向中，接收输入和输出函数名可能不明显，但我们无需分析函数本身。接收输入认准`std::cin`,打印内容认准`std::cout`，特别是`std::cin`，跟它在一次出现的变量极有可能是用户输入，是逆向的主要目标。
4. 逆向要善于看整体。虽然说逆向真的就是字面意思——反着来，但反的是整体而不是机械式地倒着来。比如异或一般是一个for循环里面`^`，整个for循环周围的变量算作一个整体，也就是一个步骤。一个加密算法也是一个步骤，等等。如果是先加密算法再异或，那逆向的时候肯定是异或再加密算法，不难看出重点是区分异或和加密算法以及种种操作。区分后再着手细节，比如单个算法怎么逆。
5. 连着的变量可能会有间接引用。比如for循环中利用地址引用一个数组或类似数组的变量，而那个变量明显又没有那么长。这时候for循环中取到的值可能会有相邻的变量。比如（下面是个伪python代码）：

```
v30=array[5]
v31=x
v32=x
for i in range(7):
    v30[i]=xxx
```

示例中v30长度为5，然而for循环却取了7个元素。这时相邻的元素v31和v32就会被取到。ida中可能出现这种间接取变量的变量名都是挨着的，31，32，33或者别的一串数字。

6. xxtea加密算法识别。以下给出反编译得到的xxtea加密算法内容(c++)，其他的题反编译后看到类似结构的可以直接套用xxtea解密脚本。xxtea的特征为一堆位操作。附xxtea python实现,[来源](https://www.cnblogs.com/DirWang/p/12198526.html)。

```python
import struct

_DELTA = 0x9E3779B9


def _long2str(v, w):
    n = (len(v) - 1) << 2
    if w:
        m = v[-1]
        if (m < n - 3) or (m > n): return ''
        n = m
    s = struct.pack('<%iL' % len(v), *v)
    return s[0:n] if w else s


def _str2long(s, w):
    n = len(s)
    m = (4 - (n & 3) & 3) + n
    s = s.ljust(m, b"\0")
    v = list(struct.unpack('<%iL' % (m >> 2), s))
    if w: v.append(n)
    return v


def encrypt(str, key):
    if str == '': return str
    v = _str2long(str, True)
    k = _str2long(key.ljust(16, b"\0"), False)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    sum = 0
    q = 6 + 52 // (n + 1)
    while q > 0:
        sum = (sum + _DELTA) & 0xffffffff
        e = sum >> 2 & 3
        for p in  range(n):
            y = v[p + 1]
            v[p] = (v[p] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff
            z = v[p]
        y = v[0]
        v[n] = (v[n] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z))) & 0xffffffff
        z = v[n]
        q -= 1
    return _long2str(v, False)


def decrypt(str, key):
    if str == '': return str
    v = _str2long(str, False)
    k = _str2long(key.ljust(16, b"\0"), False)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    q = 6 + 52 // (n + 1)
    sum = (q * _DELTA) & 0xffffffff
    while (sum != 0):
        e = sum >> 2 & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff
            y = v[p]
        z = v[n]
        v[0] = (v[0] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[0 & 3 ^ e] ^ z))) & 0xffffffff
        y = v[0]
        sum = (sum - _DELTA) & 0xffffffff
    return _long2str(v, True)
```

1. 识别base64编码。如果你在一个看起来很复杂的函数中发现引用了这样的字符串:`A-Za-z0-9+/=`，即全大写小写字母加数字和+/=这三个符号，注意可能是base64编码，无需逆向，找个解码网站就好了。
2. 识别迷宫题地图大小。因为迷宫题的地图有可能是一个平铺开的字符串，而运行时走的迷宫却是二维，这时判断迷宫是怎样摆的很重要。例题[maze](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C/5%E7%BA%A7/Reverse/maze.md)中一段代码如下：

```c
if (s__*******_*_****_*_****_*_***_*#_*_00601060[(long)(int)local_28 * 8 + (long)local_28._4_4_]
        == '#') {
      __s = "Congratulations!";
      goto LAB_00400810;
    }
```

注意到`local_28 * 8`。很多正方形的迷宫题都是这个套路，先找到终点，然后看乘以了什么数字。这里是8，因此迷宫为8*8。

8. 逆向出来的程序判断输入是否是字母或转大小写的方式会比较奇怪，以及一些加密算法爆破比强行逆向好。例题：[SimpleRev](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/SimpleRev.md)
9. r2 patch程序。有些时候flag就在程序中，但是有一个复杂的逻辑判断输入是否正确，而且flag的生成也无法得知。这个时候用于判断的if分支可以直接patch掉。`r2 程序名`使用r2进行分析，aaa分析全部，s前往地址，oo+打开写入模式，wao选择要更改的字节。完整如下：

```bash
$ r2 luck_guy 
 -- You can mark an offset in visual mode with the cursor and the ',' key. Later press '.' to go back
[0x004006b0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x004006b0]> s 0x004009b6
[0x004009b6]> pd 1
|       ,=< 0x004009b6      750c           jne 0x4009c4
[0x004009b6]> oo+
[0x004009b6]> wao
| wao [op]  performs a modification on current opcode
| wao nop   nop current opcode
| wao jinf  assemble an infinite loop
| wao jz    make current opcode conditional (same as je) (zero)
| wao jnz   make current opcode conditional (same as jne) (not zero)
| wao ret1  make the current opcode return 1
| wao ret0  make the current opcode return 0
| wao retn  make the current opcode return -1
| wao nocj  remove conditional operation from branch (make it unconditional)
| wao trap  make the current opcode a trap
| wao recj  reverse (swap) conditional branch instruction
| WIP:      not all archs are supported and not all commands work on all archs
[0x004009b6]> wao je
[0x004009b6]> pd 1
|       ,=< 0x004009b6      740c           je 0x4009c4
[0x004009b6]> quit
```

发现0x004009b6成功从jne改为je。此题为[[GXYCTF2019]luck_guy](https://buuoj.cn/challenges#[GXYCTF2019]luck_guy)的patch部分。

10. 逆向从输入开始。有些程序在最开始可能会放很多复杂的难以分析的函数，此时分辨其参数和我们的输入是否有关。如果无关说明是程序自动生成的，把使用的值连同函数抄下来运行或者下断点就能得到结果了。
11. 算是对第10点的补充，逆向从判断开始。一定要看判断对错的关键if语句引用的变量是什么，根据那个变量的引用看看哪些是加密函数，没用的不用看，节省时间和精力。
12. java换行输出内容：`System.out.println()`，不换行输出：`System.out.print()`
13. apk是可以解压的（把后缀名从apk改为zip），里面不仅仅有class文件，还会可能会有so文件。so文件里面还有一部分逆向逻辑，在程序中会以`System.loadLibrary("so文件名")`的形式来加载。
14. 有些时候给出flag的函数不会在程序内部被调用，因此逆向时要看完整函数列表，注意有什么漏掉的函数。
15. 将apk导入jadx后，`资源文件`文件夹中有apk解压出来的内容，其中res里面是二进制的xml资源，可能会有一些信息藏在里面；lib下有so资源，有些程序会调用里面的函数。apk内容详情见[此处](https://www.jianshu.com/p/d29c37dda256)。
16. 下面的代码看起来很长，实际上逻辑非常简单。

```c
  length = strlen(result);
  if (1 < length) {
    index = 0;
    do {
      cVar1 = result[index];
      result[index] = result[index + 0x10];
      result[index + 0x10] = cVar1;   //上方是关键识别处，很明显是一个交换逻辑，重点在于很什么交换，因此index + 0x10处的数据是最重要的。0x10是16，说明是把前16位和后16位整体交换
      index = index + 1;
      length = strlen(result);
    } while (index < length >> 1); //无需纠结此处，length>>1等同于把length除以2
  }
  cVar1 = *result;
  if (cVar1 != '\0') {
    *result = result[1];
    result[1] = cVar1;
    length = strlen(result);
    if (2 < length) {
      index = 2;
      do {
        cVar1 = result[index];
        result[index] = result[index + 1];  //同样的交换逻辑，但是此处的数据变为了index + 1]，那就是相邻两个数据的交换了
        result[index + 1] = cVar1;
        index = index + 2;
        length = strlen(result);
      } while (index < length);
    }
  }
```

这两个交换搭配起来无需在意顺序，先两个交换在一半一半地交换等同于先一半一半地交换再两个交换。知道逻辑本身的情况下我们可以选择更简单的方式重现逻辑，如下面这样(脚本为[easy-so](https://adworld.xctf.org.cn/challenges/details?hash=b902eb43-71de-43a5-b70b-8424f986f61e_2&task_category_id=6)解题脚本）：

```python
data=list('f72c5a36569418a20907b55be5bf95ad')
index=0
for i in range(0,len(data),2):
	data[i],data[i+1]=data[i+1],data[i]
flag=''.join(data[16:]+data[:16])
print(flag)
```

17. 使用python双端队列实现字符轮转效果。轮转效果指的是：

```
a b c d e
轮转一圈
b c d e a
轮转两圈
d e a b c
```

例题：[easyjava](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C/6%E7%BA%A7/Reverse/easyjava.md)

18. 有些看起来很复杂难以逆向的算法就运行一下看看结果是什么，也许是出题人故意把一个很简单的效果写成很复杂的样子。比如[[ACTF新生赛2020]rome](https://www.cnblogs.com/Mayfly-nymph/p/12805930.html)，这题的加密代码看起来很怪，又减又模又加的，怎么逆向呢？实际运行一下会发现仅仅是跟凯撒类似的位移操作罢了。这题的解密脚本也值得积累。

```python
import string

model = [81,115,119,51,115,106,95,108,122,52,95,85,106,119,64,108]

s1 = string.ascii_lowercase
s2 = string.ascii_uppercase

flag = ""
#chr(65)='A',chr(97)='a'
for i in model:
    if i > 64 and i <= 90:
        flag += s2[i-14-65]  #假设i没有被位移，那么其ascii值减去A的ascii值得到的差值正是其在s1中的索引。程序加密时加上了14，那么我们减回来再取索引就好了
    elif i > 96 and i <= 122:
        flag += s1[i-18-97]  #此处同理，只不过是小写字母
    else:
        flag += chr(i)
print ('flag{'+flag+'}')
```

19. 简单的内容考虑爆破。上述题目也可以用爆破的方式解出，毕竟大小写字母不多，全部遍历一遍比对期望输出完全不难。这就要求对爆破数量级有个估计。
20. 限定条件不一定要明确指出。比如下面的场景：

```python
a=input()
if len(a)!=5:
  print("no!")
  exit(0)
b=int(a)
```

有两个限定条件，明显的是长度必须为5，不明显的是int(a)，提示输入是数字。同时限定条件也能在判断是否正确的if语句后。例题:[CrackRTF](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/CrackRTF.md)

19. .ab 后缀是Android的备份文件，需要使用[Android backup extractor](https://github.com/nelenkov/android-backup-extractor)从中提取出apk。ab文件分为加密的和不加密的，想要区分可以16进制编辑器打开，它们的开头会不一样：

- 未加密，文件前面有24字节文件头，文件头包含none标志，文件头之后就是数据
- 加密，文件头包含AES-256标志

例题：[app3](https://www.jianshu.com/p/04a78d45b2cf),这题还有SQLiteStudio的使用。

20. 有些函数的调用不会明显出现在main函数中，init_array和fini_array里有时也会有出题人刻意藏起来的函数。例题：[[2019红帽杯]easyRE](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/%5B2019%E7%BA%A2%E5%B8%BD%E6%9D%AF%5DeasyRE.md)
21. 不要过于相信伪代码，汇编才是王，要有看汇编的习惯，里面可能藏着一些伪代码看不到的重要信息。比如[[WUSTCTF2020]level2](https://buuoj.cn/challenges#[WUSTCTF2020]level2)，脱upx壳后main函数非常简单：

```c
undefined4 main(void)

{
  puts("where is it?");
  return 0;
}
```

flag在汇编代码里就很明显了。

```
        0804888a 83 ec 14        SUB        ESP,0x14
        0804888d c7 45 f4        MOV        dword ptr [EBP + -0xc]=>local_14,flag
                 68 a0 0e 08
```
22. windows多线程时，注意不同线程的函数是否访问了同一个数据内容，逆向时要考虑到这样的影响。例题：[Youngter-drive](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/Youngter-drive.md)
23. z3求解无符号整数时要把数字转为二进制再计算。这里的“无符号”代表ida里经常看到的unsigned。例题:[[GWCTF 2019]xxor](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/%5BGWCTF%202019%5Dxxor.md)
24. 在逆向android前，要确认是不是纯native开发的app，可在资源文件文件夹下的AndroidManifest.xml查看是否有`android:hasCode="false"`字样。如果有就代表是这种，jadx分析apk是找不到mainActivity的，直接ida看so文件，寻找`android_main`。
25. twofish算法。例题:[easy-dex](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C/7%E7%BA%A7/Reverse/easy-dex.md)
26. C# dll文件逆向题，需使用[dnspy](https://github.com/dnSpy/dnSpy)。Unity逆向题也是这个思路，一般题目里有dll文件，使用编译器反编译找到逻辑才能开始逆向。例题:[[BJDCTF2020]BJD hamburger competition](https://blog.csdn.net/Lenard404/article/details/123854785)
27. hook题型。程序内会调用一个函数，但在调用那个函数之前改动了那个函数的got表，导致实际调用的其实是另一个函数。在逆向前整体看一遍并把函数列表粗略看一遍，可以避免被骗。或者在发现逆向出来的结果与预期不一致时，考虑是否有hook。例题:[[Zer0pts2020]easy strcmp](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Reverse/%5BZer0pts2020%5Deasy%20strcmp.md)
28. 用z3爆破字符的数字值时，记得加上约束`xxx<128`，防止得到不必要的答案。
29. 逆向apk题第一步先看AndroidManifest.xml文件，有可能会遇到AndroidManifest.xml文件损坏需要修复的情况。例题:[APK逆向-2](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C/7%E7%BA%A7/Reverse/APK%E9%80%86%E5%90%91-2.md)
30. cocos2d 游戏apk逆向。先看AndroidManifest.xml的`android:name`确定主函数，以及要分析so文件，游戏的逻辑都在里面。分析时首先关注update函数。例题:[boomshakalaka-3](https://blog.csdn.net/shadow20080578/article/details/124124832)
31. android逆向时注意RegisterNatives函数，里面可能会将已知函数名注册为另一个函数。比如分析apk有个CheckFlag函数，加载so也能直接找到CheckFlag，但并不代表这个CheckFlag就是调用的CheckFlag。在JNI_OnLoad中可能调用了RegisterNatives将CheckFlag注册为另一个函数。例题:[Illusion](https://www.cnblogs.com/hktk1643/p/15186377.html)
32. android中getAssets函数可加载apk中assets目录下的文件，而反编译apk是可以看到assets目录中的文件的。
33. 基础ollydbg下断点、脱程序自制壳。例题:[[网鼎杯 2020 青龙组]jocker](../../CTF/BUUCTF/Reverse/[网鼎杯%202020%20青龙组]jocker.md)
34. android利用[objection](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/frida-tutorial/objection-tutorial)对apk下hook。例题:[ill-intentions](https://www.cnblogs.com/hktk1643/p/15187619.html)
35. 路由器固件逆向。需要先用binwalk从路由器固件的bin文件中提取东西，再用[firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit#kit-executables)分析。例题:[firmware](https://www.cnblogs.com/Mayfly-nymph/p/12609657.html)
36. python解密AES密码。例题:[[GWCTF 2019]re3](../../CTF/BUUCTF/Reverse/[GWCTF%202019]re3.md)
37. 安卓unity游戏的核心逻辑一般位于assets\bin\Data\Managed\Assembly-CSharp.dll。不同题目可能路径不一样，但Assembly-CSharp.dll永远是要看的文件。
38. dnSpy基础[调试](https://www.singoo.top/article/detail/161.html)。注意32位的dnSpy只能调试32位的程序，64位dnSpy只能调试64位程序。
39. xxtea逆向。例题:[xx](../../CTF/攻防世界/6级/Reverse/xx.md)
40. c++函数名修饰+二叉树变换动调解法。例题:[[2019红帽杯]childRE](../../CTF/BUUCTF/Reverse/[2019红帽杯]childRE.md)
41. ollydbg动调解题。例题:[[SWPU2019]ReverseMe](https://blog.nowcoder.net/n/aa8086cbf8c54e3b8dd49c52e2fcefe0)
42. [Pyinstaller extractor](https://github.com/extremecoders-re/pyinstxtractor)脱壳。例题:[[羊城杯 2020]login](https://blog.csdn.net/yhfgs/article/details/120556096)
43. SM4加密算法。例题:[[安洵杯 2019]crackMe](https://shijingtian.github.io/2020/03/17/ctf/%E5%AE%89%E6%B4%B5%E6%9D%AF%202019-crackMe/)
44. [WebAssembly](https://zhuanlan.zhihu.com/p/68048524)+Android。例题:[丛林的秘密](https://bbs.pediy.com/thread-252374.htm#msg_header_h1_0)。webAssembly可以被看作是web层面的汇编编译目标，可用[wasm2c](https://github.com/WebAssembly/wabt/blob/main/wasm2c/README.md)将wasm文件转为c语言。
45. 如果程序的验证逻辑是很多if语句，可以用爆破解时，[angr](https://www.anquanke.com/post/id/212816#h2-8)符号执行也是一种选择。例题:[[WUSTCTF2020]funnyre](https://blog.csdn.net/ytj00/article/details/107735151)
46. RC4算法。例题:[[GUET-CTF2019]encrypt](https://www.cnblogs.com/Moomin/p/15839791.html)
47. perl是解释语言，perlapp只是把你的perl程序压缩后放在资源里面，执行的时候会解压的。意思就是，逆向perl程序动调比静态分析好。例题:[[WMCTF2020]easy_re](https://blog.csdn.net/qaq517384/article/details/124134079)
48. [Ollvm混淆](https://bbs.pediy.com/thread-274532.htm)([控制流平坦化](http://www.qfrost.com/LLVM/%E3%80%90LLVM%E3%80%91Flattening%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/)混淆可以用[deflat](https://github.com/cq674350529/deflat)脚本部分去除)。例题1:[[RoarCTF2019]polyre](https://www.52pojie.cn/thread-1562227-1-1.html)。例题2:[[安洵杯 2019]game](../../../../../../../../../../../../../CTF/BUUCTF/Reverse/[安洵杯%202019]game.md)
49. 三维迷宫题+花指令去除。例题:[[SCTF2019]babyre](https://blog.nowcoder.net/n/46e15a89016144b899126fcd9644cdc0)。这题的另一个[wp](https://www.cnblogs.com/Moomin/p/15864510.html)有写ROR4和ROL4的c语言实现。
50. python可利用[ctypes](https://docs.python.org/zh-cn/3.7/library/ctypes.html)调用dll或共享库中的函数。
51. python字节码手动反编译[参考](https://bbs.kanxue.com/thread-246683.htm)。
52. apk也可以加壳，可用[fridaDump](https://github.com/hluwa/FRIDA-DEXDump)脱壳，需要配置frida环境。例题:[[网鼎杯 2020 青龙组]bang](https://blog.csdn.net/m0_46296905/article/details/115727899)
53. 基础vm虚拟机逆向。例题:[[GWCTF 2019]babyvm](../../CTF/BUUCTF/Reverse/[GWCTF%202019]babyvm.md)
54. 在C#中，字符串默认是Unicode字符串，所以转成字节数组，在每个字符字节后都要加一个"\x00"
55. [MFC](https://baike.baidu.com/item/MFC/2530850)逆向，需要使用[xspy](https://www.52pojie.cn/forum.php?mod=viewthread&tid=193686&highlight=xspy)。例题:[[HDCTF2019]MFC](https://blog.csdn.net/m0_46296905/article/details/116240702)。
56. golang无符号程序逆向。相关脚本：[AlphaGolang](https://github.com/SentineLabs/AlphaGolang) （IDA），[GoReSym](https://github.com/mandiant/GoReSym) （IDA，Ghidra）
57. 迷宫+blowfish加密算法。例题:[[RCTF2019]DontEatMe](https://lantern.cool/wp-games-2019rctf/#DontEatMe)
58. Smart Assembly混淆可用[de4dot](https://github.com/de4dot/de4dot)去混淆。例题:[[FlareOn2]YUSoMeta](https://blog.csdn.net/weixin_53349587/article/details/122310993)
59. 双进程保护程序逆向。关键的加密和检查逻辑无法通过静态分析得到，程序在动态运行时开启另外的进程，利用[int3](https://www.codenong.com/cs106526086/)和WriteProcessMemory向具有检查逻辑的进程写入正确的字节。例题:[[SWPU2019]EasiestRe](https://blog.csdn.net/weixin_53349587/article/details/122279966)
60. angr[基本使用](https://www.anquanke.com/post/id/212816)。例题:[[NPUCTF2020]EzObfus-Chapter2](https://blog.csdn.net/weixin_53349587/article/details/121880972)。这题的脚本如下：

```python
from angr import *
p = Project('C:\\Users\\admin\\Desktop\\attachment.exe',auto_load_libs = False) #创建Project加载二进制文件。auto_load_libs 设置是否自动载入依赖的库，在基础题目中我们一般不需要分析引入的库文件，这里设置为否
state = p.factory.blank_state(addr=0x004164F8) #这里不用initial_state，使用factory的blank_state方法，传入地址，表示从该地址的状态开始。此步跳过程序开始的输入部分，直接从逻辑开始
simfd = state.posix.get_fd(0) #创建一个标准输入对象
data,real_size = simfd.read_data(22) #read_data函数返回两个值 第一个是读到的数据内容 第二个为内容长度
state.memory.store(0x0042612C,data) #直接把数据存到相应地址
state.memory.store(0x00426020,data)
sm = p.factory.simulation_manager(state) #用刚才的state创建manager
sm.one_active.options.add(options.LAZY_SOLVES) #添加这行提高脚本运行效率
sm.explore(find = 0x00416609,avoid = 0x004165EA) #寻找有解分支，0x00416609是成功分支，0x004165EA是失败分支
text = sm.one_found.solver.eval(sm.one_found.memory.load(0x0042612C,22),cast_to = bytes) #memory.load从addr地址处的数据取出size字节，solver.eval打印定义的BVS的值
print (text)
```

参考[此处](https://b0ldfrev.gitbook.io/note/symbolic_execution/angr-jin-jie)

61. 题目出现反调试内容，可能为：

- TlsCallback相关函数逻辑
- NtQueryInformationProcess： 取进程信息函数，可以用于反调试(有调试端口，可以检测进程是否被调试)。
- ZwQueryInformationThread： 获取线程信息，可以用于反调试。
- IsDebuggerPresent。可以进入该函数的api在执行逻辑前直接ret，剩下的全部nop掉
- CheckRemoteDebuggerPresent

基本都能直接靠patch反反调试。例题:[[SUCTF2019]Akira Homework](https://blog.csdn.net/weixin_53349587/article/details/122274017)。这题有很多反调试的函数，主要逻辑是解密程序内的数据，写为dll，在靠LoadLibrary加载解密出来的dll，使用dll里的aes逻辑检查flag。

62. nes后缀文件逆向，使用[FCEUX](https://fceux.com/web/download.html)。例题:[[FlareOn6]Snake](https://blog.csdn.net/weixin_53349587/article/details/122463460)
63. python [struc.unpack](https://cloud.tencent.com/developer/article/1406350)使用+python直接读取so文件数据+字符处理。例题:[[FlareOn2]Android](https://www.cnblogs.com/Mz1-rc/p/17035685.html)。此题整体逻辑不难，一个apk内部调用加载的so文件的检查方法。方法逻辑是将输入的字符转为数字，将其质因数分解，看看分解结果是否和程序自带的相同。数据处理是这道题最难的部分。

```python
import struct
# author Mz1
t1_addr = 0x5004
with open('libvalidate.so', 'rb') as f:
	f.seek(t1_addr-0x1000)   # 这里要-0x1000可以在ida里看到，双击off_5004，看IDA View界面的下方的左边，能看见其地址为0x4004
	t1_data = f.read(23*4)
	t1 = struct.unpack("<"+"23I",t1_data) #<代表小端，单个I是unsigned int长4字节；下方的H是unsigned short，长两字节。加上数字代表有多少个（23*4//4=23，6952//2=3476）
	f.seek(0x2214)
	word_2214_data = f.read(6952)
	word_2214 = struct.unpack("<"+"3476H", word_2214_data)
	print(word_2214[:5])
	res = []
	for i in t1:
		offset = i - 0x1000
		f.seek(offset)
		data = f.read(6952)
		a = struct.unpack("<"+"H"*3476, data)
		v = 1
		for j in range(len(a)):
			if a[j] != 0:
				v *= word_2214[j] ** a[j]
		res.append((v >> 8))
		res.append((v & 0xff)) #似乎c里面的数字内存转字符都是这么做的
for i in res:
	print(chr(i),end='')
```

64. 利用侧信道攻击（Side-channel attacks）巧解vm逆向题。例题:[More Control](https://gynvael.coldwind.pl/?en&id=763),以下是学习到的一些技巧

- 缺少按位或字节码，因为大部分固定用时比较算法都会用上按位或。当然也有少部分会用按位与和ADD，这些都没有就要注意是否有侧信道攻击。
- 对于去除符号的文件，确定虚拟机主循环通常是比较困难的事。可以用gdb打开文件，在输入处按ctrl+c强制退出，到gdb调试界面后用where就能知道自己在哪了。

```
$ gdb -q ./main
Reading symbols from ./main...
(No debugging symbols found in ./main)
(gdb) r ext.bin
Starting program: main ext.bin
Give flag: ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7e54992 in __GI___libc_read ...
(gdb) where
#0  0x00007ffff7e54992 in __GI___libc_read ...
#1  0x000055555541b42d in ?? ()
#2  0x000055555541b2e2 in ?? ()
#3  0x000055555541c2c0 in ?? ()
#4  0x0000555555407c04 in ?? ()
#5  0x0000555555407fc3 in ?? ()
#6  0x00005555554087a9 in ?? ()
#7  0x0000555555419dae in ?? ()
#8  0x0000555555407fb2 in ?? ()
#9  0x00007ffff7d69d90 in __libc_start_call_main ...
#10 0x00007ffff7d69e40 in __libc_start_main_impl ...
#11 0x000055555540743a in ?? ()
```

- 简单的patch脚本。

```python
#!/usr/bin/python
import os

with open("main", "rb") as f:
  d = bytearray(f.read())

os.system("nasm patch.nasm")

with open("patch", "rb") as f:
  patch = f.read()

while len(patch) < 3 + 6:
  patch += b'\x90'

assert len(patch) == 9

# File offset for 0x107a5f default virtual address is 0x7a5f.
d[0x7a5f:0x7a5f+9] = patch

# Output executable will be called ./brute
with open("brute", "wb") as f:
  f.write(d)
```

- 基于侧信道攻击（时间）的简单自动脚本。

```python
#!/usr/bin/env python3
import string, shlex, sys
from subprocess import Popen, PIPE
cmd = 'perf stat -r 25 -x, -e instructions:u %s ' % sys.argv[1]
key = ''
while True:
  maximum = 0,0
  for i in string.printable:
  c = cmd + shlex.quote(key+i) + ' >/dev/null'
  _, stdout = Popen(c, stderr=PIPE, shell=True).communicate()
  nb_instructions = int(stdout.decode('utf-8').split(',')[0])
  if nb_instructions > maximum[0]:
    maximum = nb_instructions, i
    key += maximum[1]
  print(key)
```

- 一个记录海量技巧的[pdf](https://pagedout.institute/download/PagedOut_001_beta1.pdf)。

65. [snek](../../CTF/LA%20CTF/Reverse/snek.md)
- 可利用pickletools反编译pickle序列化对象
- pickle opcodes简单解释器
- code object（CodeType）可用dis.dis反编译
- 可重写常用函数（例如print）插入pdb断点。进入pdb调试界面后，可用inspect模块检查当前栈帧，返回上一栈帧，获取当前栈帧的code object等
- 可将code object类型写为pyc文件后使用反编译器反编译（python3.10）
  ```py
  #https://github.com/D13David/ctf-writeups/tree/main/amateursctf23/rev/trick_question
  import marshal
  marshal.dump(code, open("check.pyc", "wb"))
  # run pycdc on check.pyc
  ```
- 如何安装[pycdc](https://github.com/zrax/pycdc)：https://www.youtube.com/watch?v=J_vzY2P_ALE
  ```
  git clone https://github.com/zrax/pycdc.git
  cd pycdc
  cmake -DCMAKE_INSTALL_PREFIX="${PREFIX}"
  sudo make && sudo make install
  ```
66. [Symbolic Victory](http://itsvipul.com/writeups/Trellix_Hax_2023/SymbolicVictory.html)
- claripy.BVS模拟要求解的符号量并放置在内存中
- angr.Project可添加base_addr(`angr.Project("./decode",main_opts={'base_addr': 0x100000})`)以及entry_state的参数(`p.factory.entry_state(args=["./decode",key,data])`)
- 添加指定地址的内存内容的约束
- angr介绍[pdf](https://flagbot.ch/lesson5.pdf)
67. [Reachable Fruit](http://itsvipul.com/writeups/Trellix_Hax_2023/ReachableFruit.html).
- 固件（firmware）逆向。可使用[firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)提取出系统。
- 带有固件版本<= 1.0.02 (build3)的WUMC710 Wireless-AC Universal Media Connector的[命令注入漏洞](https://nvd.nist.gov/vuln/detail/CVE-2022-43971)的利用。
68. DOS Executable文件可用[DOSBox](https://www.dosbox.com/)运行，并且其内置[调试](https://www.vogons.org/viewtopic.php?t=3944)功能。
69. 对一个文件使用`strings`命令，如果发现大量`esp32`，这可能是CPU类型，对应着xtensa处理器架构。在ida（7.7版本以上）里选择cpu famility为xtensa即可开始反编译。
70. dnSpy可以修改dll文件。菜单栏->Edit->Edit class/method即可打开修改窗口，修改完后点击Compile关闭窗口。最后菜单栏->File->Sava all即可保存修改完成的dll。
71. [Gossip](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/Binary/Gossip/writeup.md)
- [apktool](https://github.com/iBotPeaches/Apktool)的使用。此题需要用id加载一个string资源，id可在jadx里获取到。之后便可用grep命令在apktool的结果里面搜索这个id，获取资源。
- Alicebot与.aiml后缀文件([Artificial Intelligence Markup Language，AIML](https://www.tutorialspoint.com/aiml/index.htm),基于xml文件语法)相关逆向。主要还是在逆向过程中找到线索后在apktool反编译结果里使用grep命令。
72. [x130](https://github.com/jdabtieu/wxmctf-2023-public/blob/main/rev5/writeup.md)
- yan85架构反编译[脚本](https://github.com/jdabtieu/yan85-disassembler)
- 此题是yan85的变种，提供了一些逆向虚拟机vm的经验
73. [TEJ5M](https://github.com/jdabtieu/wxmctf-2023-public/blob/main/rev6/writeup.md)
- 浮点数表示标准[IEEE 754](https://baike.baidu.com/item/IEEE%20754/3869922),更详细的例子在[此处](http://c.biancheng.net/view/314.html)。
- 另一种解法使用angr。用`eval_upto`（参考这篇[帖子](https://www.cnblogs.com/Here-is-SG/p/15815136.html))得出全部可行解，hook防止路径爆炸。
74. 可用strace命令跟踪程序的函数调用。
75. 利用共享库（shared library）加载的优先级hook程序。假如程序多次调用库里的某个无用函数且耗时较长（如sleep），就可以将其patch掉（call改为nop）或者使用下方的脚本：

```c
#include <stdio.h>
unsigned int sleep(unsigned int seconds) {//注意签名要一致
  return 0;
}
__attribute__((constructor)) static void setup(void){
  fprintf(stderr, "Hooked process,no sleeps!\n");
}
```

然后编译为共享库：`gcc -shared -fPIC -ldl nosleep.c -o nosleep.so`。最后更改LD_PRELOAD路径并运行程序：`LD_PRELOAD="./nosleep.so" ./sleeper`。

76. [pydumpck](https://github.com/serfend/pydumpck):反编译由python打包生成的exe，例如pygame模块编写的游戏。
77. [Maze](https://rinnnt.github.io/ctf/2023/04/10/bucketctf-2023-writeup.html#maze-478-points-hard)
- [预测](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)java random.nextInt（double）随机数。java的伪随机让我们可以在只获取到一个由random.nextDouble生成的数字后就能完整预测接下来的数字。额外地，我们还能通过double预测之前的种子，从而获取在所获取的double数字之前生成的随机数。预测代码的java版本：[github](https://github.com/fta2012/ReplicatedRandom)；python版本：

```python
multiplier = 0x5DEECE66D
addend = 0xB
mask = (1 << 48) - 1

double = float(input("Input the float > "))

num = int(double * (1 << 53))
first_seed_top = num >> 27
second_seed_top = num & ((1 << 27) - 1)

for i in range(1 << 22):
    global seed
    first_seed = (first_seed_top << (48 - 26)) + i
    if ((first_seed * multiplier + addend) & mask) >> (48 - 27) == second_seed_top:
        seed = (first_seed * multiplier + addend) & mask
        print(f"FOUND: {first_seed}")

def next(n):
    global seed
    seed = (seed * multiplier + addend) & mask
    return seed >> (48 - n)


def nextDouble():
    return ((next(26) << 27) + next(27)) / (1 << 53)

def nextInt(bound):
    r = next(31)
    m = bound - 1
    if (bound & m) == 0:    # if bound is a power of two
        r = (bound * r) >> 31
    else:
        u = r
        r = u % bound
        # Some checks to see if random number becomes negative from overflow?
        while u - r + m > (1 << 31) - 1:
            u = next(31)
            r = u % bound
    return r
def prev_seed():
    global seed
    seed = (((seed - addend) & mask) * inv) & mask
```

原理在wp和帖子里均已给出。

78. adb使用[文档](https://github.com/mzlogin/awesome-adb) 。可用于调试android apk。
79. tea加密算法：[ezTea](../../CTF/moectf/Reverse/ezTea.md)
80. wasm反编译ghidra[插件](https://github.com/nneonneo/ghidra-wasm-plugin)，以及将wasm转为ida可识别binary的插件： https://github.com/vient/wasm2ida
81. [reverse_html](https://blog.csdn.net/weixin_43798872/article/details/127728365)
- MS Windows HtmlHelp Data(后缀chm)相关逆向。使用hh命令反编译chm文件得到html。`hh.exe -decompile <结果存放路径> <chm文件>`
82. [Give My Money Back](https://siunam321.github.io/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back/)
- Microsoft Cabinet archive data(.cab后缀)可用cabextract，7z或WinRAR解压
- 简单vbs deobfuscation
83. [Hero Ransom](https://github.com/HeroCTF/HeroCTF_v5/tree/main/Reverse/HeroRansom)
- [hollows_hunter](https://github.com/hasherezade/hollows_hunter)使用:扫描进程memory并自动dump+fix memory中的可疑PE。使用之前可以参考[PE format documentation](https://www.aldeid.com/wiki/PE-Portable-executable)查看内存中是否藏着PE头结构。
- IDA console中运行get_processes()可得到程序的PID.PID可用于hollows_hunter：`.\hollows_hunter64.exe /pid <pid>`
84. [InfeXion 3](https://github.com/HeroCTF/HeroCTF_v5/tree/main/Reverse/InfeXion_3)
- .NET deobfuscation工具：[de4dot](https://github.com/de4dot/de4dot)
- [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)鉴别。
85. [sELF control v3](https://0xswitch.fr/CTF/heroctf-v5-self-control)
- ELF文件结构详解：https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
- shared object (ET_DYN)一定有PIE，executable file (ET_EXEC)不一定有
- 使用[Hellf](https://github.com/0xswitch/Hellf/tree/master) patch文件+readelf使用。[xelfviewer,](https://github.com/horsicq/XELFViewer)也不错
  - 更改文件segment的权限。根据[此处](https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html)，RX对应5
  ```py 	
  from Hellf import ELF
  e = ELF("./patched")
  e.Elf64_Phdr[3]
  #ELF Program header struct
  #  p_type:       0x1
  #  p_flags:      0x4
  #  p_offset:     0x1000
  #  p_vaddr:      0x401000
  #  p_paddr:      0x401000
  #  p_filesz:     0x305
  #  p_memsz:      0x305
  #  p_align:      0x1000
  e.Elf64_Phdr[3].p_flags = 5
  e.save("patched_perm")
  ```
  - 查看`.dynstr`
  ```py
  from Hellf import ELF
  e = ELF("./patched")
  e.get_section_by_name('.dynstr').data.split(b"\0")
  ```
  - `.dynsym`相关
  ```py
  from switch import nsplit
  e=ELF("")
  len(e.get_section_by_name('.dynsym').data)
  # 240
  # 240 / 10 entries = 24 Elf64_Sym，下面for循环24的由来
  # typedef struct {
  #        Elf64_Word      st_name; <--- this is the offset to .dynstr
  #        unsigned char   st_info;
  #        unsigned char   st_other;
  #        Elf64_Half      st_shndx;
  #        Elf64_Addr      st_value;
  #        Elf64_Xword     st_size;
  # } Elf64_Sym;
  for i in nsplit(e.get_section_by_name('.dynsym').data, 24):
      print(hex(i[0]))
  e.get_section_by_name('.dynstr').data[0x31:].split(b"\0")[0] #0x31来自上方print出来的hex
  hex(e.get_section_by_name('.dynstr').data.index(b"getc")) #获取某个函数（这里是getc）在.dynstr中的偏移
  # '0x13'
  ```
- `.dynstr`中存储的symbol的ascii名称用于在library里查找对应的symbol。意味着更改`.dynstr`里的名称就LAN可以调用libc里另外的函数
- When IDA found 2 entries in the import table that point to the same function. IDA will label the second with `_0`.
- 此题的[非预期解](https://xarkes.com/b/advent-2019-Genetic-Mutation-First-Blood.html)（不同题但是方法可以继续用）介绍了一个patch elf文件的magic bytes来执行RCE的方法。shell默认一个可执行binary的magic bytes中不含`\n`或null。所以如果我们把elf的开头三个字节patch成`sh\n`，shell就会认为这是一个文本文件，那么就会执行第一条命令，即sh。
86. [Ducky2](https://github.com/BYU-CSA/BYUCTF-2023/tree/main/ducky2)
- [USB Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky)和其DUCKYSCRIPT逆向。可用[在线工具](https://ducktoolkit.com/decode#)或者[DuckToolkit](https://github.com/kevthehermit/DuckToolkit).由DUCKYSCRIPT创建的文件为bin后缀，file命令无法识别。
- 可以选择DUCKYSCRIPT的键盘布局。不同的键盘布局会导致解密出不同的结果。所有布局：https://github.com/hak5/usbrubberducky-payloads/tree/master/languages ，爆破命令：
```sh
for i in `cat langs.txt` 
  do
  echo $i     
  python3 ducktools.py -l $i -d ../inject.bin /dev/stdout | grep "flag{"
  done
ch
de
fi
mx
sk
us
gb
pt
be
it
cz
hr
dk
fr
br
ca
si
se
es-la
ca-fr
no
es
```
87. [Ducky 3](https://meashiri.github.io/ctf-writeups/posts/202305-byuctf/#ducky-3)
- 根据给出的payload还原自定义字符/键盘映射
```py
chars = "" #来自payload
with open('nject.bin', 'rb') as F:
    duckbin = F.read()
    ducks = hexlify(duckbin)
    lookup = {}   # lookup table
    i = 0
    # build the lookup table: key = hex code; value = character
    for c in chars:
        lookup[ducks[i:i+4]]=c
        i+=4
    s = ""
    while(i<len(ducks)):
        try:
            print(f"{ducks[i:i+4]} --> {lookup[ducks[i:i+4]]}")
            s += lookup[ducks[i:i+4]]
        except Exception as e:
            print (e)   # print and ignore if a character appears in the flag, but not in the lookup table. This happens for { and }
            #continue
        i+=4    
    print(s)
```
88. [Chicken Again](https://github.com/BYU-CSA/BYUCTF-2023/tree/main/chicken-again)
- chicken esoteric programming language.工具:[chickenpy](https://github.com/kosayoda/chickenpy).命令：`chickenpy -f chicken`
89. [spring](https://medium.com/@laithxl_79681/hsctf-2023-spring-challenge-823d78d41fc2)
- java里的左移在溢出发生时不保留原数字的符号。比如一个8-bit数字左移56位后，最左的数字会被看成符号位，于是结果就是个负数。例如137(10001001)左移56就是`1000100100000000000000000000000000000000000000000000000000000000`。因为最左的bit为1，这个数字为负数，表示的值为其补码。如果想在python里表示这个过程，需要将137左移后减去其补码1<<64（比上面的数多一位）。在python里逆向java的左移也很简单，将左移结果右移相同的位数，然后按位和0xff只保留其最右8位就行了（保留多少位取决于原数字有多少位）
90. [re-cursed](https://kos0ng.gitbook.io/ctfs/ctfs/write-up/2023/hsctf/reverse-engineering#re-cursed-4-solves)
- 一般GHC编译的由haskell语言写成的程序可用[hsdecomp](https://github.com/gereeter/hsdecomp)反编译。此题的情况无法使用，介绍了另一种解题的思路（甚至绕过了原本的虚拟机考点，直接解）：枚举所有和用户输入相关的指令
  - 确定输入内容所在的内存，在内存地址处下内存断点。（如果无法确切知道其地址，可以在附近下个普通断点然后再内存里搜寻刚才输入的字符串。也可以用这种方法跳过某些和输入相关但是和加密逻辑无关的指令）
  - 不断更换内存断点。在每个mov指令或是相关指令处理的地址处下断点。重复此步骤直到发现可疑内容（逻辑，函数名等）。
  - 使用脚本记录可疑指令处理的参数及结果（异或，加减，比较等）。
  - 根据获取的记录逆向，或者直接z3
91. [interpreted-arduino](https://ayusshh.medium.com/bcactf-4-0-writeup-interpreted-arduino-i-rev-1997c885d640)
- Arduino内置函数setup在程序启动时会被自动调用一次。每次按RESET按钮重启时也会被调用。以下是更多信息：
```
The setup() function is automatically called by the Arduino framework, so you don't need to explicitly call it in your code.
The setup() function is called before the loop() function, which is the main entry point for the program's execution.
The setup() function is called only once when the Arduino board is powered on or reset.
The setup() function is used to configure the initial state of the program, such as setting pin modes, initializing libraries, and configuring communication interfaces.
Any code that needs to be executed only once at the beginning of the program should be placed inside the setup() function.
```
90. [golfers](https://github.com/BCACTF/bcactf-4.0/tree/main/golfers)
- [Vyxal](https://github.com/Vyxal/Vyxal)语言逆向（文件后缀名.vyx）
91. [Mima Flux Capacitor](https://github.com/mattulbrich/mimaflux): a debugger for Mima assembly code. 这种汇编码通常用于大学教学。
92. [writeright](https://github.com/D13David/ctf-writeups/tree/main/nahamcon23/rev/writeright)
- 使用VeSP simulator运行`.vsp`后缀文件（VeSP (VEry Simple Processor) program）
- python版本： https://github.com/abhishekg999/NahamConCTF-2023/blob/main/Re/writeright.md
92. [Mayhem](https://elvisblue.github.io/posts/nahamcon-mayhem-solution/)
- Havoc [demon.exe](https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/Source/Demon.c)+sleep obfuscation technique：[Ekko](https://github.com/Cracked5pider/Ekko)，hide malware payload during runtime execution, it works by encrypt the malware payload while it is sleeping. Ekko使用RC4加密payload，且key为UString格式：
```c
typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING ;
```
那么RC4的key开头一定为`10 00 00 00 10 00 00 00`。可根据此线索在dump文件中搜索key。
- python Crypto.Cipher解密RC4密文。
- windbg preview分析dump文件。
  - `!address`:show the memory region
  - `.writefile file start L?<length>`:从文件中dump the payload
93. [Red Light Green Light](https://nirajkhatiwada.com.np/tutorials/2023/06/18/nahamcon-ctf-2023-mobile-challenges.html)
- 使用frida script hook apk使其在runtime更改函数源码。
```java
Java.perform(function () {
  var MainActivity = Java.use('com.nahamcon2023.redlightgreenlight.MainActivity');

  MainActivity.checkLight.implementation = function (view) {
    this.checkLight(view);
    this.red.value = false;
  };
});
```
93. [geoguesser](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/rev/geoguesser),[wp](https://github.com/abhishekg999/UIUCTF-2023/tree/main/geoguesser)
- janet编程语言逆向。这种不熟悉的语言逆向题可以用ChatGPT快速上手，参考： https://chat.openai.com/share/43339f5a-158d-4aac-8b95-58fe59f8bfbb
- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/UIUCTF%202023/geoguesser ：让chatgpt patch janet编译器使其打印出变量的值而不是类型（janet_to_string_b）
94. [vmwhere](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/rev)，[wp](https://github.com/abhishekg999/UIUCTF-2023/tree/main/vmwhere-suite)
- wm虚拟机逆向。除了一些特殊情况外，这类型题的标准逆向方法还是在反编译器里获取各类opcode然后自己写虚拟机的disassembler。可参考wp的disassembler改出一个
  - 或者改动反编译出的源码，直接在程序里TRACE：https://github.com/D13David/ctf-writeups/tree/main/uiuctf23/rev/vmwhere1
  - https://github.com/P3qch/ctfs/tree/main/uiuctf2023/vmwhere1 有个更简单的反编译器脚本
  - 某些初级的虚拟机验证flag时，执行的指令数与flag正确的字符成正比（正确的字符越多，执行的指令数越多）。可以利用这点进行测信道攻击，爆破flag。 https://www.youtube.com/watch?v=bmV0EL_cDpA ,利用[valgrind](https://linux.die.net/man/1/valgrind):`valgrind --trace-children=yes --tool=callgrind ./chal vm_program < flag.txt`
95. [pwnykey](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/rev/pwnykey),[wp](https://github.com/D13David/ctf-writeups/tree/main/uiuctf23/rev/pwnykey)
- [devicescript](https://microsoft.github.io/devicescript/intro) bytecode逆向。文档：https://microsoft.github.io/devicescript/language/bytecode ，源码：https://github.com/microsoft/devicescript 。
  - 其内置一个反编译器：`devs disasm ctf.devs`。不过这个反编译器无法应对某些混淆技巧，如：https://breakdev.org/x86-shellcode-obfuscation-part-3/ ，https://github.com/defuse/gas-obfuscation 。需要自己手动patch掉混淆指令后再反编译，或者用wp里的一个[自动化脚本](https://github.com/D13David/ctf-writeups/blob/main/uiuctf23/rev/pwnykey/patch_binary.cpp)。
  - https://ctftime.org/writeup/37386 ：自己手写一个简易的反编译器同时避免官方反编译器的问题
- [xorwow](https://en.wikipedia.org/wiki/Xorshift#xorwow) PRNG识别+c++实现。这还有个C实现： https://gist.github.com/RubenBrocke/248e80151e2ff4d4ea67a5af792ec4d6
96. [Fast Calculator](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/rev/fastcalc),[wp](https://bronson113.github.io/2023/07/03/uiuctf-2023-writeups.html#fast-calculator)
- 编译源码如果加上`-ffast-math`，会导致程序的数学计算加快，代价是精度变低。参考 https://simonbyrne.github.io/notes/fastmath/ 。更致命的影响是，编译后的程序默认不含有NaN，infinity等数字，因此检查这些数字的函数都会统一返回0。需要自行patch程序使其恢复正常功能。比如使用gdbscript hook函数：
```py
gdb.execute("file ./calc")
gdb.execute("b *0x4021ae")
gdb.execute("b *0x4022af")
gdb.execute("b *0x4022FA")
x=open("input","w+")
x.write("8573.8567*1")
x.close()
gdb.execute("r < input")
gdb.execute("c")
# def is_inf(result):
ops_list=[]
for i in range(46*8):
    op=int(gdb.execute("x/gx $rsp+32",to_string=True).split(":")[1],16)
    first=int(gdb.execute("x/gx $rsp+40",to_string=True).split(":")[1],16)
    second=int(gdb.execute("x/gx $rsp+48",to_string=True).split(":")[1],16)
    gdb.execute("c")
    # print(gdb.execute("info reg xmm0",to_string=True).splitlines()[-2].)
    result=int(gdb.execute("info reg xmm0",to_string=True).splitlines()[-2].split("=")[1],16)
    gdb.execute("c")
    ret=int(gdb.execute("p/x $rax",to_string=True).split("=")[1],16)
    if(hex(result)=='0x8000000000000000' or hex(result)=='0xfff8000000000000'):
        gdb.execute("set $rax=1")
    # ops_list.append((hex(first),chr(op),hex(second),hex(result),hex(ret)))
    gdb.execute("c")
print(ops_list)
```
- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/UIUCTF%202023/Fast%20Calculator ：ghidra如何修改函数签名（functin signature），使其传入参数
97. [Brick Breaker](https://github.com/D13David/ctf-writeups/tree/main/tenablectf23/rev/brick_breaker)
- Nintendo DS Slot-2 ROM image(`.nds`后缀文件)逆向
  - 模拟器工具： https://www.nogba.com/no$gba-download.htm , [DeSmuME](http://desmume.org/)
  - [GBA/NDS Technical Info](https://problemkaputt.de/gbatek.htm)
  - [Reverse Engineering a DS Game](https://www.starcubelabs.com/reverse-engineering-ds/)
    - https://github.com/ITSEC-ASIA-ID/Competitions/tree/main/CTF/2023/TenableCTF/Reversing%20-%20Pwns/Brick%20Breaker
    - 里面介绍了如何用ghidra加载ROM，或者用[tinke](https://github.com/pleonex/tinke)
  - [ARM programming for the Nintendo DS](https://www.chibialiens.com/arm/nds.php)
  - 利用binaryNinja的静态分析： https://gitlab.com/9hozt/ctf-write-up/-/tree/main/2023-tenable/re/brickbreaker
98. [Exposed](https://ctftime.org/writeup/37442)
- RISC-V架构逆向。此架构比较重要的几点：
    - 函数调用类似ARM，返回地址可能不在stack上，而在ra（return address）寄存器里
    - ecall用于执行系统调用，寄存器a7为系统调用号，从a0开始依次存参数，返回值也在a0里。附系统调用表：https://jborza.com/post/2021-05-11-riscv-linux-syscalls/
    - 以`s*`开头的寄存器在不同的函数调用时会保留
    - https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf
99. angr。虽然前面已经记过了，但还会继续记一些复杂的angr题的脚本。
- [topology](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/rev/topology)
  - https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#topology
- [icancount](https://guyinatuxedo.github.io/13-angr/plaid19_icancount/index.html)
  - PIE下的angr模拟
- [Classic Crackme 0x100](https://anugrahn1.github.io/pico2024#classic-crackme-0x100-300-pts)
  - 主要是没想到什么都不用设置的情况下angr还能跑
- [angry](https://ihuomtia.onrender.com/l3ak-rev-angry)
  - 以前遇到那种输入flag到栈上的题总是不知道怎么写脚本，不知道该把代表flag的BVS存到栈上的哪个地址。看了这个wp才知道，随便存到一个地址即可。接下来设置blank_state时跳过输入的部分，直接到判断逻辑，然后设置好寄存器即可。还可以将程序分成多次检查，第一次explore成功后将solution state取出来，重新设置好寄存器再explore即可
  - 此题的z3解法： https://github.com/L3AK-TEAM/L3akCTF-2024-public/tree/main/rev/angry 。该脚本会求出所有可能的解
- [Qamu](https://www.sudeepvision.com/blog/glacier_ctf_2024_qamu_reverse_engineering_challenge)
  - 利用capstone库编译汇编指令并写入文件
  - Concat的使用。把多个BVS拼接成一个表达式（方便初始化时将输入内容以整体的形式用store存进某个地址？）
- [tinylock](https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#tinylock)
  - 其实不是angr脚本，而是claripy的使用。claripy自己就能单独拿出来用，作用类似z3
  - 这题一共有两个阶段，第一个阶段检查flag长度，第二个阶段检查flag的实际值。巧思在于检查flag的逻辑藏在第一个阶段的汇编指令所用的立即数中，用push和ret实现跳跃。因此对编译器不可见，也是一个不错的混淆手段
100. qiling框架调试。使用[qdb](https://github.com/ucgJhe/Qdb): https://docs.qiling.io/en/latest/qdb/
101. [🏴❓🇨🇹🇫](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2023/rev/%F0%9F%8F%B4%E2%9D%93%F0%9F%87%A8%F0%9F%87%B9%F0%9F%87%AB),[wp](https://wiki.cve.gay/en/Writeups/amateursCTF2023/emojis)
- [emojicode](https://www.emojicode.org/docs/)逆向
- side-channel attack[脚本](https://github.com/tabun-dareka/side-channel-crackme-solver)：利用perf计算指令长度从而猜测出正确输入
102. [flagchecker](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2023/rev/flagchecker),[wp](https://github.com/rwandi-ctf/ctf-writeups/blob/main/amateursctf2023/flagchecker.md)
- scratch(`.sb3`)文件逆向。可以去 https://leopardjs.com/ 把sb3文件转为js后本地部署然后再逆向
  - 或者 https://scratch.mit.edu/ ，可以直接打开sb3文件并编辑
  - https://turbowarp.org/ 打开文件然后点击“转到源代码”也行
- 补充另一道scratch逆向题：[Prologue](https://sylvie.fyi/posts/lactf-2025)。`.sb3`其实就是zip，解压后打开`project.json`文件就能修改一些配置，比如变量名，代码块是否可见等（`shadow: true`）。参考 https://en.scratch-wiki.info/wiki/Scratch_File_Format
103. [CSCE221](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2023/rev/csce221)
- 若一个程序没有开启PIE，那么其coredump包含的函数和数据也和程序在同一地址
  - dump文件（core file）需要额外用反编译器反编译。注意有时候低版本的ghidra load core file会报错
104. [headache](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2023/rev/headache),[wp](https://github.com/4rr4y/ctf-writeups/blob/main/2023_AmateursCTF/Rev_Headache.md)
- python [Capstone](https://www.capstone-engine.org/lang_python.html)实践。个人感觉一般静态分析有ida或ghidra就不需要capstone了，不过这题比较特殊，整个程序是SMC的套娃，用SMC加密另一层SMC，总共套了近200层……如果手动一个一个解然后保存然后再放ida里就太繁琐了。可以就解那么几个找一下smc段的规律，加个capstone写个程序解。当然不用也可以，官方解法就没用
  - 一些wp里的api介绍
  ```py
  Cs(CS_ARCH_X86, CS_MODE_64) #初始化x86架构64bit的反编译器实例
  disasm(data, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN) #反编译64bit，小端存储的data
  (instn.address, instn.mnemonic, instn.op_str) #address为当前指令instn的地址，mnemonic则是可读的指令名字（比如mov），op_str是指令的参数
  ```
105. qiling框架使用案例。
```py
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import *
from qiling.os.windows.thread import *
from qiling.os.windows.utils import *
def _connect(ql, address: int, params):
    value = ql.mem.read(params['name'], params['namelen']) #读内存里的值
def prepare() -> Qiling:
    shellcode = b''
    rootfs = r"C:\\"
    ql = Qiling( #利用qiling实例运行在windows系统下的X86-64的shellcode
        code=shellcode,
        archtype=QL_ARCH.X8664,
        ostype=QL_OS.WINDOWS,
        rootfs=rootfs, #指定模拟时的根文件系统
        console=True, #开启console output。qiling会把模拟的输出打印到console上
    )
    #参考https://docs.qiling.io/en/latest/hijack/
    ql.os.set_api("connect", _connect, QL_INTERCEPT.ENTER) #hook名为connect的api函数，_connect为实际执行的callback函数。QL_INTERCEPT.ENTER为callback函数调用的时间，这个值表示原connect函数被调用之前
    return ql
def main():
    ql = prepare()
    try:
        ql.run()
    except:
        pass
main()
```
106. [wysinwyg](https://ctftime.org/writeup/18786)
- 可以hook syscall，达到“调用某个syscall但其实执行的是其它函数”的效果。参考[Intercepting and Emulating Linux System Calls with Ptrace](https://nullprogram.com/blog/2018/06/23/).`__libc_start_main`里可能出现hook syscall的代码，多注意当init_array内容不仅为main函数的情况。
  - 一般由ptrace，一个child和一个parent process实现。可以更改syscall实际调用的函数，阻挡syscall调用，更改syscall num，创建自定义的syscall等
107. [sheepish](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/main/Reversing/sheepish),[wp](https://github.com/ret2school/ctf/tree/master/2023/imaginaryctf/reverse/sheepish)/[goated](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/main/Reversing/goated)
- lambda演算（lambda calculus）是图灵完备的，可以只用lambda编写程序。可用[Church encoding](https://en.wikipedia.org/wiki/Church_encoding)在lambda演算里表示数字。可以用 https://lambdacalc.io/ 可视化lambda演算
- wp里还展示了一些常见的算术操作与递归的lambda形式
108. [snailchecker](https://fazect.github.io/imaginaryctf2023-rev/#snailchecker)
- [Josephus Problem](https://www.geeksforgeeks.org/josephus-problem/)以及解决问题的[算法](https://sites.math.northwestern.edu/~mlerma/problem_solving/solutions/josephus.pdf)和逆算法（原来是n个元素，每隔m淘汰一个，找出剩下的k；逆向是给k和间隔m，找n）。间隔为2的最快算法： https://github.com/4rr4y/ctf-writeups/blob/main/2023_ImaginaryCTF/Reversing_SnailChecker.md
- `int.from_bytes(b, 'big')`的本质是`b[0] * 2 ** 24 + b[1] * 2 ** 16 + b[2] * 2 ** 8 + b[3]`
109. [unwind](../../CTF/moectf/2023/Reverse/unwind.md)
- windows SEH程序动态调试。参考 https://reverseengineering.stackexchange.com/questions/18192/stepping-into-exception-handler ，将断点下在`ntdll!ExecuteHandler2`的`call ecx`指令处，然后就能跟进看到接下来调用了什么函数了。若找不到`ntdll!ExecuteHandler2`这个symbol，可以x32/x64dbg ctrl+f搜指令`call ecx`。这个指令程序里不多，一个一个排除即可
- 静态分析做法： https://github.com/XDSEC/MoeCTF_2023/tree/main/WriteUps/chitaotao/re/unwind
- SEH详解+wp： https://blog.littflower.top/posts/moectf2023-unwind-and-a-little-windows-seh/
110. [ilovepython](https://github.com/cewau/ctf-writeups/blob/main/20230805-litctf/REV_ilovepython.md)
- python高级类型推断（逆变、协变）。这题非常复杂，看懂了python的类型就懂了（但是我看不懂，后面再遇到的话再看吧）
111. [What Is It](https://learn-cyber.net/writeup/What-Is-It)
- AutoIt脚本可能被隐藏在exe中（strings这样的exe会有AutoIt字样）。提取工具： https://github.com/nazywam/AutoIt-Ripper ,或 https://github.com/JacobPimental/exe2aut 反编译
112. [Old Obfuscation](https://learn-cyber.net/writeup/Old-Obfuscation)
- exe和python文件同时出现在一个文件夹下很有可能是pyinstaller打包程序。strings exe文件内有pyinstaller字样。可用[pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor)解压
- PyArmor混淆。参考 https://github.com/Svenskithesource/PyArmor-Unpacker/tree/main 进行反混淆
113. [Hollywood](https://learn-cyber.net/writeup/Hollywood)
- 当strings一个exe文件，发现里面有.NET字样时，说明这是个c#逆向题，可以用dnSpy反编译
- dnSpy可以编辑代码然后继续编译，可以利用这点绕过反动调。有时候编辑后会报错，但是仍然可以正常应用修改
114. z3使用案例
- 有人说，cvc solver有时要比z3更快，还能解出一些z3解不出的题： https://www.youtube.com/watch?app=desktop&v=CNQwSXKBGgw
- [Guardians of the Kernel](https://github.com/moabid42/CTF-Writeups/tree/master/SekaiCTF/Guardians%20of%20the%20kernel)
  - 如果在ghidra中看见类似`CONCAT17(buffer[7],CONCAT16(buffer[6],CONCAT15(buffer[5],CONCAT14(buffer[4],buffer._0_4_)`的CONCAT语句，z3里有现成的Concat函数(注意bit length，可以参考ghidra CONCAT函数的命名： https://stackoverflow.com/questions/69430800/what-does-concat15-and-concat412-mean-in-ghidra)
  - BitVecVal与BitVec的区别： https://stackoverflow.com/questions/49247323/what-is-the-difference-between-bitvec-and-bitvecval-in-z3 ,前者是常数，后者是要求解的symbol
  - z3 And函数使用（不确定和python的and有啥区别）
  - 参考 https://mcfx.us/posts/2023-09-01-sekaictf-2023-writeup/#guardians-of-the-kernel ，还有RotatLeft和RotateRight
- [Wrong Signal](https://trebledj.github.io/posts/ductf-2023-wrong-signal/)
  - 如何将一个byte分割为4个crumb（2个bit，或者说四分之一byte）
  - 如何将symbolic crumb组合成一个完整的byte(使用`z3.ZeroExt(n, bv)`，用于将bitvector bv添加n个前缀0)
  - `z3.If`使用:`z3.If(condition, then_expr, else_expr)`,类似三元表达式，可以嵌套
  - `z3.Not`，`solver.eval`,`as_long`
- https://github.com/sam-b/z3-stuff
- [Secure Computing](https://hackmd.io/@lunashci/SJuEkctd6#Secure-Computing)
  - 个人之前没见过的逆向方式。题目在init_array里多加了一个函数，函数内部调用了seccomp syscall，flag为SECCOMP_SET_MODE_FILTER。使用seccomp添加filter后，今后所有调用的syscall都会经过这些filter。需要从binary中自行提取出filter内容，然后用seccomp-tools反编译出内容：`seccomp-tools disasm --no-bpf export > chunk1`。比较特别的地方在于，filter内部可以写复杂的针对syscall number的运算汇编
  - 此题的z3部分在于根据filter内容编写合适的脚本
  - 另一个[wp](https://the-m3chanic.github.io/2024/01/26/Writeup-Secure-Computing-IRIS-CTF-2024/)讲得更详细。补充知识点：
    - seccomp-tools大部分情况下都可以使用ptrace自动dump出filter，意味着若程序里已有ptrace调用，需要patch掉后再dump。默认只会dump一个filter，加上`-l` flag可dump出完整的flag
    - [KLEE](https://klee.github.io/) Symbolic Virtual Machine (Solver)的安装及使用。可直接在C/C++语言文件上实现符号执行
- [Array Programming Rocks](https://tellnotales.xyz/posts/gcc-ctf24_array_programming_rocks_writeup/)
    - `.ua`程序逆向，对应的语言是[Uiua](https://www.uiua.org/)
    - 其他同样是z3解法的脚本： https://gist.github.com/meowmeowxw/f25ad75a2531f8c0ac24923d3bcc86dd
- [doubledelete's revenge](https://github.com/macenb/WriteUps/tree/main/WolvCTF_2024/doubledelete)
    - rol的python逆向实现（ror）。以及z3逆向rol的做法: https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#doubledeletes-revenge
    - 另一种无z3实现方式（更加具有普遍性）： https://ctf.krauq.com/wolvctf-2024#doubledeletes-revenge-105-solves
- [Palworld](https://ctf.krauq.com/wolvctf-2024#palworld-2-solves)
    - PLD file(defining digital logic)逆向
    - 使用z3+symbolic execution engine for circuit logic的解法： https://github.com/kjcolley7/CTF-WriteUps/tree/master/2024/wolvctf/palworld
- [15min-adventure](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/rev/15min-adventure)
	- RotateLeft的使用（对应ida里的`__ROL1__`操作）。有时候一个状态难写约束可以将其分成两个
- [decrypt-me](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/rev/decrypt-me)
	- [RNGeesus](https://github.com/deut-erium/RNGeesus)中Mersenne Twister的应用。这是一个利用z3 SMT求解PRNG的工具，除了这题用的MT，还有lcg，lfsr和dual_ec_drbg
- [mbaboy](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/rev/mbaboy)
	- z3里Array的使用
- [cagnus-marlsen](https://hackmd.io/@yqroo/TJCTF2024)
  - 如何将较为复杂的条件转换成在z3里可表示的条件
  - 如何利用z3获取多个不重复的解
  - 更复杂的解法： https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#cagnus-marlsen 。思路是把整个grid看成一个64 bit的BitVec，然后按照题目要求的方式切成多块并检查（自己做的时候完全没想到这个思路……看到这种题直接就想着用64个1 bit的bitvec，可是这样就很难写那些把几个bit看成一个整体的约束了。整体看成一个的话一个一个切就完事）。涉及： UGE, UGT, ULT, BitVec, BV2Int, Concat, Extract, Solver, Sum, ZeroExt，如何定义Slice函数，如何计算bitvec的hamming weight（ https://stackoverflow.com/a/61331081 ）
- K-out-of-N constraint（PbEq/PbLe/PbGe）： https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#archventure-time
- [watchdog](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/blob/main/Reversing/watchdog)
	- 又是被z3坑的一天……本来都逆出来逻辑了，是个多项式求值，给定几组(x,y)后逆出系数。本来说用Lagrange，结果发现程序的里的y值只能保存64bit，不是真正的结果。于是用z3，明明都按位或了，结果怎样都不对。搜了一下可能是z3使用带符号数的原因，不过不确定。官方解法是把它看成个线性模方程组，64位整数用模`2**64`代替
	- 其他解法（sage线性方程组求解和正确z3脚本）： https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#watchdog
- [Floats](https://github.com/imenyoo2/ctf_writeups/blob/main/wwctf2024/Floats.md)
  - 如何编写有关浮点数计算的z3脚本。这题计算的浮点数比较刁钻，`0.0`和`-0.0`。需要使用正确的类型z3才能正常工作，比如`FP("x", Float32())`。脚本见 https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#floats
  - [官方wp](https://github.com/WorldWideFlags/World-Wide-CTF-2024/tree/main/Reverse%20Engineering/Floats)提到这题的灵感来源： https://orlp.net/blog/subtraction-is-functionally-complete 。话说wp里的z3脚本长得还挺别致的（？）
  - 此题计算时只用了加和减两种运算，结果很像按位和。所以也可以用简单的bitvec来模拟方程
- [bloatware](https://sylvie.fyi/posts/bloatware)
  - 逆向js mixed boolean-arithmetic (MBA) expression混淆。这个混淆方式结合一堆位运算和算术运算，使整个算式看起来非常复杂，但实际上只是在做一些基本的操作。比如`(x ^ y) + 2 * (x & y)`等同于`x+y`。可以用[SiMBA](https://github.com/DenuvoSoftwareSolutions/SiMBA)简化线性MBA
  - MBA会影响z3，使z3解方程的复杂度变高。需要简化算式后再放入z3，不然可能没法在规定时间内跑出结果。我认为wp作者的做法太聪明了，没有使用上述提到的工具而是直接手搓了遍历ast并简化的代码；题目有1950个条件，利用随机生成的input尝试通过某个条件，然后比对能够通过条件的值找到潜在的规则。这个“潜在的规则”相当于简化了MBA算式方程，这时放到z3里就能解出来了
- 有些时候如果8-bit vector出不来结果，可以尝试用32-bit vector： https://github.com/opcode86/ctf_writeups/tree/main/wwCTF2024
115. [Conquest of Camelot](https://black-frost.github.io/posts/sekai2023/)
- OCaml语言binary逆向。这种语言的函数调用约定比较奇怪，ida可能无法生成伪代码。另外，这种语言对数组的操作会自动添加大量的bound checking，函数体会看起来很复杂但逻辑可能很简单
- 參考 https://mcfx.us/posts/2023-09-01-sekaictf-2023-writeup/#conquest-of-camelot ，（ida里）calling convection应该为`__int64 __usercall func<rax>(__int64 arg0@<rax>, __int64 arg1@<rax>, __int64 arg2@<rdi>)`
116. [Sahuang Flag Checker](https://github.com/TheBlupper/ctf_writeups/tree/main/sekaiCTF2023)
- use AVX-512 instruction set and other vector instructions to obfuscate a program。据说ghidra和ida都没法反编译，binja可以反编译一部分，错误的地方需要手动修改
- 只有支持AVX-512的cpu才能运行这类binary。可以用[Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html)运行
117. [SPACEGAME](https://github.com/D13David/ctf-writeups/tree/main/ductf23/rev/spacegame)
- lua love2d game engine游戏逆向。游戏的exe文件可以用binwalk提取出资源，包括lua脚本，不过是混淆过的。其中部分为混淆后的字符串，可参考wp的做法将其反混淆
118. [patchwork](https://github.com/MindSystemm/CTF-WriteUps/blob/master/Challenges/PatriotCTF23/Writeups.md#patchwork)
- 可配置ghidra使其反编译无法到达的代码段
119. [Impossibrawler!](https://github.com/D13David/ctf-writeups/tree/main/csaw23/rev/impossibrawler)
- godot engine游戏逆向。可利用工具 https://github.com/bruvzg/gdsdecomp recover project，然后在引擎内打开
- 也可以参考 https://github.com/n132/CTF-Write-Up/tree/main/2023-CSAW-CTF-Quals/Impossibrawler ，用工具并修改脚本后重新build： https://docs.godotengine.org/en/latest/contributing/development/compiling/index.html
120. [ANNS](https://github.com/sahuang/my-ctf-challenges/tree/main/vsctf-2023/rev_anns)
- python使用faiss库
121. [teenage_wasm](https://github.com/D13David/ctf-writeups/tree/main/vsctf23/rev/teenage_wasm)
- chrome dev tools调试wasm： https://developer.chrome.com/blog/wasm-debugging-2020/
122. [Skribl](https://github.com/4n86rakam1/writeup/tree/main/BuckeyeCTF-2023/rev/Skribl)
- python 3.13 pyc反编译。因为版本过高，大部分pyc反编译器都不能用， https://github.com/nedbat/coveragepy/blob/coverage-5.6b1/lab/show_pyc.py 可以。不过不能直接反编译成python代码，只能是类似python汇编的内容。不过直接用python自带的dis似乎也是一样的效果： https://github.com/chloge/BuckeyeCTF-2023/tree/main
123. [First Date](https://github.com/D13David/ctf-writeups/tree/main/sunshinectf23/rev/first_date)
- pdz后缀文件（Playdate PDZ）逆向。可以在[模拟器](https://help.play.date/manual/simulator/)内运行这类文件。相关逆向资料： https://github.com/cranksters/playdate-reverse-engineering
- pdz文件内部包含很多文件，可用binwalk提取（上面的逆向资料里也有pdz.py提取）。游戏内部的脚本使用lua（后缀luac，为Lua bytecode）。列举一些反编译器（但是据wp作者所说，它们基本都不支持lua高版本）：
  - [luadec](https://github.com/viruscamp/luadec)，反编译playdate bytecode的fork版本： https://github.com/scratchminer/unluac
  - [unluac](https://sourceforge.net/projects/unluac/)
  - [RustyLuaDec](https://github.com/dondish/RustyLuaDec)
  - 在线反编译器： https://luadec.metaworm.site/ ， https://lua-bytecode.github.io/ 
  - 额外做法：去 http://www.lua.org/ftp/ 找到对应的lua版本，下载后用里面内置的`./luac -l`反编译。假如是反编译playdate的bytecode，注意playdate的bytecode文件头稍微有些不一样，要按照wp里的做法改一下，而且会多一些自定义操作码（参考 https://github.com/cranksters/playdate-reverse-engineering/blob/main/formats/luac.md ），这个[fork](https://github.com/scratchminer/lua54)可以解决:
  ```sh
  curl -sLO https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar
  mkdir decompiled
  java -jar unluac.jar main.luac -o main.lua
  ```
  - 有助于手动反编译lua assembly的工具： https://www.luac.nl/ 。可参考wp作者的做法，就是自己写lua代码，然后看出来的bytecode是不是和目标差不多
- 其他wp/做法：
  - https://www.youtube.com/watch?v=qA6ajf7qZtQ
124. [What am I?](https://www.youtube.com/watch?v=-E3VTblFkKg)
- dll文件可以当作压缩文件（archive）打开，`.rsrc`文件夹下可能有图片之类的资源
125. [Intention](https://hackmd.io/@lawbyte/HJ3_3lT-a#Intention-356-pts)
- `AndroidManifest.xml`中`android:exported="true"`属性标记该activity可被安装在同一个设备上的其他application调用
- android api参考：
    - 什么是intent： https://stackoverflow.com/questions/6578051/what-is-an-intent-in-android 。 an "intention" to perform an action，比如用来启动一个activity
    - activity： https://developer.android.com/reference/android/app/Activity
    - setResult： https://developer.android.com/reference/android/app/Activity#setResult(int,%20android.content.Intent) 。返回结果到调用当前activity的activity
    - 如何用intent启动特定的activity并获取那个activity的返回结果
    ```java
    Intent intent = new Intent();
    intent.setComponent(new ComponentName("com.kuro.intention", "com.kuro.intention.FlagSender")); //设置要发送intent的component
    startActivityForResult(intent, 1337); //配合下面重写的onActivityResult接收返回结果
    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        //填获取data的具体步骤
        //注意调用的activity内部要是没有调用finish()，需要手动按返回键返回之前的activity
    }
    ```
- 其他wp： https://hackmd.io/@avila-pwn-notes/S1a16gqb6#Intention---356
126. [Imagery](https://hackmd.io/@avila-pwn-notes/S1a16gqb6#Imagery---436)
- android implicit intent拦截。构造intent时分两种，显示（explicit）intent和隐式（implicit）intent。显示intent类似指名道姓，指定要调用的activity。隐式则是指定了要调用的action，而不指定具体的activity。隐式intent有被安装在同设备的其他application拦截的风险。攻击者可在AndroidManifest.xml中添加intent-filter拦截隐式intent。拦截后可将intent原本的内容替换为自己构造的内容，顺便读取原本intent的内容。例如activity A->intent->被activity B拦截，篡改为_intent。处理后返回activityA->activity A在接下来的程序逻辑中使用恶意内容
- 拦截后intent的代码：
```kotlin
val pwnIntent = Intent()
pwnIntent.data = Uri.parse("file:///data/data/com.kuro.imagery/files/flag.txt") //本来是activity A内部的文件，现在篡改后攻击者可任意读取其内部文件
Log.d("exploit", "sending payload")
setResult(133337, pwnIntent)
finish()
```
127. [Netsight](https://hackmd.io/@avila-pwn-notes/S1a16gqb6#Netsight---496)
- export的activity不一定代表漏洞。但诸如webview的activity不应该被export，不然攻击者就可以打开任意的网页了
- webview client内部中可能有些函数标记着`@JavascriptInterfaces`，表示这些函数可以在打开的网页内用js脚本调用
- [Access to arbitrary components via WebView](https://blog.oversecured.com/Android-Access-to-app-protected-components/#access-to-arbitrary-components-via-webview):若攻击者可随意控制`Intent.parseUri`的参数，即可借此访问那些未被导出的component
- intent.setFlags(1)表示`FLAG_GRANT_READ_URI_PERMISSION`，允许读取调用者application的file provider中的文件。`@xml/provider_paths.xml`文件中记录了file provider中可共享的文件。可以用`content://`协议读文件
128. [Internals](https://hackmd.io/@lawbyte/HJ3_3lT-a#Internals-499-pts)
- [APKKiller](https://github.com/aimardcr/APKKiller):可以利用java的反射修改内部类以及字段。例如可以用[ActivityThread ](https://android.googlesource.com/platform/frameworks/base.git/+/master/core/java/android/app/ActivityThread.java)修改packageName字段
- 如何提取apk文件中的dex文件
121. [ElectroNES](https://github.com/D13David/ctf-writeups/tree/main/udctf23/rev/electro_nes)
- 使用[FCEUX](https://fceux.com/web/home.html)分析NES文件内存
- [NES memory mapping](https://github.com/solidajenjo/NES-Emulator/blob/master/DragoNES/DragoNES/docs/nesmemorymapping.txt)
122. [Dark Secrets](https://learn-cyber.net/writeup/Dark-Secrets)
- RPG Maker游戏逆向。由RPG Maker所制作的游戏的进程名为`RGSS2 Player`
- `.rgss2a`后缀文件存储着RPG Maker游戏的资源。可以用 https://github.com/uuksu/RPGMakerDecrypter 提取出被加密的资源。新建一个RPG Maker VX项目，将空项目的文件用提取出来的文件替换，即可用引擎将该游戏打开。打开后可以看见对话内容，修改敌人数据等
- 也有`.rgssad`后缀的资源文件。见 https://abuctf.github.io/posts/IronCTF
123. [Virtual RAM](https://ctftime.org/writeup/38229)
- Game Boy ROM image emulator:[BGB](https://bgb.bircd.org/)。这个模拟器可以查看vram
124. [Skilift](https://github.com/4n86rakam1/writeup/tree/main/GlacierCTF_2023/intro/Skilift)
- Verilog文件逆向（后缀`.v`）
125. [Electric Byte](https://github.com/heftymouse/writeups/blob/main/TUCTF23/rev/electric-byte.md)
- Electron app的ASAR文件可以用npx提取源代码
- 安装Electron环境后可以用`--inspect`加上`chrome://inspect`调试程序。注意版本要对，用strings查看binary内字符串即可
- 详细做法： https://www.youtube.com/watch?v=tMv671uPdZY
126. ghidra逆向xtensa的插件：
- https://github.com/Ebiroll/ghidra-xtensa
- https://github.com/yath/ghidra-xtensa
- 11.0版本无需插件，默认支持
127. [ZombieNet](https://jorianwoltjer.com/blog/p/ctf/htb-university-ctf-2023/zombienet)
- firmware(固件)分析。直接用 `binwalk -e` 可以得到不少有价值的内容。需确保安装[squashfs-tools](https://github.com/plougher/squashfs-tools)。可直接用`sudo apt install squashfs-tools`安装
- [CURLOPT codes](https://gist.github.com/jseidl/3218673)
- openwrt的boot process中的init部分步骤：
```
1. init reads /etc/inittab for the "sysinit" entry (default is "::sysinit:/etc/init.d/rcS S boot")
2. init calls /etc/init.d/rcS S boot
3. rcS executes the symlinks to the actual startup scripts located in /etc/rc.d/S##xxxxxx with option "start":
4. after rcS finishes, system should be up and running
```
- [官方wp](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/forensics/%5BMedium%5D%20ZombieNet)使用了qemu-mipsel模拟执行MIPS程序
128. [BioBundle](https://www.partywave.site/show/ctf/HTB%20University%20CTF%202023%20-%20BioBundle)
- 逆向动态加载的库（dynamically loaded libary）
- 程序里打开的所有文件都可以在`/proc/[PID]/[fd]`里读取到。只要文件打开了有fd就行，比如`dlopen`函数
- ghidra将bss段上的data转换为array
129. [RiseFromTheDead](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/rev/%5BHard%5D%20RiseFromTheDead)
- 使用pwntools Corefile分析core dump文件
- 个人做这题时是用gdb手动找的……参考 https://stackoverflow.com/questions/8305866/how-do-i-analyze-a-programs-core-dump-file-with-gdb-when-it-has-command-line-pa
130. [One Step Closer](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/forensics/%5BEasy%5D%20One%20Step%20Closer)
- 使用`cscript.exe`+visual studio动态调试vbs脚本
131. [Il2CppDumper](https://github.com/Perfare/Il2CppDumper)
- Unity IL2CPP编译打包的游戏的逆向工具。和一般用dnSpy逆向`Assembly-CSharp.dll`的题目（Mono打包）的区别是两者反编译方法不能共用。介绍网站： https://il2cppdumper.com
- 补充一道IL2CPP题目：[Bug Squash 2](https://crypto-cat.gitbook.io/ctf-writeups/2024/intigriti/game/bug_squash2)。使用Il2CppDumper的做法： https://snocc.dev/blog/1337UP-gamepwn#bugsquash2 。另一种反编译的方式是用cheatengine，见 https://www.youtube.com/watch?v=Nk-TNzHxN0M
- 再来一道：[Space Maze](https://github.com/tien0246/writeup/tree/main/spacemaze)。可以从文件头看出使用的unity版本，还可以用frida hook函数
- https://noob3xploiter.medium.com/hacking-and-reverse-engineering-il2cpp-games-with-ghidra-5cee894024f2
132. [noodle-nightmare](https://meashiri.github.io/ctf-writeups/posts/202312-pingctf/#noodle-nightmare)
- 有时候源代码复杂的逆向题编译后看汇编或动调反而会简单一点。还可以参考wp的做法，编译时保存C++ preprocessor的输出，逻辑也会简单很多
133. [Warmup - Game](https://github.com/rixinsc/ctf-writeups/blob/master/wgmy2023.md#warmup---game)
- unity逆向题一般会给出游戏本体exe文件以及几个文件夹，内置dll文件。如果只见到一个exe文件，仍然可以尝试用dnSpy加载该exe文件，检查是否有packer存在,例如[Appacker](https://github.com/SerGreen/Appacker)。可以在unpack函数处下一个断点查看工具将文件解压到了哪个文件夹，然后去那个文件夹拿到解压后的全部文件
- [UABEA](https://github.com/nesrak1/UABEA): Unity asset extraction tool
134. [Defeat_the_Boss](https://github.com/jasonpeh373/Wargame2023-RE)
- 利用 https://www.saveeditonline.com/ 修改RPGMaker制作的游戏的存档文件
- 游戏中出现的部分对话可以在游戏exe文件中通过strings得到内容及相关上下文
135. [ezandroid](../../CTF/moectf/2023/Reverse/ezandroid.md)
- apk lib文件逆向。如果在JNI_OnLoad中发现了RegisterNatives字样，说明存在动态注册逻辑。ida内部动态注册所使用的FindClass函数类似这样：`sub_17F0(v4, (__int64)"com/doctor3/ezandroid/MainActivity");`,v4可能是jni_env
136. [天网](https://github.com/XDSEC/MoeCTF_2023/blob/main/WriteUps/constellation/Reverse/%E2%80%9C%E5%A4%A9%E7%BD%91%E2%80%9D.md)
- c# .NET逆向。这类程序通常较大，因为除了程序本身还有运行时库需要打包。有些时候DnSpy无法正常识别程序，这时可以尝试用ILSpy
- c#中有个AppDomain.CurrentDomain.UnhandledException event，可注册委托函数，当程序发生异常时转入委托函数执行
137. [Sl4ydroid](https://sl4y3r-07.github.io/posts/BackdoorCTF'23-Writeups/#revsl4ydroid)
- 可以用jadx+adb调试Android apk应用程序
- 这篇[wp](https://gr007.tech/writeups/2023/backdoor/index.html#baby-ebpf)使用了[GameGuardian](https://gameguardian.net/forum/files/),可以查看内存。像是apk界的cheat engine
138. [Baby-ebpf](https://gr007.tech/writeups/2023/backdoor/index.html#baby-ebpf)
- ebpf文件逆向。ghidra似乎无法分析，直接`objdump -d`可以获取汇编
- 一个用来trace ebpf文件执行的脚本： https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#baby-ebpf
- IDA pro ebpf插件： https://github.com/zandi/eBPF_processor
139. [CSS Password](https://seall.dev/posts/uoftctf2024#reverse-engineeringcss-password-148-solves)
- 逆向CSS逻辑
- 补充wp：
  - https://vulnx.github.io/posts/UofTCTF/#reverse-engineeringcss-password
  - https://github.com/jjchoNC/ctf-writeups/tree/main/UofTCTF%202024/rev/CSS%20Password
140. [All Worbled Up](https://hackmd.io/@khoavnpsc/HkxcT5MY6)
- python bytecode assembly(字节码)手动反编译例题
141. [dicequest](https://github.com/digitaldisarray/writeups/blob/main/2024_2_2dicectf_quals_dicequest.md)
- 利用[scanmem & GameConqueror](https://github.com/scanmem/scanmem)扫描linux游戏内存并修改。可以用`kill -STOP pid`命令暂停某个进程；用`kill -CONT pid`继续
- 命令行版本工具使用： https://ctf.krauq.com/dicectf-2024#dicequest-107-solves
142. [nano](https://matth.dmz42.org/posts/2024/ptrace_based_self_debugging_binaries/)
- patch JZ/JNZ花指令
- ptrace在程序里的利用。ptrace系统调用可让一个进程跟进/调试另一个进程，且调试的进程可以读/写被调试进程的内存和CPU context。ptrace也可以作为一个反调试的手段，因为一个进程只可被一个进程trace（调试器同样利用了ptrace）。可以用waitpid查看被调试进程的状态，进而决定下一步（例如读取寄存器，存储寄存器等）。可以选择静态分析这类binary，或者尝试用strace命令trace父进程，即事先没有被trace的进程
- 不要相信反编译器。有些会触发segfault的指令在反编译出来的代码里看不到，只能读汇编
143. [dance](https://matth.dmz42.org/posts/2024/ptrace_based_self_debugging_binaries/#2-dance)
- 与上面那道题类似的思路，利用ptrace增加逆向难度。这次是用ptrace修改子进程的代码
- 一些反逆向手段：
  - 动态构造混淆lib文件并加载，运行时才一个指令一个指令解码。解码当前指令后销毁之前的指令，防止攻击者直接到最后提取完整lib
  - 对main函数代码实行checksum，若patch后程序直接退出
  - 使用syscall调用ptrace和exit而不是使用libc函数，防止攻击者通过hook LD_PRELOAD泄露信息
144. [MyVault](https://alisayed37.github.io/posts/myvault-writeup/)
- AndroidManifest.xml文件中的activity数量为程序screen的数量
- apk逆向题还是运行一下为好，有些信息光看代码看不出来。例如这题要求输入数字，运行程序会知道只能输入4位数字，但代码里看不出来
145. [Touch Grass](https://github.com/jjchoNC/ctf-writeups/tree/main/BITS%20CTF%202024/rev/Touch%20Grass)
- flutter apk逆向。参考 https://medium.com/@mohammadolimat/bitsctf-2024-reverse-writeup-0f15f28c342f
- 利用apktool解包apk并patch汇编再打包。重新打包的apk需要用[Uber Apk Signer](https://github.com/patrickfav/uber-apk-signer)或者类型签名工具签名后才能安装
- 和传感器及相关插件（accelerometer，pedometer，sensor_plus）有关的题目可以从onSensorChanged事件下手
146. [flag-finder](https://medium.com/@mohammadolimat/la-ctf-2024-reverse-writeup-6d05acd9c7be)
- `.win`,`.unx`后缀(Game Maker Studio游戏文件)修改工具:[UndertaleModTool](https://github.com/UnderminersTeam/UndertaleModTool)使用
147. [technically-correct](https://hackmd.io/@lamchcl/SJIdwQb3a#revtechnically-correct)
- 有些时候可以通过修改elf文件的header，使反编译器无法读取elf文件。解决办法是自行用readelf看一遍文件，寻找有没有不符合头部定义的内容（大端/小端？32/64？）
148. [Injecting Commands](https://intrigus.org/research/2024/03/03/braeker-ctf-2024-injecting-commands-writeup/)
- Mach-O binary(macOS)逆向。binary的代码用特殊格式隐藏在了文件里，Ghidra无法直接分析。可以用[ImHex](https://github.com/WerWolv/ImHex)内置的pattern分析文件，出错后也可以自行修改pattern
- Mach-O binary中，程序入口点由LC_UNIXTHREAD决定（新版在LC_MAIN）
- 利用GitHub Actions调试不同平台的程序:[action-tmate](https://github.com/mxschmitt/action-tmate),otool，lldb分析程序信息
- 使用Unicorn模拟运行程序
149. [binaryshrink](https://mahmoudelfawair.medium.com/breakerctf-24-binaryshrink-4cc9feae0259)
- tinyELF类型题可使用radare2调试binary，获取指定内存处地址。有时候ghidra和ida都无法识别的binary radare2可以
- 参考 https://github.com/D13David/ctf-writeups/tree/main/braekerctf24/rev/binary_shrink ，也可以用objdump
150. [The mainframe speaks](https://github.com/D13David/ctf-writeups/tree/main/braekerctf24/rev/mainframe)
- Rexx(Regina Rexx)混淆脚本分析
151. [beehive](https://blog.bi0s.in/2024/03/02/RE/beehive-bi0sCTF2024/)
- eBPF程序基础知识及逆向。可以用`llvm-objdump`获取汇编代码
- ida eBPF程序分析插件使用:[eBPF_processor](https://github.com/cylance/eBPF_processor)
- 加载eBPF程序到kernel内并与之交互，调用eBPF程序hook的自定义syscall
152. [GccChat](https://0xmirasio.github.io/2024-02-02-GCC-gcchat1&2/)
- 可用[hermes-dec](https://github.com/P1sec/hermes-dec)反编译被编译成Hermes VM bytecode的React Native framework文件。也可以直接修改汇编的字节码，保存后重新打包、签名apk即可运行修改逻辑后的apk
- 官方wp更详细： https://github.com/GCC-ENSIBS/GCC-CTF-2024/tree/main/Reverse
153. [Faulty Network](https://github.com/InfoSecIITR/write-ups/blob/master/2024/vishwa-ctf-2024/rev/Faulty%20Network/Faulty_Network.md)
- python torch神经元网络逆向。暂时还不懂AI这方面的东西，先记着吧
154. [UnholyEXE](https://github.com/strobor/ctf-writeups/tree/main/wolvctf2024/UnholyEXE)
- ZealOS可执行文件ZXE逆向。ghidra无法直接反编译这类文件，需要在ghidra里手动patch（比如添加引入的外部函数的memory map等）
- 可用virtualBox boot zealOS帮助分析；可用ImDisk挂载ZealOS的文件系统并且修改
155. [game-graphics-debugging](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/game-graphics-debugging)
- 通过调试程序分析程序无法运行的原因。结合一点个人经验，大部分情况都是缺失了某个dll。IDA的dubugger options里有个`Suspend on library load/unload`，能帮助找到缺失的dll/函数。找到程序要求的dll后放在程序所在的相同目录下即可
- 有些时候flag会藏在某个线程的TLS（ThreadLocalStorage）中。这种藏flag的情况适用于那些没有输入的逆向题
- 官方的视频解法： https://github.com/WolvSec/WolvCTF-2024-Challenges-Public/tree/master/rev/graphics ，使用不同GPU debuggers
156. [flagen](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Unbreakable-Individual-2024/flagen.md)
- 使用apk[在线模拟器](https://appetize.io/)动态分析apk
157. [the-heist-1](https://cyberghost13337.github.io/2024/03/24/JerseyCTF-2024.html#the-heist-1)
- rol的python实现
158. [WeirdSnake](https://hackmd.io/@tahaafarooq/picoctf-2024-reverse-engineering#WeirdSnake-300-Points)
- python bytecode逆向。可以用`dis.dis(function_name)`查看某个函数的bytecode。对于同一段代码，不同版本的python会给出不同的bytecode。一定要注意用`dis.dis`边逆向边比对目标，你以为的代码不一定是你以为的
- 另外个人做题时发现反编译时似乎有点“联系上下文”的意思。比如一个代码片段里调用了FOR_ITER，但是前面却没有GET_ITER。然后找到调用这个函数的代码段，发现GET_ITER在调用函数前的代码段里（如果不追究语法的话，以后看到GET_ITER就遍历即可）
159. [Fruit Deals](https://github.com/S4L1M-abd/UTCTF-WriteUPS/tree/main/Reverse/Fruit%20Deals)
- xlsm excel sheet文件中的vba macro逆向。虽然很容易找到工具（oletools中的`olevba.exe`）提取出sheet文件里的macro，但是用excel打开可以运行并调试代码，有助于逆向
160. [In The Dark](https://gist.github.com/nrabulinski/ba0a6927866e822e27faae190185a0f1)
- 使用rust Ptracer trace另一个程序。可以调试，查看寄存器的值，修改内存（patch）等
161. [Alien](https://github.com/tamuctf/tamuctf-2024/tree/master/rev/alien)
- 使用QEMU运行嵌入式系统的固件（use QEMU to run firmware for embedded systems）。题目是lm3s6965固件
162. [hole](https://hackmd.io/@Zzzzek/HyUXVYQl0#hole)
- Erlang/Elixir `.beam`后缀文件逆向。wp里是手动反编译的做法,但赛后发现有自动反编译器： https://github.com/michalmuskala/decompile
163. [FLARE-VM](https://github.com/mandiant/flare-vm)
- 集成了各种reverse工具的vm配置环境
164. [pickledbg](https://github.com/Legoclones/pickledbg)
- python pickle文件调试器
165. [warmup](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/rev/warmup)
- binja/ghidra/ida的一些bug，可用于混淆代码。参考 https://blog.es3n1n.eu/posts/obfuscator-pt-1/ 。对于不同反编译器，这些指令会使其无法反编译：
```
ida: ENTER 0xFFFF, 0xFF
binja: adc
ghidra:
mov     r13, 0xffffffffffffffff
lea     r13, [r13]
mov     r8, qword [r13]
```
166. [wonderful](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/rev/wonderful)
- 若binary内部有一个名为`.themida`的PE section，说明此binary被Themida加密过了。wp记录了这类binary的分析过程
167. [food-without-salt](https://fastcall.dev/posts/sdctf-rev-2024/)
- godot engine游戏逆向。之前记过要用[gdsdecomp](https://github.com/bruvzg/gdsdecomp)反编译出工程文件，但这题多了个花样，工程文件被加密了。参考 https://godot.community/topic/35/protecting-your-godot-project-from-decompilation 。长话短说，可用[gdke](https://github.com/char-ptr/gdke)提取出密钥，将密钥输入到gdsdecomp即可
168. [Fly Away!](https://hackmd.io/@avila-pwn-notes/r183kzlEA)
- [Flutter](https://flutter.dev/) android apk逆向工具[reFlutter](https://github.com/Impact-I/reFlutter)使用。这个工具替换要逆向的apk的lib文件，使其在执行过程中打印出供调试的信息，后续还可用burpsuite监控流量。还能搭配frida框架hook函数
169. [Perfectly Legit Crypto Casino](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Nahamcon-2024/Malware/Perfectly_Legit_Crypto_Casino.md)
- Electron应用程序逆向。这类应用的源码在`app.asar`文件里，解压方式参考 https://github.com/clausmalver/ctf-writeup/tree/main/Nahamcon_2024
- 这题的软件是针对macOS开发的，所以用mac打开会发现这个程序有个自定义的图标。但本质上还是个目录，可以直接cd进去
170. [What's in the Box?](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Nahamcon-2024/Rev/Whats_In_The_Box.md)
- Makeself POSIX shell script executable(self-executable archive)。这类脚本执行的代码在尾部（具体是第几行可以自行打开文件查看）,tail等命令可以提取出代码
- 也可以在运行途中去tmp目录找到执行的代码： https://medium.com/@0xMr_Robot/nahamcon-ctf-2024-reverse-engineering-challenges-b397296721c1
171. [Buggy Jumper](https://www.youtube.com/watch?v=t_7eETJO6v8)
- 如何使用Android Studio调试apk
172. [CC](https://github.com/imenyoo2/ctf_writeups/tree/main/L3akCTF%202024)
- python gdb script使用。发现了一个之前没想到过的逆向方式——可以同时开启两个gdb实例，两者用两个文件通信。这样就能实现实例1调用实例2里的函数了。我记得C语言里有不需要中间文件直接跟一个进程通信的函数，不知道gdb里行不行
173. [Anti](https://github.com/L3AK-TEAM/L3akCTF-2024-public/tree/main/rev/Anti)
- HOP(Hook_Oriented_Programming)反调试技巧： https://github.com/moabid42/anti-debug
174. [Parabox](https://github.com/rex69420/ctf-writeups/tree/main/GPN%20CTF%202024/rev/parabox)
- GameBoy reverse。一些gameboy emulator（模拟器）：[Gearboy](https://github.com/drhelius/Gearboy/),[BGB](https://bgb.bircd.org/)。此wp使用后者解题
- python记录键盘按下的键和脚本模拟按键
- ghidra gameboy插件： [GhidraBoy](https://github.com/Gekkio/GhidraBoy)
- 其他wp： https://github.com/Capo80/CTF-Writeups/tree/main/gpn_2024/parabox
175. [Electric](https://github.com/MathVerg/WriteUp/tree/master/GPN2024/Electric)
- 如何运行python compiled library（[Cython](https://github.com/cython/cython) ）
176. [Everlasting_Message](https://justinapplegate.me/2024/codegatectf-everlastingmessage/)
- 认识一些C语言函数
  - Message Queues: msgget/msgsnd/msgrcv/msgctl
  - Process Threads: pthread_create
  - 以及如何在ghidra里创建这些函数用到的struct结构类型
- python gdb script编写
177. [Mips](https://kos0ng.gitbook.io/ctfs/write-up/2024/akasec-ctf/reverse-engineering)
- Nintendo 64 ROM image逆向。注意和97条的Nintendo DS Slot-2 ROM image不是一个东西。参考文章： https://blog.quantumlyconfused.com/ctf/2022/05/22/nsec2022-n64/ ；可用[ares](https://ares-emu.net/)模拟运行并调试；可用ghidra插件[N64LoaderWV](https://github.com/zeroKilo/N64LoaderWV)反编译image
- ares的调试模块是一个gdb server，配置端口后用gdb-multiarch连接即可进行调试，因为Nintendo 64 ROM image的架构不是常见的amd64,是MIPS
- 另一种逆向方式：将z64 ROM转为ELF后ida pro配上 https://assemblergames.org/viewtopic.php?t=39372 即可。如何转化： https://gist.github.com/JayFoxRox/5eaa45b374a44ce27143388bab1753b7
178. [Orgalorg](https://kos0ng.gitbook.io/ctfs/write-up/2024/akasec-ctf/reverse-engineering)
- python gdb script编写：如何自定义gdb里的命令
179. [My Brain Hurts](https://github.com/kaien07/CTF-Writeups/tree/main/BCACTF%202024/My%20Brain%20Hurts)
- brainfuck逆向
180. [lambda](https://octo-kumo.github.io/c/ctf/2024-wanictf/rev/lambda)
- [Lambdifier](https://github.com/gio54321/lambdifier):利用lambda表达式的python混淆/反混淆脚本
181. [Rustyschool](https://github.com/perfectblue/ctf-writeups/tree/master/2024/googlectf-2024/rev-rustyschool)
- （痛苦）逆向rust的记录
- 技巧还是有的，比如用trace函数了解大致调用了什么函数；比对两次trace结果就能知道是否有随机成分，具体在哪里；patch rust的random相关函数来控制其seed；动调通常比静态分析更适合rust……但更多是逆向实力+数学
- 官方wp比较简短： https://github.com/google/google-ctf/tree/main/2024/quals/rev-rustyschool
182. [push_and_pickle](https://github.com/rerrorctf/writeups/tree/main/2024_06_29_UIUCTFCTF24/misc/push_and_pickle)
- 使用[pickleassem](https://github.com/gousaiyang/pickleassem)手动编写pickle opcode。手动编写相比于自动生成可以绕过一点过滤，比如global和global_stack opcode（`c`和`\x93`）不是必需的
- python pickle code逆向。可以用radare2配合pickle插件，或者直接用python版本小于3.9的uncompyle6。作者没提到是什么插件，网上搜到的第一个结果是[r2pickledec](https://github.com/doyensec/r2pickledec)
- 其他wp： https://gist.github.com/C0nstellati0n/78f5887b5bee235583a026840354ae54#push-and-pickle 。又认识了几个工具：
  - [astor](https://github.com/berkerpeksag/astor):将AST转换为代码
  - [Fickling](https://github.com/trailofbits/fickling):将pickle转为AST
    - 补充一个使用fickling的题目：[pickle-season](https://github.com/x3ctf/challenges-2025/blob/main/rev/pickle-season)。也可以用python自带的pickletools模块，不过要用python 3.14的pickletools，旧版本的有些bug
  - [pker](https://github.com/EddieIvan01/pker):更方便创建pickle opcodes
183. [tooooo fancy](https://hackmd.io/@fsharp/ryuOxo1DC)
- [tcl](https://en.wikipedia.org/wiki/Tcl)语言汇编逆向。如果题目提供了程序的机器码，可以用[tbcload](https://github.com/corbamico/tbcload)将其转换为assembly code。指令集参考 https://core.tcl-lang.org/tclquadcode/wiki?name=Standard+Tcl+Bytecodes
184. [Time Travel](https://nesrak1.github.io/2024/07/06/timetravel.html)
- 逆向由[5D Brainfuck With Multiverse Time Travel](https://esolangs.org/wiki/5D_Brainfuck_With_Multiverse_Time_Travel)编写的程序。这个语言太癫了，wiki界面也云里雾里的。建议直接把这篇wp看成这门语言的介绍
- 调试普通brainfuck的调试器： https://ashupk.github.io/Brainfuck/brainfuck-visualizer-master/
185. [sssshhhh](https://medium.com/@harryfyx/writeup-ductf-2024-sssshhhh-d2fac53f2ed1)
- ghidra逆向golang程序案例
- 官方wp： https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/beginner/sssshhhh
186. [Wacky Recipe](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/misc/wackyrecipe)
- 逆向esoteric language [chef](https://esolangs.org/wiki/Chef)。相关文档： http://progopedia.com/language/chef/
- 其他wp： https://github.com/EnchLolz/DUCTF-24/blob/main/MISC/Wacky%20Recipe.md
187. [Irony](https://stelin41.github.io/en/posts/irony_catthequest2024_ctf/)
- 逆向gameboy rom。发现[GhidraBoy](https://github.com/Gekkio/GhidraBoy)插件不是什么时候都好用，比如这题就基本没分析出来东西。不过[BGB](https://bgb.bircd.org/)模拟器（也是调试器）还是好用的
- 手动分析gb studio bytecode。见[GBVM Operations](https://www.gbstudio.dev/docs/scripting/gbvm/gbvm-operations/)和[GB Studio](https://github.com/chrismaltby/gb-studio)
188. [bf](https://yun.ng/c/ctf/2024-ictf/rev/bf)
- 使用[debugger](https://bxt.gitlab.io/brainfuck-debugger/)调试brainfuck代码。不过这题主要利用的工具还是这个可以运行brainfuck并限制步数上限的js库：[braincrunch](https://github.com/Macil/braincrunch)
189. [The Moon](https://gist.github.com/TrixterTheTux/6ed0999479443823538fe2d1b8739458)
- 逆向lua脚本。好新颖的一道题，调试方法也挺神奇。因为脚本内部加了一堆反调试的代码，所以直接从lua的内部实现下手，让代码里使用的关键函数有方便调试的输出，就能弄明白题目的逻辑了
- 遇见一道“类似”的题，也是逆向混淆后的lua脚本：[Lost](https://github.com/uniquadev/ctf-writeups/blob/main/trx-ctf-2025/lost)
  - 混淆后的脚本可以用诸如[lua-beautifier](https://goonlinetools.com/lua-beautifier)的工具美化。若美化后的脚本输出与原本脚本的输出不一样，可能是脚本内有integrity check
  - 可以hook lua内的库函数从而得知脚本调用了什么函数以及在何处调用。比直接修改lua的函数便捷
190. [html](https://github.com/Thehackerscrew/CrewCTF-2024-Public/tree/main/challenges/rev/html)
- [html语言](https://html-lang.org)逆向。不是网站的那个html，确确实实是一种编程语言，只是故意设计的像html。有位大佬写了个转换器，可将这种语言转为python代码： https://github.com/harrier-lcc/html-python-transpile
191. [Secure Computing](https://github.com/Pusty/writeups/tree/master/SekaiCTF2024)
- 使用windows kernel syscall作为opcode的vm。见[windows-syscalls](https://github.com/j00ru/windows-syscalls)。dump所有syscall的脚本见wp
192. [Magnum-Opus](https://github.com/trinityhall49/writeups/tree/main/challenges/rev/python/sekaictf-magnum-ops-2024)
- 又是一道python pickle bytecode逆向题,利用reduce操作执行python内部的的函数（pickle反序列化漏洞也是这个原理）
- 这篇wp的做法是patch pickle的源代码（`/usr/lib/python3.11/pickle.py`），使其输出诸如调用函数和参数之类的调试信息
- 建议不要自己实现pickle vm，太复杂了，容易有很多bug。建议直接像这篇wp一样利用hook的方式进行逆向
193. [BlackHole](../../CTF/moectf/2024/Reverse/BlackHole.md)
- 如何使用mingw-w64在linux上编译c文件到exe
194. [bootme](https://github.com/Pusty/writeups/tree/master/m0leConCTFTeaser2025)
- 如何逆向`bootloader.bin`。这类bin没法直接放到反编译器里，需要自行找到起始偏移和代码relocation后的地址才能看到重要的逻辑
195. [m0veCon](https://github.com/Pusty/writeups/tree/master/m0leConCTFTeaser2025)
- 逆向Move语言binary。一些参考资料：
  - https://www.zellic.io/blog/introducing-movetool/
  - 另一个有关move的wp： https://leoq7.com/2023/02/PBCTF-Move-VM
  - 反编译器： https://github.com/move-language/move-on-aptos ， https://aptoslabs.medium.com/move-revealed-the-revela-decompiler-b206eaf48b45
196. [upx-revenge](https://github.com/XDSEC/MoeCTF_2024/blob/main/Official_Writeup/Reverse/Moectf%202024%20Reverse%20Writeup.md)
- UPX解压的时候会检测程序段名称是否为UPX0\UPX1这类的,如果段名称被人为篡改则无法正常解压。把名称改回来，或者动调，手动脱壳即可
197. [Cython-Strike: Bomb Defusion](http://www.qetx.top/posts/14919)
- 如何“逆向”pyd文件。似乎这种文件没法反编译，只能用import指令导入模块后用help查看模块里作者提供的内容
198. [Lighthouse of DOOM](https://snocc.dev/blog/1337UP-gamepwn)
- 逆向`.tap`后缀文件（ZX Spectrum游戏）。相关内容：
  - 文章： https://mrcook.uk/reverse-engineering-zx-spectrum-games
  - 反编译工具：[SkoolKit](https://github.com/skoolkid/skoolkit)
  - 模拟器：[Fuse](https://fuse-emulator.sourceforge.net)
  - 逆向工具：[Spectrum Analyser](https://colourclash.co.uk/spectrum-analyser)。使用这个工具的视频wp： https://www.youtube.com/watch?v=ZcnWdFjS5WE
199. [Funny](https://dungwinux.github.io/-blog/security/2024/11/17/1337up-live-writeup.html)
- 逆向pyc文件的技巧
  - 由于python每次版本更新可能会修改opcode，所以不同版本的python生成pyc的magic number不同，也就不能跨版本运行。因此，相关反编译工具pycdc（也叫Decompyle++）也无法反编译较新版本的pyc。提供一个暂时的解决方法： https://idafchev.github.io/blog/Decompile_python ，通过假装支持某些opcode从而阻止工具停止运行
  - dis module可以反编译pyc文件，不过要跳过文件起始处的文件头。见 https://stackoverflow.com/a/59431935
  - `dis.get_instructions`可以提供opcode的详细内容，比如各个opcode的行列号（坐标）
200. [platyprotect64](https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#platyprotect64)
- 逆向`.prg`后缀文件（Commodore C64 program）
201. [BasicAVR](https://github.com/Cryptonite-MIT/niteCTF-2024/blob/main/hardware/BasicAVR)
- 似乎是逆向atmega2560 microcontroller程序elf，基于avr8。指令集参照 https://ww1.microchip.com/downloads/en/DeviceDoc/AVR-Instruction-Set-Manual-DS40002198A.pdf
202. [Between Two Worlds](https://hackmd.io/@Solderet/rk2g-kwr1g)
- 逆向[Windows Mixed Mode Assemblies](https://learn.microsoft.com/en-us/cpp/dotnet/mixed-native-and-managed-assemblies)。这题由c#和native code组成，同一个binary需要用两种不同的反编译器打开才能看到完整逻辑
- [Reverse Engineering Mixed Mode Assemblies (IDA, DnSpyEx)](https://www.youtube.com/watch?v=H8gr3NxWteM)
203. [Sentir](https://gist.github.com/C0nstellati0n/a066c450ed5d4c8ffbb0c1328283fe14#sentir)
- 逆向`.NET` AOT程序： https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net
204. [oh-my-gadt](https://scuffed.online/x3ctf-2025)
- 逆向混淆过的Haskell代码。看来大家都用AI辅助啊
- 比赛时尝试动调，差点给我连蒙带猜逆出来了。还是wp的做法聪明些，把函数定义拿出来调用看一下做了什么
- 静态分析做法及haskell gadt介绍： https://pingotux.si/blog/oh-my-gadt
205. [secure-snek](https://github.com/x3ctf/challenges-2025/tree/main/misc/secure-snek)
- 逆向混淆后的python代码。这题的混淆方式类似虚拟机vm，可以参考 https://forum.tuts4you.com/topic/44240-python-obfuscated-keygenme 的方式添加trace代码查看调用的函数
206. [elfisyou](https://gist.github.com/tillvit/441d9fec637f1d9c1f17f00fcca7dfe3)
- （minimal）elf格式解析
207. [mcflagchecker](https://github.com/carl-vbn/cucyber-ctf-writeups/tree/main/lactf-2025/rev/mcflagchecker)
- 逆向minecraft [Data pack](https://minecraft.wiki/w/Data_pack)中的`.mcfunction`“代码”逻辑。不完全是代码是因为里面的命令缺少大部分语言里的功能，比如if和变量之类的。很多人用工具将普通代码（cbscript）转换为`.mcfunction`（见 https://github.com/uclaacm/lactf-archive/tree/main/2025/rev/mcflagchecker ），因此自己根据规律写一个反编译器是可能的
- 其他wp： https://github.com/EllE961/LA-CTF-McFlagChecker
208. [Pika-Pika](https://github.com/E-HAX/EHAX-CTF-2025/tree/master/rev/PIKA-PIKA)
- Pokemon GBA games逆向工具：[Hex Maniac Advance](https://github.com/haven1433/HexManiacAdvance)
209. [World's Hardester Flag](https://blog.mard.kr/ctf/2025/02/26/BroncoCTF-Writeup.html)
- 使用[Dex Explorer](https://www.reddit.com/r/ROBLOXExploiting/comments/14y4xqr/noobie_guidedocument_to_using_dex_explorer)查看roblox游戏内的object与脚本
210. [buckys-impossible-obby](https://github.com/ZTzTopia/ctf/tree/main/writeups/2025/broncoctf/forensics/buckys-impossible-obby)
- roblox studio使用
- 其他wp（这题好像允许攻击者执行任意lua代码？）： https://github.com/ZTzTopia/ctf/tree/main/writeups/2025/broncoctf/misc/worlds-hardester-flag
211. [LLL](https://unoarroefy.github.io/blog/trx2025)
- 逆向[Service Modeling Language](https://en.wikipedia.org/wiki/Service_Modeling_Language)（`.sml`）
212. [Molly](https://ctftime.org/writeup/40045)
- 分析dll+exe。dll文件的entry point函数全部执行完后才到当前进程（exe文件）
213. [rulemaster](https://github.com/TheRomanXpl0it/TRX-CTF-2025/blob/main/rev/rulemaster)
- 逆向`.cbc`文件（文件头`ClamBC`，ClamAV signature bytecode）
- 另一道类似的题： https://vince-qu.com/posts/24_07_13_hitcon_antivirus.html
214. [Flattened Vyper](https://md.updownup.de/s/IswdBTUYe)
- 逆向solidity evm code。可以用[evm-run](https://github.com/zemse/evm-run)运行代码