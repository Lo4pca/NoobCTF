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