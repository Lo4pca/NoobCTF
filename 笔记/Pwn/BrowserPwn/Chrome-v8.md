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