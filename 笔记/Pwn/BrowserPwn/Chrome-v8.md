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