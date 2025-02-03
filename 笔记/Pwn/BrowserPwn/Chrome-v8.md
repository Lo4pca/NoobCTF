# Chrome V8

我这次真的只做最简短的笔记，真的（

Part-1包含大部分外部资源和作者编写教程的动机，此处省略

## [Part-2](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-2)

V8是chrome浏览器里很小的一部分，存在沙盒，因此没法直接通过v8漏洞控制整个系统，一般只针对v8进程。v8高度模块化，所以可以脱离Chromium内部其他的代码学习

解释型语言通常需要经历一个从中间语言转换成cpu支持的指令的过程，故运行速度很慢。不过大部分js引擎选择将js代码编译成特定架构的机器码，称为Just-in-Time (JIT)编译。编译过程前期消耗较大，但是运行起来很快。面对一段代码，js引擎首选第一种做法；当检测到某段代码被多次运行后，则会编译代码

v8中比较重要的部分：
- [Ignition](https://v8.dev/docs/ignition):v8的解释器,负责生成js的字节码
- Turbofan:v8唯一的编译器(2017年前用的是Crankshaft)。当v8检测到某段代码被调用多次后，Turbofan会编译这段代码，并在未来的调用中重定向程序控制流到编译好的JIT段。大部分v8 bug都在这里出现，因为js本来是“不该”被编译的
- [Liftoff](https://v8.dev/blog/liftoff)：负责从WebAssembly创建机器码。能够快速编译WebAssembly，不过具体的优化过程还是靠Turbofan。区别于Ignition，它会立刻将编译结果交给Turbofan，而不是等待一段代码被运行多次后
- [Torque](https://v8.dev/docs/torque)和CodeStubAssembler( [CSA](https://v8.dev/blog/csa) )：为了获得更好的性能，v8预编译了ECMAScript标准定义的内置（built-in）函数。本来是用CSA写的，但是手写这些汇编函数导致了太多bug，于是Torque出现了。Torque帮助开发者在v8支持的各种架构中为内置函数编写高效的代码