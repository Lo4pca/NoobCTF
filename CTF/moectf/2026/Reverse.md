# 2B 小模型

第一步依旧是扔给ds。它很快就分析出这是一个三层的线性神经网络，每层均为线性变换。第三层输出12个值，最后通过一个30×12的线性层得到最终的字符。这听起来像是z3的活，所以我叫它“用z3重写反编译代码来求解，未知的数据段可留空让我来填入”。于是得到了如下脚本：

```py
from z3 import *
import struct

# Layer 1: FUN_140002030(0x140003030, 0x140003000, ...)
#   W1: 12x12 ints (32-bit signed) at 0x140003030
#   b1: 12 ints (32-bit signed) at 0x140003000
# Layer 2: FUN_140002030(0x1400032a0, 0x140003270, ...)
#   W2: 12x12 ints at 0x1400032a0
#   b2: 12 ints at 0x140003270
# Layer 3: FUN_140002030(0x140003510, 0x1400034e0, ...)
#   W3: 12x12 ints at 0x140003510
#   b3: 12 ints at 0x1400034e0
# Final Layer: weights at DAT_140005100 (30x12 longlongs)
#              bias at DAT_140005010 (30 longlongs)

W1 = [[0]*12 for _ in range(12)]   # 12x12 ints
b1 = [0]*12                        # 12 ints

W2 = [[0]*12 for _ in range(12)]   # 12x12 ints
b2 = [0]*12                        # 12 ints

W3 = [[0]*12 for _ in range(12)]   # 12x12 ints
b3 = [0]*12                        # 12 ints

W4 = [[0]*12 for _ in range(30)]   # 30x12 longlongs
b4 = [0]*30                        # 30 longlongs

def unpack_at(fp,offset,cnt):
    fp.seek(offset)
    return struct.unpack('<' + 'i' * cnt, f.read(cnt*4))
with open("chall13.exe",'rb') as f:
    W1=unpack_at(f,0x1630,144)
    W1=[W1[i*12:(i+1)*12] for i in range(12)]
    b1=unpack_at(f,0x1600,12)

    W2=unpack_at(f,0x18a0,144)
    W2=[W2[i*12:(i+1)*12] for i in range(12)]
    b2=unpack_at(f,0x1870,12)

    W3=unpack_at(f,0x1b10,144)
    W3=[W3[i*12:(i+1)*12] for i in range(12)]
    b2=unpack_at(f,0x1ae0,12) #?
#FUN_140001b50生成的数据不依赖输入
#x64dbg在FUN_140001b50调用完成处下个断点，然后运行 savedata data.bin,DAT_140005010运行时的实际地址,0x1000
with open("data.bin",'rb') as f:
    b4=struct.unpack('<' + 'q' * 30, f.read(30*8))
    W4=struct.unpack('<' + 'q' * (30*12), f.read(30*12*8))
    W4=[W4[i*12:(i+1)*12] for i in range(30)]

s = Solver()

x = [Int(f'x{i}') for i in range(12)]
for xi in x:
    s.add(xi >= 0, xi <= 95)

def linear_layer(inputs, W, b, out_size):
    """Build a linear layer: out[i] = b[i] + sum_j W[i][j] * inputs[j]"""
    outputs = []
    for i in range(out_size):
        expr = b[i]
        for j in range(len(inputs)):
            expr += W[i][j] * inputs[j]
        outputs.append(expr)
    return outputs

y1 = linear_layer(x, W1, b1, 12)
y2 = linear_layer(y1, W2, b2, 12)
y3 = linear_layer(y2, W3, b3, 12)
y  = linear_layer(y3, W4, b4, 30)

for yi in y:
    s.add(yi >= 0x20, yi <= 0x7e)

flag_start = "moectf{"
for i, ch in enumerate(flag_start):
    s.add(y[i] == ord(ch))
s.add(y[29] == ord('}'))

if s.check() == sat:
    m = s.model()
    inp = [m[xi].as_long() for xi in x]
    print("Found input:", inp)
    out_vals = [m.evaluate(yi).as_long() for yi in y]
    print("Output bytes:", out_vals)
    print("Output string:", ''.join(chr(c) for c in out_vals))
```
顺利得到flag。但是在我整理脚本，删除最开始的占位数据后，再运行竟然报错了。罪魁祸首是我标注问号的那行，我抄代码时忘记改变量了……赶紧改回来，但改正后反而得不到flag了……

后面和ds讨论，感觉可能是没有找出所有满足约束的解的问题。找全部解的方式如下：
```py
while s.check() == sat:
    m = s.model()
    inp = [m[x[i]].as_long() for i in range(12)]
    out_vals = [m.evaluate(y[i]).as_long() for i in range(30)]
    out_str = ''.join(chr(c) for c in out_vals)
    print("input:", inp)
    print("output:", out_str)
    s.add(Or([x[i] != inp[i] for i in range(12)]))
```
这样就能在正确的数据下得到flag了