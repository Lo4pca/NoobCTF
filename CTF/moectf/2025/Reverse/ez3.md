# ez3

AI和它没用的脚本小子（

```py
#谢谢你deepseek
from z3 import *
def convert_little_endian(byte_sequence):
    bytes_list = byte_sequence.split()
    values = []
    for i in range(0, len(bytes_list), 4):
        if i + 3 < len(bytes_list):
            byte0 = int(bytes_list[i], 16)
            byte1 = int(bytes_list[i+1], 16)
            byte2 = int(bytes_list[i+2], 16)
            byte3 = int(bytes_list[i+3], 16)
            value = (byte3 << 24) | (byte2 << 16) | (byte1 << 8) | byte0
            values.append(value)
    return values
def solve_flag():
    a=convert_little_endian("b0 b1 00 00 78 56 00 00 f2 7f 00 00 32 a3 00 00 e8 a0 00 00 4c 36 00 00 d4 2b 00 00 fe c8 00 00 7c 4a 00 00 18 00 00 00 e4 2b 00 00 44 41 00 00 a6 3b 00 00 8c be 00 00 7e 8f 00 00 f8 35 00 00 aa 61 00 00 4a 2b 00 00 28 68 00 00 9e b3 00 00 42 b5 00 00 ec 33 00 00 d8 c7 00 00 8c 44 00 00 10 93 00 00 08 88 00 00 d4 ad 00 00 c2 3c 00 00 96 07 00 00 40 c9 00 00 32 4e 00 00 2e 4e 00 00 4a 92 00 00 5c 5b 00 00")
    s = Solver()
    flag_chars = [BitVec(f'char_{i}', 8) for i in range(34)]
    for char in flag_chars:
        s.add(And(char >= 32, char <= 126))
    b = [None] * 34
    for idx in range(34):
        temp = (ZeroExt(24, flag_chars[idx]) + idx) * 0xBABE
        if idx != 0:
            temp = temp ^ b[idx-1] ^ 0x114514
        b_val = temp % 0xCAFE
        b[idx] = b_val
        s.add(b_val == a[idx])
    solutions = []
    while s.check() == sat:
        model = s.model()
        current_solution = ''.join([chr(model[char].as_long()) for char in flag_chars])
        solutions.append(current_solution)
        exclude_constraint = Or([flag_chars[i] != model[flag_chars[i]] for i in range(34)])
        s.add(exclude_constraint)
    print(f"\n共找到 {len(solutions)} 个解:")
    for i, solution in enumerate(solutions, 1):
        print(f"{i:3d}: {solution}")
solve_flag()
```

`temp % 0xCAFE`这段逻辑在汇编里比较复杂（0x0040488e开始），因为汇编里没有现成的模指令。由于c++的反编译结果比较烦人，我便尝试用python重写题目的逻辑来验证我的猜测，但发现不行，原因就在这个模运算。两者对模运算的定义不同。python总是返回非负结果，而汇编遵循数学定义，结果符号与被除数相同。加上汇编自己会生成关于模的优化算法以及内存表示等乱七八糟的问题，两者的结果可能大相径庭。不过这个问题z3里没有，可能BitVec对模的定义与汇编相同？