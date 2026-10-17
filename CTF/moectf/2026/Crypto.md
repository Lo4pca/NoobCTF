# 西小电银行

```py
from itertools import product
from hashlib import sha256
TAIL = ";risk=low;ok"
def serialize_record(record) -> bytes:
    text = (
        f"bank=XiXiaoDianBank;"
        f"branch={record['branch']};"
        f"serial={record['serial']};"
        f"card={record['card']};"
        f"pin={record['pin']};"
        f"user_id={record['user_id']}"
        f"{TAIL}"
    )
    return text.encode("utf-8")
def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])
record2=
plain=serialize_record(record2)
cipher=bytes.fromhex("")
key=xor(cipher,plain)[16:]
target=bytes.fromhex("")
print(xor(target[:len(key)],key))
user_id=""
salt=b""
for i in product('0123456789abcdef',repeat=4):
    candidate=''.join(i)
    if sha256(salt + b':' + (user_id+candidate).encode()).hexdigest()[:12]=="":
        print(user_id+candidate)
        break
```
（我的pwntools和cryptodome不在一个环境里，所以用了这个笨方法；结果清理完脚本发现不用cryptodome……）

# m1x3d_d1p

```py
from hashlib import shake_256
from operator import xor
p3 = 2^521 - 1
E = EllipticCurve(GF(p3), [1, 0])
order=E.order()
G = E(,)
Q = E(,)
factors=[]
dlogs=[]
#smooth attack
for fac in list(factor(order)):
    fac=pow(fac[0],fac[1])
    factors.append(fac)
    t = order // fac
    dlogs.append((t*Q).log(t*G))
h=crt(dlogs,factors)
assert h*G==Q
n = 
c = 
#二项式展开
if (c-1)%n==0:
    msg=((c-1)//n)%n
else:
    msg=((c+1)//n)%n
p1 = 
g = 4
LOWER = 2^72
WIDTH = 2^50
Fp = IntegerModRing(p1)
#Pollard's kangaroo
x = discrete_log(Fp(h), Fp(g), bounds=(LOWER, LOWER + WIDTH))
def int_to_bytes(value, size):
    return int(value).to_bytes(size, "big")
ct = bytes.fromhex("")
stream = shake_256(int_to_bytes(x, 16) + int_to_bytes(msg,16)).digest(len(ct))
print(bytes(xor(a, b) for a, b in zip(ct, stream)))
```
(ds算的)二项式展开的结果是 $(n-1)^k \equiv (-1)^k + (-1)^{k-1} k \cdot n + (-1)^{k-2} \frac{k(k-1)}{2} n^2 \pmod{n^3}$

# ez_lattice

approximate gcd，简称agcd。特征是有多个类似下面的式子：
- $x_0 = y_0m + z_0$
- $x_1 = y_1m + z_1$
- $x_2 = y_2m + z_2$
- ...

且 $y_1x_0-y_0x_1$ ( $=y_1z_0-y_0z_1$ )相比于 $x_0$ 较小
```py
from Crypto.Util.number import *
cipher=
x0,x1,x2,x3,x4,x5=cipher
L = Matrix([
    [1, x1, x2, x3,x4,x5],
    [0, x0 , 0 , 0,0,0],
    [0, 0 , x0 , 0,0,0],
    [0, 0 , 0 , x0,0,0],
    [0, 0 , 0 , 0,x0,0],
    [0, 0 , 0 , 0,0,x0],
])
m0=L.LLL()[0][0]
e0=x0%m0
M=(x0-e0)//m0
flag=long_to_bytes(m0)
for i in range(1,len(cipher)):
    flag+=long_to_bytes((cipher[i]-(cipher[i]%M))//M)
print(flag)
```
我最开始设置secret为42个a来测试脚本是否可行，结果无论如何都没法跑出答案；倒是换成题目给的cipher后一切顺利。估计是全为a的话存在更小的线性关系

# moePoly2

```py
#我的sagemath环境中没有pwntools
import socket
class Remote():
    def __init__(self,host:str,port:int):
        self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host,port))
    def recvuntil(self,marker:str):
        data = b""
        marker=marker.encode()
        while marker not in data:
            data += self.s.recv(1)
        return data
    def sendline(self,content:str):
        self.s.sendall(content.encode() + b"\n")
    def sendlineafter(self,marker:str,content:str):
        self.recvuntil(marker)
        self.sendline(content)
    def recvline(self):
        return self.recvuntil("\n")
    def recvlines(self,num:int):
        return [self.recvline() for _ in range(num)]
    def close(self):
        self.s.close()
r=Remote("127.0.0.1",64776)
def query(x):
    r.sendlineafter(": ",'1')
    r.sendlineafter(": ",str(x))
    return int(r.recvline())
r.recvuntil("p = ")
p=int(r.recvline())
roots=[]
res=[]
N_EQS=10
for i in range(N_EQS):
    roots.append(random_prime(1<<255))
    res.append(query(roots[-1]))
P = PolynomialRing(ZZ,','.join(f'a{i}' for i in range(31+13)))
coeffs=list(P.gens())
eqs=[]
for i in range(N_EQS):
    eq=0
    for j,coeff in enumerate(coeffs):
        eq+=coeff*roots[i]**j*(1<<248)
    eq-=res[i]
    eqs.append(eq)
A,mons = Sequence(eqs).coefficients_monomials(sparse=False)
L = block_matrix(QQ, [
    [A.T,1],
    [p,0]
])
flag=L.LLL()[0][N_EQS:][:-1]
print(bytes(-i for i in flag))
```
# 墨箓验真

1. 试墨台

因为`hash_with_key`每6个字符会交替符号，在旧帖末尾添上12个相同数字就能互相抵消

2. 折简阁

分析key的符号算式：
```py
b = var('b0 b1 b2 b3 b4 b5')
def is_digit_string(value):
    return isinstance(value, str) and value.isdigit()
def pad_digits(text):    
    if not is_digit_string(text):
        raise ValueError("input must be a non-empty digit string")
    missing = (6 - len(text) % 6) % 6
    for value in range(1, missing + 1):
        text += str(value)
    return text
def symbolic_block_hash(block):
    expr = 0
    for i, ch in enumerate(block):
        d = int(ch)
        expr += (1 - 2*b[i]) * d
    return expr
def symbolic_hash_with_key(text):
    padded = pad_digits(text)
    total = 0
    group_index = 0
    for idx in range(0, len(padded), 6):
        block = padded[idx:idx+6]
        sign = 1 if group_index % 2 == 0 else -1
        total += sign * symbolic_block_hash(block)
        group_index += 1
    return total.expand()
print(symbolic_hash_with_key("124477011547"))
```
如果系数全是正数，那直接把系数输入进去就完事；否则需要利用填充的第二个块进一步凑出负数系数，比如上述脚本的输出是`-2*b0 - 2*b1 - 6*b2 + 2*b3 - 6*b4 + 7`。block_hash的计算公式为 $\sum_{i=0}^{5} (1 - 2b_i) \cdot d_i$ ，展开后得 $(d_0 + d_1 + d_2 + d_3 + d_4 + d_5)-2(b_0 d_0 + b_1 d_1 + b_2 d_2 + b_3 d_3 + b_4 d_4 + b_5 d_5)$ 。需要让两个块的数字和这部分相减得7，key系数部分一一对应

第二个块的后5个字符固定为12345，利用这个信息可以反推第一个块的后5个字符；再利用字符和之差必须为7得出开头的字符。这块ds比我更快反应过来（也许我应该早点把这题给它看的，它的思路比我快还比我清晰……），以下是它的例子：

- 块1 `"125275"`： $22 - 2(b_0 + 2b_1 + 5b_2 + 2b_3 + 7b_4 + 5b_5)$
- 块2 `"012345"`： $15 - 2(b_1 + 2b_2 + 3b_3 + 4b_4 + 5b_5)$

3. 霆纹坛

用脚本生成符号算式后扔给ds就好了……

# moePoly3

```py
#省略Remote类
r=Remote("127.0.0.1",61194)
def query(x):
    r.sendlineafter(": ",'1')
    r.sendlineafter(": ",str(x))
    return int(r.recvline())
res=query(256)
coef = []
for i in range(31):
    coef.append(res % 256)
    res //= 256
r.sendlineafter(": ",str(int(''.join(str(c) for c in coef))))
print(r.recvlines(2))
```
# moeChamp10n

```py
from __future__ import annotations
from hashlib import sha256
from typing import Iterable
a = 16302871846448256339569448006931389858269118713881858000841721100072112275228016532331388554188928492783936143483799084176586471963896405862124526512264974
b = 1097861

iv = bytes.fromhex("ff8e74d7df70b1b968d0d68c")
ct = bytes.fromhex(
    "f358dc96e2977fb91453ff381de25c4990e9436a0114cd77a593d66090f9254381baaf8cfd074683c3"
)
tg = bytes.fromhex("93ba6253a13e87c3174141f40b2cac11")

def local_champions(a, b):
    W = (a + b) // 2
    champions = {
        c
        for u in range(1, b)
        for c in ((a + b) * u - b * W,
                -((a + b) * u - b * W))
    }
    return champions

def derive_key(local_champions: Iterable[int]) -> bytes:
    h = sha256()
    for c in sorted(local_champions):
        h.update(str(c).encode())
        h.update(b"\n")
    return h.digest()

def decrypt_flag(key: bytes) -> bytes:
    from Crypto.Cipher import AES

    e = AES.new(key, AES.MODE_GCM, nonce=iv)
    return e.decrypt_and_verify(ct, tg)

key = derive_key(local_champions(a, b))
flag = decrypt_flag(key)
print(flag.decode())
```
遇到不知道什么考点的题的第一步是扔给ds。它说weight函数是“minimum-L_1 representation”，指在给定一组基（或生成元）和线性约束下，用这些基表示一个元素时，使表示系数的范数（绝对值之和）最小的那组表示。此处省略一堆毫无营养的掰扯，总之ds认为这题和拓展欧几里得算法和连分数有关。前者确实可用在weight的计算上，后者它没解释明白，我也不懂连分数（可能是幻觉，后续chatgpt神没有提到任何关于连分数的内容）

如何计算weight（其实真正解题时完全用不着这个函数）：gcd(a,b)=1，因此任何数c都可以表示成ax+by=c的形式。可以先找到一组特解 $(x_0,y_0)$ ，则所有解形如 $(x_0+bt,y_0-at),t\in Z$ 。绝对值函数在正数轴单调递增，负数轴（往负无穷方向）上也是；所以绝对值最小的表示一定在原点周围。ds没算具体是在什么周围，只给了一个粗略至极的实现（但是能用）：
```py
inv_a_mod_b = pow(a, -1, b)
def weight(c):
    x0 = (c * inv_a_mod_b) % b
    y0 = (c - a * x0) // b

    candidates = set()

    t_y = y0 // a
    for dt in range(-20, 20):
        candidates.add(t_y + dt)

    t_x = -x0 // b
    for dt in range(-20, 20):
        candidates.add(t_x + dt)

    best = None
    for t in candidates:
        x = x0 + b * t
        y = y0 - a * t
        w = abs(x) + abs(y)
        if best is None or w < best:
            best = w
    return best
```
另一点观察是，邻居（指 $c\pm a,c\pm b$ ）的权重与c的权重的差值不会大于1。由此得到如下推断：
```
az+bw=a(x+1)+by
az-ax+bw-by=a
a(z-x)+b(w-y)=a
a+a(z-x-1)+b(w-y)=a
a(z-x-1)+b(w-y)=0
z-x-1=b, w-y=-a
z=b+x+1, w=-a+y
```
根据这玩意，我感觉local champion应该在a和b的中点部分？手动验证了几个，比如`x=-b//2`,`y=a//2`;`x=b//2`,`y=-a//2-1`……勉勉强强凑出了10个，我甚至都不确定为什么，因为指定x和y后得到的数的权重不一定就是指定的x与y之和，具体规律我是一窍不通

ds执着于它的连分数，但我还是不懂。于是我转而求助另一个AI：chatgpt。我把目前得到的内容总结了一遍，开启思考模式后坐等结果

1分18秒后，它给出一串以`moectf`开头的字符串。我下意识认为这又是哪里来的幻觉，但它还给了我hex形式的key。直到本地输出同样的内容后，我才注意到我从来没有告诉过它flag格式是`moectf{}`。wow

接下来是chatgpt神给出的分析

local champion的线性表示的(x,y)一定具有不同的符号。假设x=u > 0, y=-v < 0，则c=au-bv,w(c)=u+v。现在考虑同一个整数c在t=-1下的表示：(u-b,a-v)，权重为|u-b|+|a-v|。因为0 < u < b,0 < v < a（否则存在更小的表示），原式等于(b-u)+(a-v)=a+b-(u+v)。如果(u,-v)是权重最小的表示，必然有 $u+v\leq a+b-(u+v)$ ，即 $u+v\leq\frac{a+b}{2}$

现在我们有了上限，接下来从local champion的条件中推下限。对于c+a，一个特解是c+a=a(u+1)-bv。取t=-1，有(u+1-b,a-v)。类似上面的推演，原式等于(b-u-1)+(a-v)=a+b-(u+v)-1，因此 $w(c+a)\leq a+b-(u+v)-1$ 。local champion需要 $u+v\geq a+b-(u+v)-1$ ,即 $u+v\geq\frac{a+b-1}{2}$

u+v是整数，所以 $u+v=\lfloor\frac{a+b}{2}\rfloor$

# moePoly4

可以用和`moePoly2`一样的方法恢复系数，而恢复出来的系数又组成truncated lcg。我不想思考了，于是直接找了个现成脚本（
```py
r=Remote("127.0.0.1",62001)
def query(x):
    r.sendlineafter(": ",'1')
    r.sendlineafter(": ",str(x))
    return int(r.recvline())
r.recvuntil("a = ")
a=int(r.recvline())
r.recvuntil("b = ")
b=int(r.recvline())
r.recvuntil("p = ")
p=int(r.recvline())
roots=[]
res=[]
N_EQS=20
for i in range(N_EQS):
    roots.append(random_prime(1<<255))
    res.append(query(roots[-1]))
P = PolynomialRing(ZZ,','.join(f'a{i}' for i in range(26)))
coeffs=list(P.gens())
eqs=[]
for i in range(N_EQS):
    eq=0
    for j,coeff in enumerate(coeffs):
        eq+=coeff*roots[i]**j
    eq-=res[i]
    eqs.append(eq)
A,mons = Sequence(eqs).coefficients_monomials(sparse=False)
L = block_matrix(QQ, [
    [A.T,1],
    [p,0]
])
W = 1<<500
ws = diagonal_matrix([W]*N_EQS + [1]*26 + [W], sparse=False)
L*=ws
L=L.LLL()
L/=ws
for i in L:
    if abs(i[-1])==1:
        out=i
        if i[-1]==-1:
            out*=-1
        break
out=out[N_EQS:][:-1]

#https://gist.github.com/maple3142/c7c31d2e5893d524e71eb5e12b0278f0
def get_L(k):
    M = matrix([p])
    A = matrix([a ** i for i in range(1, k)]).T
    I = matrix.identity(k - 1) * -1
    Z = matrix([0] * (k - 1))
    L = block_matrix([[M, Z], [A, I]])
    return L
K = [b]
for i in range(1, len(out)):
    K.append((K[-1] + b * a ** i) % p)
K = vector(K)
L = get_L(len(out))
shifted = [(x * 2 ** 128 - K[i]) % p for i, x in enumerate(out)]
B = L.LLL()
sys = vector(shifted)
sby = B * sys
ks = vector(round(x) for x in sby / p)
zs = B.solve_right(ks * p - sby)
tmp = sys + zs
results = [(tmp[i] + K[i]) % p for i in range(len(tmp))]
assert (L * vector(results)) % p == (L * K) % p  # Extra checking
seed=((results[0]-b)*inverse_mod(a,p))%p
r.sendlineafter(": ",str(seed))
print(r.recvlines(2))
```
# JK_R0LL1ng

```py
from z3 import *

R1_SIZE = 17
R2_SIZE = 19
R3_SIZE = 16

R1_MASK = 0x12000
R2_MASK = 0x72000
R3_MASK = 0xB400

def parity(x, mask):
    """Return a 1-bit BitVec equal to the XOR of bits of x where mask has 1."""
    res = None
    for i in range(mask.bit_length()):
        if (mask >> i) & 1:
            bit = Extract(i, i, x)
            res = bit if res is None else res ^ bit
    return res if res is not None else BitVecVal(0, 1)

R1_var = BitVec('R1', R1_SIZE)
R2_var = BitVec('R2', R2_SIZE)
R3_var = BitVec('R3', R3_SIZE)

s = Solver()

s.add(R1_var >= 1 << (R1_SIZE - 1))
s.add(R1_var < 1 << R1_SIZE)
s.add(R2_var >= 1 << (R2_SIZE - 1))
s.add(R2_var < 1 << R2_SIZE)
s.add(R3_var >= 1 << (R3_SIZE - 1))
s.add(R3_var < 1 << R3_SIZE)

R1, R2, R3 = R1_var, R2_var, R3_var
q = BitVecVal(1, 1)

with open("output.txt", "r") as f:
    hexstr = f.read().strip()
out_bytes = bytes.fromhex(hexstr)
assert len(out_bytes) == 128

for byte_idx in range(128):
    b = BitVecVal(0, 8)
    for _ in range(8):
        # --- LFSR 1 ---
        j = parity(R1, R1_MASK)
        R1 = (R1 << 1) | ZeroExt(R1_SIZE - 1, j)

        # --- LFSR 2 ---
        k = parity(R2, R2_MASK)
        R2 = (R2 << 1) | ZeroExt(R2_SIZE - 1, k)

        # --- LFSR 3 ---
        x = parity(R3, R3_MASK)
        R3 = (R3 << 1) | ZeroExt(R3_SIZE - 1, x)

        # --- JK flip‑flop ---
        q = If(j == 0,
               If(k == 0, q, BitVecVal(0, 1)),
               If(k == 0, BitVecVal(1, 1), q ^ BitVecVal(1, 1)))

        # --- Output bit ---
        b = (b << 1) | ZeroExt(7, q ^ x)

    s.add(b == out_bytes[byte_idx])

if s.check() == sat:
    m = s.model()
    r1 = m[R1_var].as_long()
    r2 = m[R2_var].as_long()
    r3 = m[R3_var].as_long()

    key = f"{r1:05x}{r2:05x}{r3:04x}"
    print("[+] Found key:", key)
    print("[+] Flag: moectf{" + key + "}")
else:
    print("[-] No solution found.")
```
三个lfsr让我想起了Cryptohack的`Jeff's LFSR`，那题有人用z3直接秒了。所以我就叫ds把题目改成z3脚本，真的秒了……