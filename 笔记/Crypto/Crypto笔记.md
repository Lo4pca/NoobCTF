# Crypto笔记

此篇笔记对应的gist： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101 。题目对应的关键词将加粗

## RSA
- 得到d和c，p和q为相邻质数。例题：[[NCTF2019]babyRSA](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Crypto/%5BNCTF2019%5DbabyRSA.md)
- 光滑数分解+威尔逊定理使用。例题1：[smooth](../../CTF/moectf/2022/Crypto/smooth.md)，例题2:[[RoarCTF2019]babyRSA](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Crypto/%5BRoarCTF2019%5DbabyRSA.md)
- 共模攻击。适用于相同明文用同样的n却用不同的e加密时。注意两个不同的e需要互质。[例题1](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C/3%E7%BA%A7/Crypto/best_rsa.md)搭配使用Crypto库读取公钥，[例题2](https://blog.csdn.net/weixin_44017838/article/details/104886290)搭配解密结果是ascii的情况。

```python
from Crypto.Util.number import *
from gmpy2 import invert
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
def decrypt(e1,e2,n,c1,c2):
    _,s1,s2=egcd(e1,e2)
    if s1<0:
        s1 = -s1
        c1 = invert(c1, n)
    elif s2<0:
        s2 = -s2
        c2 = invert(c2, n)
    m = pow(c1,s1,n)*pow(c2,s2,n) % n
    return long_to_bytes(m)
n=0
c1=0
c2=0
print(decrypt(1697,599,n,c1,c2).decode())
```

- lcm问题+e与phi不互质（gcd较小）。例题：[[NPUCTF2020]EzRSA](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Crypto/%5BNPUCTF2020%5DEzRSA.md)
- dp泄露。例题：[0rsa0](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/moectf/Crypto/0rsa0.md)
- sagemath解二元方程组+e，d泄露后分解n。例题:[[MRCTF2020]Easy_RSA](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Crypto/%5BMRCTF2020%5DEasy_RSA.md)
```py
P_n = 
P_F_n =
var("p q")
eq1=P_n==p*q
eq2=P_F_n==(p-1)*(q-1)
solve([eq1,eq2],p,q)
```
- rsa衍生算法：[Rabin](https://co5mos.github.io/2018/09/14/rsa-rabin/)。[原理](https://zhuanlan.zhihu.com/p/533927542)及脚本：

```python
import libnum

p = 49123
q = 10663
c = 162853095
n = p*q
c_p = pow(c,(p+1)//4,p)
c_q = pow(c,(q+1)//4,q)
a = libnum.invmod(p,q)
b = libnum.invmod(q,p)
x = (b*q*c_p+a*p*c_q)%n
y = (b*q*c_p-a*p*c_q)%n

print(bin(x%n))
print(bin((-x)%n))
print(bin(y%n))
print(bin((-y)%n))
```

rabin算法可以解出来4个明文，一般末尾会有类似校验码的东西，帮助分辨哪个是真正的明文。[来源](https://www.jianshu.com/p/00a35ebd36fb)。
- 当模数n过大， $m^e$ 次方没有n大时，就可以直接对c开e次方。例题:[[INSHack2017]rsa16m](https://blog.csdn.net/zippo1234/article/details/109268561)。
- e和phi不互素+中国剩余定理解决多组c和n问题。例题1:[Weird_E_Revenge](../../CTF/moectf/2022/Crypto/Weird_E_Revenge.md)。例题2:[[De1CTF2019]babyrsa](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Crypto/%5BDe1CTF2019%5Dbabyrsa.md)。[simpleRSA](https://blog.csdn.net/weixin_52640415/article/details/127817186)
  - 如果给出两组n，c和e，且两组数据的phi和e gcd一致，解法与Weird_E_Revenge大致相同。
```python
from Crypto.Util.number import *
import gmpy2
from sympy.ntheory.modular import crt
e1 = 0
p1 = 0
q1 = 0
c1 = 0
n1 = p1 * q1
e2 = 0
p2 = 0
q2 = 0
c2 = 0
n2 = p2 * q2
p = p1
phi1 = (p - 1) * (q1 - 1)
phi2 = (p - 1) * (q2 - 1)
b = gmpy2.gcd(e1, phi1)
a1 = e1 // b
a2 = e2 // b
bd1 = gmpy2.invert(a1, phi1)
bd2 = gmpy2.invert(a2, phi2)
mb1 = pow(c1, bd1, n1)
mb2 = pow(c2, bd2, n2)
c3 = mb1 * mb2 % p
c2 = mb2 % q2
c1 = mb1 % q1
res = crt([q1, q2, p],[c1, c2, c3])[0]
n = q1 * q2
f = (q1 - 1) * (q2 - 1)
m = res % n
d2 = gmpy2.invert(7, f)
m = pow(m, d2, n)
msg = gmpy2.iroot(m, 2)[0]
print(long_to_bytes(msg).decode())
```
- e非常大，相应的d就会很小。低解密指数攻击（wiener attack）。例题:[[羊城杯 2020]RRRRRRRSA](../../CTF/BUUCTF/Crypto/[羊城杯%202020]RRRRRRRSA.md)
```python
import gmpy2
from Crypto.Util.number import long_to_bytes
def continuedFra(x, y):
    cF = []
    while y:
        cF += [x // y]
        x, y = y, x % y
    return cF
def Simplify(ctnf):
    numerator = 0
    denominator = 1
    for x in ctnf[::-1]:
        numerator, denominator = denominator, x * denominator + numerator
    return (numerator, denominator)
def calculateFrac(x, y):
    cF = continuedFra(x, y)
    cF = list(map(Simplify, (cF[0:i] for i in range(1, len(cF)))))
    return cF
def solve_pq(a, b, c):
    par = gmpy2.isqrt(b * b - 4 * a * c)
    return (-b + par) // (2 * a), (-b - par) // (2 * a)
def wienerAttack(e, n):
    for (d, k) in calculateFrac(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        p, q = solve_pq(1, n - phi + 1, n)
        if p * q == n:
            return abs(int(p)), abs(int(q))
    print('[!]not found!')
e = 0
n = 0
c = 0
p, q = wienerAttack(e, n)
print('[+]Found!')
print('[-]p =', p)
print('[-]q =', q)
d = gmpy2.invert(e, (p-1)*(q-1))
flag = long_to_bytes(pow(c,d,n))
print (flag)
```
- 多项式下的RSA(PolynomialRing)。例题:[[watevrCTF 2019]Swedish RSA](../../CTF/BUUCTF/Crypto/[watevrCTF%202019]Swedish%20RSA.md)
- e与phi不互质且gcd很大，使用AMM开根法+CRT。例题:[[NCTF2019]easyRSA](https://blog.soreatu.com/posts/intended-solution-to-crypto-problems-in-nctf-2019/#easyrsa909pt-2solvers)。附AMM算法（sagemath）：

```python
import time
import random
def AMM(o, r, q):
    start = time.time()
    print('\n----------------------------------------------------------------------------------')
    print('Start to run Adleman-Manders-Miller Root Extraction Method')
    print('Try to find one {:#x}th root of {} modulo {}'.format(r, o, q))
    g = GF(q)
    o = g(o)
    p = g(random.randint(1, q))
    while p ^ ((q-1) // r) == 1:
        p = g(random.randint(1, q))
    print('[+] Find p:{}'.format(p))
    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s = s // r
    print('[+] Find s:{}, t:{}'.format(s, t))
    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alp = (k * s + 1) // r
    print('[+] Find alp:{}'.format(alp))
    a = p ^ (r**(t-1) * s)
    b = o ^ (r*alp - 1)
    c = p ^ s
    h = 1
    for i in range(1, t):
        d = b ^ (r^(t-1-i))
        if d == 1:
            j = 0
        else:
            print('[+] Calculating DLP...')
            j = - discrete_log(d, a)
            print('[+] Finish DLP...')
        b = b * (c^r)^j
        h = h * c^j
        c = c^r
    result = o^alp * h
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    print('Find one solution: {}'.format(result))
    return result
```

- p和q相邻或接近，使用费马分解法。

```python
import gmpy2
def Fermat(num):
    x = gmpy2.iroot(num,2)[0]
    if x*x < num:
        x += 1
    while(True):
        y2 = x*x - num
        y = gmpy2.iroot(y2,2)[0]
        if y*y == y2:
            break
        x += 1
    return [x+y, x-y]
```

- 低加密指数（e为3等较小数）攻击。

```python
from Crypto.Util.number import *
from gmpy2 import iroot
def smallEattack(c, e, n):
    for i in range(10 ** 10):
        res = iroot(n * i + c, e)
        if res[1]:
            print(long_to_bytes(res[0]))
            break
```

- Franklin-Reiter相关信息攻击巧解给出d，phi密文，m非常大，e很小的题目。例题:[d-phi-enc](../../CTF/HackTM%20CTF/Crypto/d-phi-enc.md)
- 获得d和n后可用Cryptodome库获取p和q。

```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from pwn import xor
n = 0
e = 65537
d = 0
ciphertext =
p = RSA.construct((n, e, d)).p
q = n//p
key = xor(long_to_bytes(p), long_to_bytes(q)) #pwn的xor函数无需两个字符串相同长度
plaintext = xor(bytes.fromhex(ciphertext), key).decode()
print(plaintext)
```

- 根据d和e构造出n:[Calculating RSA Public Modulus from Private Exponent and Public Exponent](https://crypto.stackexchange.com/questions/81615/calculating-rsa-public-modulus-from-private-exponent-and-public-exponent)。更详细的方法：https://stackoverflow.com/questions/2921406/calculate-primes-p-and-q-from-private-exponent-d-public-exponent-e-and-the
- [已知d分解n](https://crypto.stackexchange.com/questions/6361/is-sharing-the-modulus-for-multiple-rsa-key-pairs-secure)。
```python
import random
import math
from Crypto.Util.number import long_to_bytes
c = 0
n = 0
d = 0
e = 0x10001
def remove_even(n):
    if n == 0:
        return (0, 0)
    r = n
    t = 0
    while (r & 1) == 0:
        t = t + 1
        r = r >> 1
    return (r, t)
def get_root_one(x, k, N):
    (r, t) = remove_even(k)
    oldi = None
    i = pow(x, r, N)
    while i != 1:
        oldi = i
        i = (i*i) % N
    if oldi == N-1:
        return None 
    return oldi
def factor_rsa(e, d, N):
    k = e*d - 1
    y = None
    while not y:
        x = random.randrange(2, N)
        y = get_root_one(x, k, N)
    p = math.gcd(y-1, N)
    q = N // p
    return (p, q)
p, q = factor_rsa(e, d, n)
print(p, q)
assert p * q == n
m = pow(c, d, n)
flag = p - m
print(long_to_bytes(flag))
```
已知phi分解n也是这个考点。本身已知e和d分解n就是为了凑phi的倍数，现在如果有phi直接分解即可。[factorize_me!](../../CTF/moectf/2023/Crypto/factorize_me!.md)。更好的脚本（给定n和phi直接返回n的全部因子，无论n是多少个质数的乘积）： https://github.com/XDSEC/MoeCTF_2023/blob/main/WriteUps/Orac1e/Crypto_Writeup.md#factorize_me

- p高位泄露（coppersmith），可直接根据泄露的高位p，n和e求出p。需使用sagemath运行。

```python
n = 0
p4=0 #泄露的高位
e = 0x10001
pbits = 1024 #完整p的位数
kbits = 128 #要爆破（求解）的位数（不是已泄露的位数，为pbits-已泄露位数）
PR.<x> = PolynomialRing(Zmod(n))
f = x + p4
roots = f.small_roots(X=2^kbits, beta=0.4)
if roots:        
    p = p4+int(roots[0])
    print ("n=", n)   
    print ("p=", p)
    print ("q=", n/p)
```

coppersmith算法的作用是求解根较小的同余式方程。已知p高位攻击其实是求这么一个方程的根： $p_{high}+x=0\mod p$ 。特殊地，如果大小得当，可以在不知道模只知道模的倍数前提下，求解方程。即解 $p_{high}+x=0\mod n$ 。
- coppersmith(m高位泄露,已知明文高位)。假设加密了消息 m，如下：

$C\equiv m^e\mod N$

并且我们假设我们知道消息 m的很大的一部分 m0，即 m=m0+x，但是我们不知道 x。那么我们就有可能通过coppersmith恢复消息。这里我们不知道的 x其实就是多项式的根，需要满足 Coppersmith 的约束。当 e足够小，且部分明文泄露时，可以采用Coppersmith单变量模等式的攻击，如下：

$c=m^e\mod n=(mbar+x_0)^e\mod n$

其中 mbar=(m>>kbits)<<kbits
```python
def phase2(high_m, n, c):
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    m = high_m + x
    M = m((m^3 - c).small_roots()[0])
    print(hex(int(M))[2:])

n = 
c = 
high_m = 

phase2(high_m, n, c)
```
```py
c = 
n = 
e = 
K.<x> = PolynomialRing(Zmod(n))
secret_len =  #原m的长度,有时候需要猜测
known_high = #已知的m高位
polynomial = (x + 2^(secret_len)*(known_high))^e - c
polynomial = polynomial.monic()
roots = polynomial.small_roots(X=2^secret_len)
print(roots)
```
有时候可以尝试用`\x00`尝试提高已知明文，然后用small_roots开根。[Small Inscription](https://born2scan.run/writeups/2023/06/02/DanteCTF.html#small-inscription)。这题的e是3，flag长度小于30。方程确实是我理解的那个方程，就是补`\x00`才能解出来可能是因为这样small_root要求的根相对比较小，而且不会影响出来的结果。
```py
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
ct=
N=
R.<x> = PolynomialRing(Zmod(N))
prefix=b'' #已知的明文部分
for i in range(30):
    m1 = bytes_to_long(prefix+b'\x00'*i)
    poly= (m1+x)**3 - ct
    root=poly.small_roots()
    if root:
        print(long_to_bytes(m1+int(root[0])))
```
- coppersmith's short-pad attack& Related Message Attack(Franklin-Reiter，相关信息攻击)
```python
import binascii
def attack(c1, c2 e):
    PR.<x>=PolynomialRing(Zmod(n))
    a=
    b=
    c=
    d=
    g1 = (a*x+b)^e - c1
    g2 = (c*x+d)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()
    return -gcd(g1, g2)[0]
c1 =
c2 =
e =
m1 = attack(c1, c2 e)
print(binascii.unhexlify("%x" % int(m1)))
```
相关信息攻击的关键点在于找出两条信息具有线性关系的方程。通常方程形如 $((a\*m)+b)^e\mod n$ 和 $((c\*m)+d)^e\mod n$ ，也是脚本中需要自己填写的a，b，c和d值的由来。[unusualrsa2](https://4xwi11.github.io/posts/80806ae5/#unusualrsa2)。另外今天又发现个不错的例题+解析：[Twin](https://github.com/Warriii/CTF-Writeups/blob/main/akasec/crypto_twin.md)
- 给出p+q（(p-2)(q-2)一个作用）和n时，构造多项式即可获取p或q。

$f(x)=(x-p)(x-q)$<br>
$f(x)=x^2-(p+q)x+pq$<br>
$f(x)=x^2-(p+q)x+n$<Br>
$p,q=\frac{s\pm\sqrt{s^2-4n}}{2}$

```python
from gmpy2 import isqrt
from Crypto.Util.number import long_to_bytes
n=0
s = 0 #s为p+q
c=0
discrim = s**2 - 4*n
assert isqrt(discrim)
test = int(isqrt(discrim))
test_p = (s + test) // 2
if n % test_p != 0:
    test_p = (s - test) // 2
p = test_p
q = n // p
assert p * q == n
e = 0x10001
l = (p-1)*(q-1)
d = pow(e, -1, l)
m = pow(c, d, n)
print(long_to_bytes(m))
```
- rsa要求明文不能大于n。如果明文大于n了，解密的结果是m-k\*n。此时要么按照正常方式求出m后不断加上n的倍数尝试爆破，要么尝试获取多组密文解密后用crt还原完整明文。例题:[Search-3](https://hackmd.io/9_WE-HinSYqFQyKubluRuw?view#Search-3---470---Hard)
  - 爆破做法也是有技巧的，参考[rsa-is-broken](https://github.com/BCACTF/bcactf-4.0/tree/main/rsa-is-broken).大部分flag的结尾均为`}`,那么flag模256一定为125(`ord('}')`)。那么可以从模256=125的m出发开始爆破，每次加上n*256而不是1。至于为什么是256，个人猜测是因为0-255代表了所有可能的字符。同一道题还有以下脚本:
  ```py
    from Crypto.Util.number import *
    import math
  
    # Given
    p = 892582974910679288224965877067
    q = 809674535888980601722190167357
    n = p * q
    e = 65537
    d = pow(e, -1, math.lcm(p-1, q-1))
    c = 36750775360709769054416477187492778112181529855266342655304
    newm = pow(c, d, n)
  
    flag_len = 35   # Figured out experimentally lol
  
    minimum_byte_string = b'bcactf{' + b',' * (flag_len - 6)
  
    multiple = bytes_to_long(minimum_byte_string) // n              # Minimum multiple of N added to get `bcactf{`
    while (newm + n * multiple) & 0xFF != ord("}"): multiple += 1      # Increment until it will end with `}`
  
    start = multiple    # Minimum multiple of N starting with `bcactf{` and ending with `}`
    end = 2 ** 100      # Really big number that doesn't matter
    step = 256          # 256 is coprime to N, so v + i * N (mod 256) has a period of 256


    for i in range(start, end, 256):
        # Test byte string
        byte_str = long_to_bytes(newm + n * i)
    
        # Stop once we're past the `bcactf{` part
        if not byte_str.startswith(b'bcactf{'):
            break
    
        # If the whole byte string is in-flag-range ASCII, print and exit
        if all(0x2C < byte < 0x7f for byte in byte_str):
            print(byte_str)
            break
    ```   
- 基于多项式的RSA。在有限域上选取两个不可约多项式 g(p),g(q)，g(n)=g(p)⋅g(q)。计算出 g(n)的欧拉函数 φ(g(n))=φ。再选取一个整数 e作为公钥，e与 φ是互素的，那么对于明文 g(m)，加密过程为 $g(m)^e$ ≡g(c)(mod g(n))。解密则计算私钥 d满足 ed≡1(mod φ)，则 $g(c)^d$ ≡ $(g(m)^e)^d$ ≡ $g(m)^{ed}$ ≡ $g(m)^{φ+1}$ (mod g(n))。同样考虑 g(n)与 g(m)互素，欧拉定理对于多项式亦成立。得到 $g(m)^{φ+1}$ ≡g(m)(mod g(n))，所以 $g(c)^d$ ≡g(m)(mod g(n))。即整数上的rsa可以推广到多项式上。对于不可约多项式 g(x)，φ(g(x))= $p^n−1$ 。p为 GF(p)的模，n为该多项式最高项次数。[unusualrsa3](https://lazzzaro.github.io/2020/09/01/other-CTFshow%E4%BE%9B%E9%A2%98-unusualrsa%E7%B3%BB%E5%88%97/index.html#unusualrsa3)
```python
#sage
p = 
R.<x> = PolynomialRing(GF(p))
N = 
S.<x> = R.quotient(N)
c = 
P, Q = N.factor() #尝试直接分解出p和q
P, Q = P[0], Q[0]
phi = (p**P.degree()-1)*(p**Q.degree()-1)
e = 0x10001
d = inverse_mod(e, phi)
m = c^d
m = "".join([chr(c) for c in m.list()])
print(m)
```
补充一篇多项式RSA的[论文](https://www.whdl.org/sites/default/files/resource/academic/Freed-RSA%2520Encryption%2520Using%2520Polynomial%2520Rings-HP.pdf) 
- 程序允许输入任意数字（除了程序使用的e），跟phi计算模逆后返回。此时有下面几种方法恢复明文：
  - 输入程序使用的e的负数：-e。程序返回的结果直接就是-d，加个符号转为d就能直接解密
  - 发送-1，这样程序返回的就是phi-1。加上1得到真正的phi即可解密
  - 使用公式:`phi = (e * d - 1) // gcd(e - 1, d - 1)`
  - 向程序发送多个e，获取多个d。让 $x_i=d_i\*e_i$ ,那么对于每个 $x_i$ ,有某个k满足 $x_i\equiv 1\mod phi\Leftrightarrow x-1\equiv phi\*k$ 。于是取所有 $x_i-1$ 的gcd可能得到phi。注意不是每一次都一定成功。
  - 另外提一点，似乎利用phi的倍数求出的d不会影响解密。
- 低加密指数广播攻击（[Hastad's broadcast attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad's_broadcast_attack)）使用相同的e加密相同的m至少e次，即可用CRT还原 $m^e$ 。攻击者可以通过开e次方获取m。这种攻击方式下的e很小，例如3.
```py
from sympy.ntheory.modular import crt
from gmpy2 import iroot
e=3
n1=
n2=
n3=
c1=
c2=
c3=
flag_cubed=crt([n1,n2,n3],[c1,c2,c3])[0]
flag=iroot(flag_cubed,3)
print(bytes.fromhex(hex(flag[0])[2:]))
```
- [unusualrsa4](https://lazzzaro.github.io/2020/09/01/other-CTFshow%E4%BE%9B%E9%A2%98-unusualrsa%E7%B3%BB%E5%88%97/index.html#unusualrsa4).已知q对p的模逆元(`inverse(q,p)`)，d，c和e，求m。
```py
from Crypto.Util.number import *
inv=
d=
c=
e=65537
for i in range(1,e):
    kphi=e*d-1
    if kphi%i==0:
        phi=kphi//i
        x=1+inv*phi-inv
        mod1=pow(3,phi,x)-1
        mod2=pow(5,phi,x)-1
        p=GCD(mod1,mod2)
        if p.bit_length()==1024:
            q=inverse(inv,p)
            print(long_to_bytes(pow(c,d,p*q)))
            break
```
- [superstitious](https://github.com/BCACTF/bcactf-4.0/tree/main/superstitious):分解特殊的n。若 $n=pq=(a^m+r_p)(b^m+r_q)$ ，则有更快速的方式分解n。参考论文： https://einspem.upm.edu.my/journal/fullpaper/vol13saugust/8.pdf ，具体实现方式在第7页。
- [Boneh-Durfee Attack](https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/boneh-durfee-attack):当d < $N^{0.292}$ 时，可利用该攻击方法恢复d
- [Sus](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Sus):分解n=p\*q\*r,其中 $q=p^2+p+1$
- [Wasteful](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Wasteful):给出`sz=2048;e_fast = getPrime(sz // 2);e_slow = e_fast + getPrime(sz // 3) * phi`,和2048位的公钥n，利用coppersmith获取p
- [S_H](https://sovietbeast-writeups.gitbook.io/writeups/ctfs/fetch-the-flag-2023/cryptography/s_h)
    - 尝试恢复部分被遮挡的SSH RSA private key。主要是要了解rsa private key的格式，确认没被遮挡的部分属于密钥的哪一部分。比如这题没被遮挡的部分为部分dq，完整dp和完整q。所以这题其实是“利用dp和e恢复p”
- [Missing Bits](https://meashiri.github.io/ctf-writeups/posts/202311-glacierctf/#missing-bits)
    - ASN.1 DER格式私钥分析： https://www.cem.me/20141221-cert-binaries.html 。注意符合这个题目的私钥有`-----END RSA PRIVATE KEY-----`字样，为`PKCS#1` encoded key
- [ARISAI](https://github.com/4n86rakam1/writeup/tree/main/GlacierCTF_2023/intro/ARISAI)
    - 多素数rsa+利用crt加快解密过程
- [Mayday Mayday](https://hackmd.io/@Giapppp/rJrKDLm8a),[官方wp](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/crypto/%5BMedium%5D%20Mayday%20Mayday)
    - dp和dq均泄露一部分后（MSB）分解n。LSB的题型见[grhkm's babyrsa](https://gist.github.com/maple3142/96b790553050b6bed5571694c2e764c0)
- [N-less RSA](https://github.com/rixinsc/ctf-writeups/blob/master/wgmy2023.md#n-less-rsa)
    - 已知phi，e和c，获取m
- [easy-rsa](https://github.com/C0d3-Bre4k3rs/PingCTF2023-writeups/tree/main/easy-rsa)
    - 获知`q&p`和`q&(p<<1)`后分解n。或者说，在得知p和q的随机个bit后尝试恢复p和q：[Random known bits of p and q](https://eprint.iacr.org/2020/1506.pdf#page=23)。这题Z3可解
    - 又遇到了类似考点的题：[Shibs](https://kanzya.github.io/posts/MAPNACTF/)。这题wp作者用了多线程（python multiprocessing）配合z3。个人做这道题时倒是用了easy-rsa里的方法: **Shibs** 。我发现这种类型的题只需要找到题目里p和q的bit之间的关系,结合backtrack的思想即可解出。p和q之间的关系用于backtrack设置bit及检查是否返回的条件。注意backtrack设置完bit并递归完后一定要取消刚才设置的bit
- [L4ugh](https://berliangabriel.github.io/post/0xl4ugh-ctf-2024/)
    - 利用LLL实现[Common Private Exponent](https://www.ijcsi.org/papers/IJCSI-9-2-1-311-314.pdf)攻击。特征为多组公钥共享一个私钥。这种攻击比较简短的解释： https://connor-mccartney.github.io/cryptography/rsa/L4ugh-0xl4ughCTF-2024
    - AES翻转bit攻击（控制iv）
- [Baby RSA](https://writeup.gldanoob.dev/bitsctf/)
    - 矩阵上的RSA。参考 https://www.gcsu.edu/sites/files/page-assets/node-808/attachments/pangia.pdf 第9页的3.3案例
- [daisy_bell](https://tanglee.top/2024/02/27/bi0sCTF-2024-Crypto-Writeups/)
    - coppersmith for RSA partial key leakag。不过这题有点不一样，泄露了部分p的高位（但是不够直接恢复p）；又泄露了 $q^{-1}\mod p$ 的部分低位。可能一个关键点在于，可以通过p的高位和n提取出q的部分高位。然后就能变形方程扔给[coppersmith脚本](https://github.com/kionactf/coppersmith)解了(这里还有个点，就是最后构造出来的方程居然有两个变量。我一直以为只能有一个变量，其实multivariate-coppersmith脚本可以处理两个变量的情况)
- [Katyusha’s Campervan](https://tanglee.top/2024/02/27/bi0sCTF-2024-Crypto-Writeups/)
    - 也是一道RSA partial key leak+multivariate-coppersmith的题目。不过这题泄露的是dp的低位（ $dp\mod 2^{892}$ ，比赛的时候压根没看出来是泄露低位……看见题还没分析就觉得太难，直接跑了）
    - 在分解n后，还需要利用binomial_dlog在合数n上求离散对数（实现参考同wp里的rr题）
    - 和这题与上一题相关的论文:[Some Applications of Lattice Based Root Finding Techniques](https://eprint.iacr.org/2010/146),[New Results for Partial Key Exposure on RSA with Exponent Blinding](https://www.scitepress.org/papers/2015/55717/55717.pdf)
- [rsa_oracle](https://github.com/PetePriority/picoctf-2024/tree/main/cryptography/rsa_oracle)
    - chosen plaintext/ciphertext attack。这题是个rsa oracle，允许加密和解密除flag外的明文/密文。wp作者参考了 https://crypto.stackexchange.com/questions/2323/how-does-a-chosen-plaintext-attack-on-rsa-work/2331#2331 ，个人写的时候参考了 https://ctf-wiki.mahaloz.re/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/
    - 脚本：**rsa_oracle**
- [ComplexProblem](https://github.com/acmucsd/sdctf-2024/tree/main/crypto/complex-problem)
    - 复数上的RSA。比赛时搜了好久"RSA over complex numbers"或者各种RSA+complex numbers的组合，但搜不出来。换个说法"rsa with gaussian primes"就出来了。 https://digitalcommons.njit.edu/cgi/viewcontent.cgi?article=1332&context=dissertations 135页（论文118页）。部分简单的复数可以在sagemath里分解。个人解法和官方解法稍微有点不一样，故记录一下（虽然本质是一样的）: **complexproblem**
- [RSAn’t](https://github.com/L3AK-TEAM/L3akCTF-2024-public/tree/main/crypto/RSAn%E2%80%99t)
    - 当同一个公钥加密两条明文时，可通过两组明文和密文求出n
    - 已知p或q高位的coppersmith。以后遇见题目里奇怪的生成质数方式时一定要用代数乘出来看看结果，不然根本看不出来一些特殊的关系
- [Rivest, Shamir, Adleman 1](https://bytethecookies.github.io/writeups/ironctf2024/rivest_shamir_adleman_1)
    - 一个经典的coppersmith p高位泄漏。不过这题到最后发现e和phi不互质。和之前我见过的情形不太一样，这题在分解n后尝试计算所有可能的密文。见 https://medium.com/@g2f1/bad-rsa-keys-3157bc57528e
- [RSA_revenge](../../CTF/moectf/2024/Crypto/RSA_revenge.md)
    - 分解互为emirp（反素数）的两个质数的乘积。注意数字的进制不重要。无论在二进制，十进制，还是十六进制下互为反素数都能尝试分解
- [kRSA](https://github.com/rerrorctf/writeups/blob/main/2024_11_15_1337UP24/crypto/krsa)
    - 假如用rsa加密一个数字k，攻击者可以尝试找满足ij=k的i和j，然后利用rsa的同态特性进行meet in the middle攻击
- [small eqs](https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#small-eqs)
    - [Williams's p + 1 algorithm](https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm)分解n。概率算法，不是百分之百成功。而且这题的p的构造有漏洞，构成p的多项式中包含一个很小的质数
- [fastcrypto](https://blog.whale-tw.com/2025/01/27/x3ctf-2025)
    - NTT算法+CRT加速RSA计算。NTT其实不负责整数乘法，而是模某个数下的多项式乘法。因此题目需要将整数转为多项式，拿到NTT结果后再从多项式转回整数。问题在于题目选择模的“某个数”太小了，而题目编写的多项式转换公式都基于系数不超过模数的前提。NTT返回的结果完全有可能超过这个限制，故出现计算错误。计算错误又会导致RSA中的fault attack，导致攻击者可以用gcd恢复p和q中的一个
    - [官方wp](https://github.com/x3ctf/challenges-2025/blob/main/crypto/fastcrypto)也不错
- [much-vulnerable-machine-3](https://github.com/x3ctf/challenges-2025/tree/main/crypto/much-vulnerable-machine-3)
    - bleichenbacher may攻击，参考论文[New Attacks on RSA with Small Secret CRT-Exponents](https://www.iacr.org/archive/pkc2006/39580001/39580001.pdf)，适用于dp/dq过小的情况

## Sagemath

感觉了解sagemath的api很重要啊，那今天就专门开个部分用于记录例题和使用的函数

sympy也放这了

- https://github.com/Neobeo/CrewCTF2023/blob/main/crypto_writeups.ipynb
    - 实数域上的rsa。这里的p，q等数可能是分数
    - [factor_trial_division(m, limit='LONG_MAX')](https://doc.sagemath.org/html/en/reference/rings_standard/sage/rings/factorint.html#sage.rings.factorint.factor_trial_division):拿所有小于等于limit的质数尝试去除m，并给出不完整的分解结果
    - [nearby_rational(max_error=None, max_denominator=None)](https://doc.sagemath.org/html/en/reference/rings_numerical/sage/rings/real_mpfr.html#sage.rings.real_mpfr.RealNumber.nearby_rational)：必须指定max_error和max_denominator中的一个。若指定max_error，则返回[self-max_error .. self+max_error]最简的分数。若指定max_denominator，则返回最接近self的分数且分母不超过max_denominator
        - 此题 $n=\frac{p}{q}$ ,所以还可以利用连分数得到p和q：`continued_fraction(n).convergents()`。似乎效果类似nearby_rational？
- https://mitsu1119.github.io/blog/p/zer0pts-ctf-2023-writeup-english/#crypto-102pts-easy_factoring-95-solves
    - 当 $N=p^2+q^2$ 时，可以借助[高斯整数](https://zh.wikipedia.org/zh-cn/%E9%AB%98%E6%96%AF%E6%95%B4%E6%95%B8)分解N。 $N=p^2+q^2=(p+qi)(p-qi)$ ，说明满足这一条件的整数p和q存在于N的高斯整数分解中（以p+qi的形式）。不过使用sagemath的factor会将其分解为高斯素数，所以尝试分解出来的高斯素数的所有combinations即可恢复p和q
    - 还可以用sympy的diop_quadratic方法： https://connor-mccartney.github.io/cryptography/other/easy-factoring-zer0pts-CTF-2023
    - `ZZ[I](N)`表示将整数N转为高斯整数.ZZ[I]为高斯整数环
    - 也可以使用[divisors](https://doc.sagemath.org/html/en/constructions/number_theory.html#divisors)，直接给出所有因子。这种方法恢复p和q就不用爆破组合了，p和q就在里面，直接遍历因子列表然后isPrime判断即可
    - sagemath自带的[two_squares](https://doc.sagemath.org/html/en/reference/rings_standard/sage/arith/misc.html#sage.arith.misc.two_squares)确实可以很快把N写成两个平方的和，但是好像不一定是素数
- [Non-Quadratic Residues](https://github.com/rwandi-ctf/ctf-writeups/blob/main/amateursctf2023/non-quadratic%20residues.md)
    - 有这样一个式子： $c\equiv x^a\mod b$ ,其中a，b（质数）和c均已知。若a较小（如此题a=210），那么可以尝试用sagemath的[nth_root](https://doc.sagemath.org/html/en/reference/finite_rings/sage/rings/finite_rings/integer_mod.html#sage.rings.finite_rings.integer_mod.IntegerMod_abstract.nth_root)开出x。
        ```py
        #感觉使用情况和效果都和上面提过的amm差不多
        GF(b)(c).nth_root(a,all=True)
        ```
- [Tan](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Tan)
    - $tan(m).n(1024)=t,arctan(t)+k\pi\approx m$ ,接下来可以用LLL尝试恢复准确的m。或者参考 https://math.stackexchange.com/questions/2160925/find-an-integer-a-such-that-a-sqrt2-has-a-given-decimal-part/2161019#2161019
        - [n](https://doc.sagemath.org/html/en/reference/misc/sage/misc/functional.html)
        - [LLL](https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix_integer_dense.html#sage.matrix.matrix_integer_dense.Matrix_integer_dense.LLL)
- [Noisier CRC](https://imp.ress.me/blog/2023-08-28/sekaictf-2023#noisier-crc)
    - [irreducible_element](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_ring.html#sage.rings.polynomial.polynomial_ring.PolynomialRing_dense_finite_field.irreducible_element):获取环上指定degree的不可约元素
    - [right_kernel](https://doc.sagemath.org/html/en/prep/Quickstarts/Linear-Algebra.html)
    - [basis](https://doc.sagemath.org/html/en/constructions/linear_algebra.html)
- [sqrt](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/crp/sqrt):计算Permutations(256)中某个元素的平方根。注意一个元素的平方根可能有很多个
    - [to_cycles](https://doc.sagemath.org/html/en/reference/combinat/sage/combinat/permutation.html#sage.combinat.permutation.Permutation.to_cycles)
    - [sage.combinat.permutation.from_cycles](https://doc.sagemath.org/html/en/reference/combinat/sage/combinat/permutation.html#sage.combinat.permutation.from_cycles)
- [Zombie Rolled](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/crypto/%5BHard%5D%20Zombie%20Rolled)。这题啥都有，包含RSA，ECC还有lattice。暂记一些能看出来的知识点
    - 利用椭圆曲线上的rational point求解丢番图方程。参考 https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4
    - 利用Groebner basis求解方程组
- [GLNQ](https://kanzya.github.io/posts/MAPNACTF/#glnq-crypto-13-solve)
    - 计算矩阵上的离散对数。若矩阵的阶为光滑数，就可以用pohlig-hellman配合sagemath解出
- [lalala](https://berliangabriel.github.io/post/bi0s-ctf-2024/)
    - 求解大型矩阵与向量的线性方程组。继续暴露我的无知。参考 https://tanglee.top/2024/02/27/bi0sCTF-2024-Crypto-Writeups/ ，这题的方程组中每个方程的结构是 $\Sigma a_i+\Sigma_i x_{b_i}^2x_{c_i}^3$ 。a，b和c均已知， $x_i$ 是要求的变量，共10个；方程总数共100个； $a_i,b_i,c_i$ 随机生成，共1000个。然后我傻了。我想着“啊啊啊啊怎么是两个变量的乘积啊”，就懵了。有没有一种可能，初中就学过，可以把两个变量看成一个？将 $x_{b_i}^2x_{c_i}^3$ 整体看成线性方程组要求的变量即可。毕竟10个变量无论怎么搭配也只有100种可能，正好有100个方程，直接解就完事。不过sagemath里排列矩阵和向量还是有点绕的
- [rr](https://tanglee.top/2024/02/27/bi0sCTF-2024-Crypto-Writeups/)
    - 好难的一道数学题……个人只能看懂前面的一小部分，涉及费马小定理，二项式定理，模下的方程变形等。后面一段通过变形方程解离散对数的讲解完全看不懂，也不知道这些数怎么设的。大概率是用了什么我不知道的定理或知识
    - binomial_dlog的sagemath实现：solve $y = g^x\mod p^r$ where q=phi(p) such that $g^q = 1\mod p$
    - 多项式最大公因子（Polynomial GCD）的简单实现。快的方法可以参考[HGCD](https://github.com/jvdsn/crypto-attacks/blob/master/shared/polynomial.py)
    - [constant_coefficient](https://ask.sagemath.org/question/52938/constant-coefficient-of-symbolic-expression/)使用
    - 其他解法: [Discrete logarithm modulo powers of a small prime](https://math.stackexchange.com/questions/1863037/discrete-logarithm-modulo-powers-of-a-small-prime), Using p-adic Ring in sage to compute discrete logarithm
- [Too Many Leaks](https://connor-mccartney.github.io/cryptography/diffie-hellman/Too-Many-Leaks-GCC-CTF-2024)
    - bivariate coppersmith求解方程。其实不仅能用于RSA，只要是在有限域下，两个变量的方程都能解（但估计和单变量coppersmith一样，有要求解的变量的大小的限制）。不过这题应用coppersmith的情况还是那种经典的leak n个bits的题，应该还有其他情况能用吧？只要找到线性关系就行（好像确实是，见 https://l0mb4rd.gitbook.io/crypto/cool-ctf-challenges/kleinvieh_2 ）
- [flag_printer](https://github.com/PetePriority/picoctf-2024/tree/main/cryptography/flag_printer)
    - 寻找一个多项式 $p(x)=a_0+a_1x+...+a_nx^n$ ，使得 $p(x_i)=y_i$ 。 $x_i$ 和 $y_i$ 都已知，相当于找多项式的系数 $a_i$ 。写成矩阵就是找Ap=y的p。这种线性方程组可以用polynomial interpolation相关算法（比如Lagrange）加速，但更快的做法参考 https://mathoverflow.net/questions/408666/fastest-implementation-of-polynomial-interpolation/458091#458091 ，思路是FFT+divide and conquer
    - 这题最快的解法可能是flintlib的[nmod_poly_interpolate_nmod_vec_fast](https://flintlib.org/doc/nmod_poly.html#c.nmod_poly_interpolate_nmod_vec_fast)。sagemath实现见 https://github.com/PetePriority/picoctf-2024/blob/main/cryptography/flag_printer/solve_fast.ipynb （Fast interpolation algorithm）
    - 这个[wp](https://github.com/SuperBeetleGamer/Crypto-Writeups/blob/main/picoCTF%202024/Flag_printer/writeup.md)使用了[优化版的Lagrange Interpolation](https://codeforces.com/blog/entry/82953)。仅供参考，wp里再优化一遍后再加上112核的机器也要20小时才能跑完……
    - 这题的矩阵其实是范德蒙德矩阵（[Vandermonde matrix](https://en.wikipedia.org/wiki/Vandermonde_matrix)），可以跟着这篇[wp](https://hackmd.io/@touchgrass/HyZ2poy1C#flag-printer)和 https://codeforces.com/blog/entry/94143 实现更优化版的Lagrange interpolation
    - 其他解法及更多参考链接：**flag_printer** ， https://cp-algorithms.com/algebra/polynomial.html#interpolation
- [cryptordle](https://github.com/aditya-adiraju/capture-the-flag/tree/main/utctf-2024/cryptordle)
    - [多项式环、理想](https://zhuanlan.zhihu.com/p/31441459)和[variety of an ideal](https://math.stackexchange.com/questions/1173939/variety-of-an-ideal)在sagemath里的使用。这么看来多项式环似乎只是全体多项式的集合，且可以有多个变量（多个变量是Multivariate Polynomial Ring）或在有限域里。对应到sagemath里的语法就是`R.<a,b,c,d,e> = PolynomialRing(GF(p))`。理想（ideal）跟着定义来就好，个人在sagemath里试了一下，怎么感觉随便写个多项式都能构造出理想，明明理想的定义挺严格的啊？有了理想后可以取variety，感觉就是理想内所有多项式共同的根
- [QCG](https://github.com/tamuctf/tamuctf-2024/tree/master/crypto/qcg),[wp](https://cryptography-journey.gitbook.io/mindflayer02-ctf-writeups/tamu-ctf-24/qcg-groebner-basis)
    - [Groebner basis](https://en.wikipedia.org/wiki/Gr%C3%B6bner_basis)的使用。这题用来求解模m下的多项式方程组的模数m以及多项式的系数。也是个跟环理想有关系的东西，但这玩意我盯着定义看都不懂，啥叫“the ideal generated by the leading monomials of G”啊？
    - 当时怎么没想着搜搜视频呢： https://www.youtube.com/watch?v=q4L_f7BMOOM ，比纯文章好懂多了。简单来说，它可以将方程组简化。比如有两个特别复杂的函数F和G和另外两个特别复杂的函数R和T，怎么知道两者的解是否相同？可以跑两次Groebner basis算法，如果两者出来的结果是一样的，两者的解就是一样的。注意它出来的结果不是解，是另一个简化版的方程组。F和G被简化成A和B，这个算法保证两者的解相同的情况下让多项式A和B的构造相比F和G更简单。这时看看维基百科就稍微能看懂了，这玩意也可以说是多项式环上理想的生成集
    - 另一道题，感觉介绍得更详细：[benaloh](https://mystiz.hk/posts/2021/2021-02-15-dicectf-1/#benaloh)。可能看[GCL](https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#gcl)更明显：结果多项式与原本的多项式组同根，加上结果多项式的阶数和复杂度都比原来的小，于是就很容易解出来了。支持多变量多项式组
- [guessing](https://github.com/Sarkoxed/ctf-writeups/tree/master/cr3ctf2024/guessing_revenge)
    - [置换矩阵](https://zhuanlan.zhihu.com/p/144347366)与矩阵的逆。发现我压根没有数学思维……这题要求提交非单位矩阵B，服务器返回 $B * A * (B ^ {-1}) * (A ^ {-1}) * FLAG$ ，其中A和FLAG都是未知矩阵，求矩阵FLAG。只需发送除恒等置换外全部的3阶矩阵置换，置换A后与 $A^{-1}$ 相乘。5个不同置换的结果经过特定运算可以得到一个单位矩阵乘上FLAG（到底是怎么想到的）
    - 预期解法是发送两个和为单位矩阵的矩阵，得到结果后经过特定运算也可以得到FLAG
- [maskRSA](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/crypto/maskRSA)
    - [高斯消元法](https://zhuanlan.zhihu.com/p/147962066) （Gauss Elimination），阶梯形矩阵（sagemath echelon_form）的使用。这题三个解法，Gröbner Basis，Gauss Elimination和拉格朗日插值法，但都没想到……看了wp有个疑惑的地方，wp说“...use Gauss Elimination to calculate each coefficient of the encryption polynomials, since the challenge give us 20 encryptions while there are only 18 coefficients in each polynomial”,但我寻思高斯消元法需要的方程个数不是和要求的变量数量有关吗？怎么这里拐到系数数量了？可能是因为这里把“系数”看成多项式的变量了。所以搞半天这里说的系数不是解方程时的系数，而是题目那个17次多项式乘起来的结果的系数，我们要求的就是这个系数，所以这个系数应该是解方程时的变量
- [Lagrange interpolation over a finite field(mod p)](https://ask.sagemath.org/question/39732/lagrange-interpolation-over-a-finite-field/)
- [accountleak](https://dunglq2000.github.io/mywriteups/TJCTF-2024.html#accountleak)
  - 利用PolynomialRing解单变量方程（多项式）。需要变形方程使其可以表示为单变量多项式
  - 另外值得一提的是，这题需要爆破多项式中的一个变量，因此给定该变量的一个值后解方程的速度越快越好。个人在比赛中用了sagemath内置的solve来解，非常慢……像这个wp用多项式环就会快很多
- [My Calculus Lab](https://github.com/Warriii/CTF-Writeups/blob/main/akasec/crypto_calculus.md)
    - 使用sagemath求解常微分方程
    - 一些sagemath api
        - `function('y')(x)`:定义一个名为y的函数，其自变量为x
        - `desolve(2*ypp - 6*yp + 3*y == 0, y, ics=[0,v0,v1], ivar=x)`:第一个参数为方程，第二个参数为因变量，第三个参数为初始条件。这里表示`x=0,y(0)=v0,y'(0)=v1`。`ivar=x`表示自变量为x
    - python sympy（无sagemath）解法：**my calculus lab**
- [Determined](https://octo-kumo.me/c/ctf/2024-uiuctf/crypto/determined)
    - 比赛时看出来了它在算5阶方阵的行列式，也想到了用sagemath或者z3算方程拿p和q，但是模拟方程太复杂了，懒得写。结果这个wp告诉我sympy里直接做个矩阵自动求行列式放到方程里就能解？
- [Raul Rosas](https://tsumiiiiiiii.github.io/deadsec24)
	- bivariate coppersmith使用，相关脚本： https://github.com/defund/coppersmith 。真的是有点憨，coppersmith我想到了，方程的表示我也想到了，结果没想到爆破一个最小的未知数使方程只剩下两个未知数从而用bivariate coppersmith。注意使用coppersmith法时，构造的方程如果有很明显的平凡解法（比如0,0），需要变形方程使其避开这种情况
	- 假如两个位数差距很大的数相乘，如一个1024位的数A乘上一个300位的数B，两者相乘的结果模 $2^{400}$ 等于A的低300位乘上B再模 $2^{400}$ 。也就是说位数低的数字相乘时只会影响另一个数字相应的低位。分解时考虑低位就好，高位不重要
- [One more bit](../../CTF/moectf/2024/Crypto/One%20more%20bit.md)
    - “增强版”wiener attack。想要wiener attack成功有个条件：d必须小于关于n的特定bit数。`Verheul and van Tilborg’s Extension`可以将这个条件变得宽松些，见 https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=158dd0abfe27fdf2ceba24c3d168df93743af569 第7页式子`(7)`
- [babe-Lifting](../../CTF/moectf/2024/Crypto/babe-Lifting.md)
    - partial key exposure attack(d泄漏高位或低位)。脚本见 https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/partial_key_exposure.py
    - 官方wp见 https://github.com/XDSEC/MoeCTF_2024/blob/main/Official_Writeup/Crypto/MoeCTF2024%20Crypto%20Writeup.md 。这个脚本我比赛时也试过，不知道为什么出不来结果
- [Twister](https://github.com/WorldWideFlags/World-Wide-CTF-2024/blob/main/Cryptography/Twister)
    - 如何用solve_right解模2的线性方程组
    - 对着wp都差点没看出来这题是解线性方程组……长点心吧
- [Quadrillion Matrices](https://lov2.netlify.app/nitectf-2024-tuan-dui-writeup)
    - 计算矩阵是否是二次剩余（legendre symbol）。不过看题目的矩阵生成代码，只有可对角化并可逆的矩阵才有可能使用legendre symbol，有和整数类似的性质。看[官方wp](https://github.com/Cryptonite-MIT/niteCTF-2024/tree/main/crypto/quadrillion_matrices)的解法会更清楚。比赛中由于生成矩阵的代码被隐藏了，直接没想到这点。看来以后遇到矩阵幂的情况要看看矩阵的对角化和jordan form形式
    - 计算矩阵的的dlp。需要神奇的CADO-NFS，而且耗时较长
    - 原来这题很久以前就有人研究过了，结合 https://cstheory.stackexchange.com/questions/12655/discrete-log-in-gl2-p 和 https://crypto.stackexchange.com/questions/22830/finding-xs-parity-in-the-discrete-log-problem 即可
- 记录个工具： https://github.com/Aeren1564/CTF ，里面的CTF_Library看起来很香

## Lattice(格)

是的我需要一个格题分类。虽然我根本就不懂什么是格

- 攻击与格有关的密码的工具： https://github.com/josephsurin/lattice-based-cryptanalysis
- [LCG to the power of n!](https://github.com/SuperBeetleGamer/Crypto-Writeups/blob/main/LITCTF%202023/lcg%20to%20the%20power%20of%20n!.md)
    - 格（lattice）中的Closest Vector Problem（CVP）
    - [IntegerLattice](https://doc.sagemath.org/html/en/reference/modules/sage/modules/free_module_integer.html#sage.modules.free_module_integer.IntegerLattice)
    - Babai_closest_vector算法实现
- [Geometry Hash](https://connor-mccartney.github.io/cryptography/other/Geometry-Hash-Balsn-CTF-2023)。这题的格构造与三角形的Centroid，Circumcenter和Incenter有关
- [Hohoho 2 Continue](https://mechfrog88.github.io/wargames-2023#hohoho-2-continue)
    - LCG。这题要求预测一个LCG的值，LCG的各个参数都知道，但要预测的项未知（不知道要预测第几个输出）。初始的x可以随意输入，但必须包含一个固定短语。做的时候傻了，后来发现可以找一个包含短语的x，并让其满足 $x=(ax+b)\mod n$ 即可。找的时候使用LLL（从wp里似乎摸到一点格的门道了，但是先不记，还有地方不懂，不想误导未来的自己）。类似的题目（也用了格，还有不错的介绍）：[Onelinecrypto](https://nush.app/blog/2023/06/21/see-tf-2023/)
- [any% ssg](https://hackmd.io/@lamchcl/SJIdwQb3a#cryptoany-ssg)
    - 利用LLL爆破类似minecraft的生成地图seed。参考官方[wp](https://github.com/AVDestroyer/CTF-Writeups/tree/main/lactf2024/any-percent-ssg)和wp里提到的视频[系列](https://www.youtube.com/playlist?list=PLke4P_1UHlmB8sB1oGdcea4SeBH0yZy5B) （另外这也是个不错的格入门视频），这题的知识点更准确地说，应该是“找到LCG的初始seed，使接下来的12个连续输出满足 $min\leq seed_i\leq max$ 的不等式“
    - 其他脚本： https://gist.github.com/TheBlupper/0b3cb0b7402c46e3d374a7244bd9e5cd
- [Too Many Leaks](https://berliangabriel.github.io/post/gcc-ctf-2024/)
    - Diffie-Hellman共享秘密的高位泄漏：Hidden number problem,见[论文](https://eprint.iacr.org/2020/1506.pdf)的6.2节,Most significant bits of finite field Diffie-Hellman shared secret
- [ReallyComplexProblem](https://maplebacon.org/2024/05/sdctf-reallycomplexproblem/)
    - 复数（complex numbers）上的部分p（这个p是高斯素数，gaussian primes）泄漏RSA题。也是个coppersmith，本来要放在rsa分类里的，不过这题的重难点都在格上，就放这了。不过这篇wp也是篇很好的coppersmith介绍文。涉及内容：
        - Howgrave-Graham Theorem，有关如何将mod p上的多项式的根转换成普通整数上多项式的根（说转换可能不太准确，应该说“存在”）
        - 如何缩减大型多项式。上面那个定理有一条要求多项式的系数向量较小，如果已有的多项式过大的话，就要找点方法将其缩小（缩的是系数而不是根）。长话短说，几个mod p下根一样的多项式的线性组合结果不会改变根。针对coppersmith这个 $f(x)=a+r\mod p$ （实际情况下还要乘个上限R）多项式找同根的多项式也不难，n是一个（常数也算），f(x)的所有次幂也是。给f(x)乘x的不同次幂也行，只是这样就没有常数项了。还有两种构造方式见wp
    - 用上面的方法找到各个根相同的多项式后，就能用LLL找最短小的线性组合了。主要这里我们要的线性组合仅限整数，如果只用在实数下找到比较正交短小的向量线性组合，用施密特正交化即可。LLL在整数RSA和复数RSA上的构造见wp（整数勉强能懂，复数完全不懂，看是看得懂每一个字，但不知道为啥要这样做）
    - 其他资料和参考文章：
        - A bunch of lectures from Tanja Lange on Coppersmith and RSA： https://www.youtube.com/@tanjalangecryptology783/videos
        - https://www.klwu.co/maths-in-crypto/lattice-2
        - [Ideal forms of Coppersmith’s theorem and Guruswami-Sudan list decoding](https://ia803007.us.archive.org/2/items/arxiv-1008.1284/1008.1284.pdf)
        - paper that summarizes the various attacks on RSA:[Recovering cryptographic keys from partial information, by example](https://eprint.iacr.org/2020/1506.pdf)
- [Crypto on the Rocks](https://github.com/supaaasuge/CTF-Challenges/tree/main/crypto-on-the-rocks)
    - PuTTY NIST P-521 elliptic curve biased k: https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-p521-bias.html 。PuTTY工具使用了NIST P-521椭圆曲线，由于一些实现错误导致选择的k的9个msb bit均为0。于是便有了[hidden number problem](https://lazzzaro.github.io/2020/11/07/crypto-%E6%A0%BC%E5%AF%86%E7%A0%81/index.html#%E9%9A%90%E8%97%8F%E6%95%B0%E9%97%AE%E9%A2%98%EF%BC%88HNP-Hidden-Number-Problem%EF%BC%89) （这题是hnp的一个小分支：dsa known msb），可用lattice求解： https://github.com/jvdsn/crypto-attacks/blob/master/attacks/hnp/lattice_attack.py
- [uf](https://connor-mccartney.github.io/cryptography/other/WaniCTF2024)
    - 求解approximate gcd问题。说有这么一组数，它们的gcd为m。但是由于某种原因，多了一个较小的误差项：
    ```py
    #理论上
    assert m == gcd([x0, x1, x2, x3])
    #但是多了几个误差项
    #x0 = y0*m + z0
    #x1 = y1*m + z1
    #x2 = y2*m + z2
    #x3 = y3*m + z3
    ```
    - 相关论文/资料： https://eprint.iacr.org/2016/215.pdf ， https://ur4ndom.dev/static/files/latticetraining/practical_lattice_reductions.pdf
- [Bigger and better](https://connor-mccartney.github.io/cryptography/small-roots/Bigger-and-better-crew-CTF-2024)
	- 经典LLL题只能懂一半……大致是给出了一个在Z/nZ上的5变量高阶多项式，要求找到根。配合[官方wp](https://gist.github.com/Babafaba/b561e663299bfaa0bb6002b1b4946b0f)能把思路看得更明白点。虽然每个根相比多项式来说很小，但高阶+多变量使得5-variate coppersmith不太可能。所以把这个5变量的高阶多项式换成25变量的一阶多项式，加上模数n过大不破坏其线性关系，用LLL找到转换后多项式的根，然后用groebner_basis或者直接solve找到原本多项式的5个根
- [Read between the lines](https://gist.github.com/7Rocky/5777a73648a3befdee58a0eac90d7b0d)
	- 一道难得的lattice LLL入门题。但我仍不确定使用LLL时的某个用来加bound的大数字该怎么定？看wp里说是“an arbitrarily large number”，但似乎其他人不是这么说的？
- [Boring LCG](https://github.com/Thehackerscrew/CrewCTF-2024-Public/tree/main/challenges/crypto/Boring%20LCG)
	- 给出LCG（`x=(ax+b) mod c`）的a、b和c参数值以及lcg的连续12个输出的高位，求最开始的x。只能稍微看懂wp里说的简单情况——c为质数，实际的情况——c为质数的3次方，完全不懂。它这个前提我就不懂，什么叫“a finite field of order $p^k$ is instead usually constructed as a polynomial ring with coefficients in $F_p$ modulo an irreducible polynomial of degree k, i.e $F_p[i]/p(x)$ ”？意思是 $F_{p^k}$ 不常用，通常用（与其同构的，这个修饰词我猜的）多项式环代替？
	- 简述一下这道题的简单情况。lcg第i项的通项公式为 $x_i=a^ix_0+b\frac{a^i-1}{a-1}$ （省略模p）, $x_0$ 是最初的seed。让 $B_i = b \frac{a^i-1}{a-1}$ ，构造以下格：

$$
\begin{bmatrix}
1 & a^1 & a^2 & \cdots & a^n \\
0 & p & 0 & \cdots & 0 \\
0 & 0 & p & \cdots & 0 \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
0 & 0 & 0 & \cdots & p \\
\end{bmatrix}
$$

考虑线性组合 $[s_0, k_1, k_2, ..., k_n]$ ，即在矩阵左侧乘上这个向量，结果是 $[s_0, s_1 - B_1, s_2 - B_2]$ 。 $k_i$ 我觉得是用来抵消模p的，毕竟乘出来结果是 $a^is_0+k_ip$ 。问题是，这个出来的向量不一定就是格里最短的向量，没法直接用LLL。于是我们构造一个结构和这个向量差不多的向量 $[h_0, h_1 - B_1, ..., h_n - B_n]$ ， $h_i$ 为 $s_i$ 最大值和最小值的中点（最大值和最小值可以根据题目给出的高位推算），用cvp相关算法算出和这个向量最近的向量，期待结果就是我们想要的那玩意
- Fast lattice reduction:[flatter](https://github.com/keeganryan/flatter)。使用案例：[SSP](https://thr34dr1pp3r.gitbook.io/ctf/deadsec-ctf-2024/crypto-ssp)。可以加速大型格的计算，但是没法处理很小的格。小格的话用sagemath自带的LLL即可
- [はやぶさ](https://7rocky.github.io/en/ctf/other/sekaictf/%E3%81%AF%E3%82%84%E3%81%B6%E3%81%95)
    - [Falcon](https://falcon-sign.info/) signatures（Fast-Fourier Lattice-Based Compact signatures over NTRU）key recovery attack。此攻击只能在参数n较小的情况下使用
    - NTRU lattice由多项式组成，wp里记录了如何将由多项式构成的格转为由整数构成的格
- [SignMeUp](https://github.com/plvie/writeup/blob/main/glacierctf2024/signmeup)
    - 又是一道将模某个质数的多未知数方程转成格的题目。感觉将来某一天我会困于如何造方形的格基矩阵（
- [R Stands Alone](https://lov2.netlify.app/nitectf-2024-tuan-dui-writeup)
    - 用格求解形如 $ax^n + by^n$ 的质数的x和y值。类似题目： https://connor-mccartney.github.io/cryptography/other/TCP51Prime-TCP1PCTF2024International
    - 比赛时借着moectf学到的知识弄出了非预期解。加密的明文长度必须超过n的最大素数因子的位数，否则就能直接拿最大素数因子-1当作phi进行解密（得到的是m模那个质数，然而m比那个质数小，于是就直接出来了）
    - 另一个未曾设想的道路：**R Stands Alone** ，竟然能直接解啊？
- [Hashing Frenzy](https://hackmd.io/@r4sti/BkCBDWuryl)
    - 有进步！看出格的可能性了！但是又退步到没看出来怎么找模数p……题目自定义的hash算法多项式如下： $A = s_6 = \sum_{i = 0}^5{s_ih_i(m)} \pmod p$ ,但p未知， $h_i$ 是已知的哈希算法。不过可以连续hash两条明文，自行计算 $\sum_{i = 0}^5{s_ih_i(m)}$ 后与服务器得到的结果相减得到 $k_1p$ 和 $k_2p$ ，gcd两者有很大可能得到p
    - 格的构造（svp做法）wp讲的很详细，不过这里记录一下个人的疑惑和见到的补充内容
        - 这个做法提到需要加个scaling factor LLL才能找到正确的结果。但最后又发现其实不加scaling factor，只要多加一个列即可。可能是因为最开始不加列所构造的格基矩阵不是一个方矩阵？当然更有可能是这样构造出来的格的最短向量比目标更短，毕竟[这个做法](https://github.com/kh4rg0sh/ctf_writeups/tree/main/backdoorctf-2024/crypto/Hashing-Frenzy)使用的格基矩阵也不是方矩阵，但LLL成功了。不过那个做法怎么是8个9维行向量组成的格？这也行吗？还是其实是9个8维列向量？后面发现去掉从右往左数第二个列也是可以的,见 **Hashing Frenzy**
        - 加了scaling factor后的线性关系是不是写错了？见`the target vector is derived as`部分，个人觉得应该是:

        $$\begin{pmatrix}h_0&h_1&h_2&h_3&h_4&h_5&1&-k\end{pmatrix}$$

        - 终于稍微看懂点cvp用法了。看起来用cvp需要知道要求的各个变量的大概大小？线性关系的选择也有讲究？
    - 在上方的gists处我还记了一位佬对这篇wp的补充说明+讨论。包括：
        - sagemath的block_matrix的用法
        - 利用PolynomialRing更快构造格的方法(用了一下，不知道为啥报错……考虑下面knutsacque的其他解法中`alex_hcsc`的类似构造方法)
        - LLL解题过程中权重（weight）的思考——什么时候该加权重，加了意味着什么？详情见 https://magicfrank00.github.io/writeups/posts/lll-to-solve-linear-equations ，我见过的有关LLL解线性方程组的最好解释
- [Secure Nonsense](https://hackmd.io/@Solderet/rk2g-kwr1g)
    - hidden number problem(hnp)。包装好直接用的hnp见 https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/lbc_toolkit/problems/hidden_number_problem.sage 。主要是这样一个式子: $\beta_i - t_i \alpha + a_i \equiv 0 \pmod p$ ,输入各个 $t_i$ 和 $a_i$ 的值并给出 $\beta_i$ 的上限，返回 $\alpha$
- [A-Complex-Shamir](https://github.com/kh4rg0sh/ctf_writeups/blob/main/backdoorctf-2024/crypto/A-Complex-Shamir)
    - lagrange's interpolation，但是只能得到 $C^{f(x)}$ ，其中C为复数，等于 $e^{i\theta}$ 。wp展示了一种求出系数的更聪明的方式，利用指数运算也有和正常多项式类似的性质用矩阵求出 $C^{a_i}$ （这块绕了我好久，实际上把存在的矩阵运算写出来就能看明白了。以及关键的部分： $f(x) = a_0 + a_1 x + a_2 x^2 + \dots + a_{68} x^{68}$ , $C^{f(x)} = C^{a_0} \cdot (C^{a_1})^x \cdot (C^{a_2})^{x^2} \cdot \dots \cdot (C^{a_{68}})^{x^{68}}$ ），其中 $a_i$ 为要求的系数
    - 接上一条，求解过程中会发现需要构造一个范德蒙矩阵（Vandermonde matrix），而这个矩阵的逆通常会包含一些分数。题目在指数下操作，分数中的分母n就会转换为取n次根，容易有精度损失。所以可以给矩阵乘上个scaling factor，把分数取消掉。最后求出结果后除以这个factor便是真正的结果了
    - 复数（complex number）的dlp。重点是可以用 $e^{i\theta}$ 表示任意复数，可以把dlp转为求模 $2\pi$ 下的线性同余方程。可惜求不了模逆元，所以只能用格来求
- [knutsacque](https://github.com/Seraphin-/ctf/blob/master/2025/irisctf/knutsacque.md)
    - 求解四元数（quaternion algebra）的线性方程。我不懂四元数，但搜了一下发现四元数乘法有个明确的公式（Hamilton product），于是整个四元数线性方程其实是四个线性方程组成的方程组。拿正常思路解即可。LLL不知道为啥出不来，不过babai_cvp侥幸拿下
    - 结果还是看不懂官方wp……四元数可以写成复数域下的矩阵，而复数元素又可以写成实数域下的矩阵。用单射同态便能构造出整数域下的矩阵，从而正常地使用LLL（大部分数学软件只支持整数域的矩阵LLL）。看了一眼wp的脚本，似乎是把一个大的四元数矩阵“切”成了四块，一个一个解（又学一种构建思路，这个构建方法不知道为什么就能直接LLL出来结果，不需要CVP）
    - Mathematica 和 [fpllh](https://www-fourier.univ-grenoble-alpes.fr/~pev/fplllh/)支持高斯整数下的LLL
    - 其他解法： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#knutsacque 。果然有人跟我类似思路，不过我没想到竟然有现成脚本： https://github.com/TheBlupper/linineq
- [zk-Openings](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/crypto_zk-openings)
    - Zero-knowledge+Lattice。太难了，难到全场零解。只知道这和[Plonkup](https://eprint.iacr.org/2022/086.pdf)有关

## Elliptic Curves(ECC,椭圆曲线)

是的我需要一个椭圆曲线题分类。我对这玩意的了解比格还少，只是记录下来方便未来的我复习(相信后人的智慧)
- [Isogenies](https://hackmd.io/_D7hNf_wQ7qq0PArYPWjSQ)
    - 3-torsion point
    - isogeny
    - montgomery coefficients
    - j-invariants
    - [Modular polynomials](https://math.mit.edu/~drew/ClassicalModPolys.html)
    - [Division polynomials](https://en.wikipedia.org/wiki/Division_polynomials)
    - [Resultant](https://en.wikipedia.org/wiki/Resultant)
- [yaonet](https://7rocky.github.io/en/ctf/other/dicectf/yaonet/)
    - OpenSSH格式ECDSA私钥恢复。给出损坏的私钥文件，文件内部包含缺少5个字节（3个前缀字节2个尾字节）私钥d，尝试恢复d并构造原本的私钥文件。利用Baby-step Giant-step算法及Meet-in-the-middle思想。难点在于当缺失的字节不连续时如何构造公式并从两端入手
    - 其他wp： https://connor-mccartney.github.io/cryptography/ecc/yaonet-DiceCTF-2024
- [not-suspicious-agency](https://www.youtube.com/watch?v=8Cbz1e3motE)
    - [Dual_EC_DRBG](https://en.wikipedia.org/wiki/Dual_EC_DRBG)（基于椭圆曲线的随机数生成器,有时候题目名称/描述会和NSA有关系）的[后门利用](https://crypto.stackexchange.com/questions/10417/explaining-weakness-of-dual-ec-drbg-to-wider-audience)。类似题目： https://github.com/cscosu/ctf-writeups/tree/master/2021/utctf/Sleeves
    - 如何在椭圆曲线下求乘法逆元：`inverse(a,E.order())`
- [budget bag](https://connor-mccartney.github.io/cryptography/ecc/budget-bag-LACTF-2024)
    - 通过曲线上的两个点恢复参数a和b
    - 带有elliptic cusp（a和b均为0）的椭圆曲线上的离散对数比较好求，参考 https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp
    - 利用离散对数将曲线上点的加法转换为线性方程（wp里说是背包问题，我菜到看不出来）。假设有一些已知的点，各个点的系数未知，整体加起来为曲线上的另一个点S。可以取已知的点中任意一个点作“生成点G”，那么剩下的点一定是G的倍数（具体多少倍求离散对数可得）。求G对于S的离散对数（不确定这样表达有没有问题，求S是G的多少倍），那么之前求的G相对于已知点集里各个点的离散对数结果与G对S的离散对数构成模曲线质数p的方程（各个离散对数结果记为 $d_i$ ,G对S的离散对数记为D那么 $d_ix+d_{i+1}y+...=D\mod p$ 。解这种模某个数的线性方程的脚本参考wp）
- [Predictable](https://blog.bi0s.in/2024/03/28/Crypto/Predictable-bi0sCTF2024/)
    - 椭圆曲线上两个点相加的double-and-add算法的时间测信道攻击
    - 利用backdoor预测Dual_EC_DRBG输出
    - 其他wp： https://tanglee.top/2024/02/27/bi0sCTF-2024-Crypto-Writeups/
- [challengename](https://tanglee.top/2024/02/27/bi0sCTF-2024-Crypto-Writeups/)
    - 若ECDSA算法定义在256-bit的曲线上而nonce只有128 bit，可以使用short nonce attack。只需两个签名就可恢复私钥
    - nonce reuse解法： https://berliangabriel.github.io/post/bi0s-ctf-2024/ ， https://gist.github.com/Hisokap3/f446034f6d6ca9bcfeee05c1dad0aaa4
- [Elliptic](https://connor-mccartney.github.io/cryptography/ecc/Elliptic-GCC-CTF-2024)
    - 如何构造anomalous curve（方便利用smart攻击求离散对数）。除了wp里的脚本，还可以用： https://github.com/jvdsn/crypto-attacks/blob/master/shared/ecc.py#L62
    - 椭圆曲线上的knapsack问题。如果可以获取足够数量的方程，如加密二进制长度为107的字符串，获取107个不同的knapsack方程就能将其转为线性方程组求解。这题还多了个将曲线上的点转为线性方程的步骤，已经在budget bag里解释过
    - [官方wp](https://www.xorminds.com/posts/2024/elliptic/)使用了格来解knapsack问题。128 bits的curve所组成的格过于dense，无法用LLL解出，需要用更大的质数，如768 bits
- [mutant-mayhem](https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#mutant-mayhem)
    - ECDSA的python简单实现
    - sagemath实现： https://nightxade.github.io/ctf-writeups/writeups/2024/Jersey-CTF-IV-2024/crypto/mutant-mayhem.html
- [forgery](https://github.com/utisss/UTCTF-24/tree/main/crypto-blsforgery)
    - BLS digital signature。BLS12-381是一个特殊的椭圆曲线，具体特征可看 https://hackmd.io/@benjaminion/bls12-381#About-curve-BLS12-381 。这种签名算法的私钥sk是一个从1到r-1（包含，r为群阶）的整数，公钥是私钥乘上 $g_1$ （子群 $G_1$ 的generator，参考 https://hackmd.io/@benjaminion/bls12-381#The-Subgroups ）。签名只需计算 $\sigma=[sk]H(m)$ 。有一个特别的性质，若n方用不同私钥签名了同一条消息，将n者所有的公钥和签名结果加起来，用这个结果验签也会通过。这种“合起来的签名”叫aggregate signatures
    - Rogue key attacks。假设A的公钥是 $pk_1$ ，攻击者B的密钥是 $sk_2$ 。B可以伪造 $pk_2=[sk_2]g_1-pk_1$ ，即B的公钥加上A公钥的逆。此时签名一条信息 $\sigma=[sk_2]H(m)$ ，此签名是A和B的有效aggregate signatures，而A明明没有签名过这条信息
- [Babylogin](https://affine.group/writeup/2024-06-Codegate-Babylogin)
    - invalid point(invalid curve)攻击。之前见过（122条）但是不太明白，今天看了 https://lazzzaro.github.io/2020/11/07/crypto-ECC/index.html#Invalid-curve-attack 稍微明白点了。这题不一样的地方在于，服务器只看x坐标，导致私钥s模invalid curve的阶d有`s mod d`和`-s mod d`两种可能。这时做crt就有点麻烦了，因为不知道到底哪种才是对的，需要爆破正确组合。wp里给了四种解决办法。另外一个难点在于怎么生成用于实施invalid point攻击的曲线和对应小阶数的点
    - 题目作者灵感来源： https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2023/10/0073-invalid_curve.pdf
    - 另一道类似的题目： https://rkm0959.tistory.com/232
- [talk-to-echo](https://github.com/BCACTF/bcactf-5.0/blob/main/talk-to-echo)
    - 又是一个invalid point(invalid curve)攻击。不过这题是入门级，稍微好理解点。生成小阶数的点和曲线时都用的是随机生成的方式，求crt时用的是 $priv^2\mod p$ 的做法来消除原本的正负数两种可能。这个方法的缺点是，假如原本曲线模n，这里想恢复 $priv^2$ 就需要crt的各个质数总乘积达到 $n^2$
- [マスタースパーク](https://7rocky.github.io/en/ctf/other/sekaictf/%E3%83%9E%E3%82%B9%E3%82%BF%E3%83%BC%E3%82%B9%E3%83%91%E3%83%BC%E3%82%AF)
    - [CSIDH](https://csidh.isogeny.org/csidh-20181118.pdf)协议。这个协议本身问题不大，这题的漏洞是返回公共参数时返回错了……不过还是借这道题了解了一下这个协议。CSIDH是Commutative Supersingular Isogeny Diffie-Hellman的缩写，内容大概如下：
        - A和B双方的私钥都是一组界于-m到m的随机数。假如拿的是A的私钥，协议利用这个私钥计算几个同源(isogeny)，这样就能从基础椭圆曲线 $E_0$ 到另一个椭圆曲线 $E_a$ 。如果拿的是B的私钥，就是从 $E_0$ 走到 $E_b$
        - 协议的公钥为曲线 $E_a$ 和 $E_b$ 的（Montgomery coefficient）。有了蒙哥马利系数就能确定一条蒙哥马利形式曲线 $By^2=x^3+Ax^2+x$ （这里A和B是蒙哥马利系数）
        - 最后，A用私钥就能从 $E_b$ 走到 $E_{ba}$ ；B能从 $E_a$ 走到 $E_{ab}$ 。殊途同归
        - Commutative指交换性， $E_{ba}=E_{ab}$ 。同源是两个超奇异椭圆曲线之间的同态
    - 剩下的是一些数学内容。群同态，计算曲线参数，Pohlig-Hellman（离散对数+crt，因为目标结果比模的p大，所以需要多个离散对数结果再用crt组回原来的内容。之前好像见过）等
- [Private Curve](https://connor-mccartney.github.io/cryptography/ecc/PrivateCurve-0xl4ughCTF2024)
    - 获取EC-LCG的7个输出后恢复曲线的参数p，a和b。主要是 https://arxiv.org/pdf/1609.03305 第5页的算法的简单实现
    - 光滑阶数曲线（smooth order curve）求离散对数
    - 另一位佬不看论文的做法，使用polynomial resultants： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#private-curve
- [Future Desk Market](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/cryptopwn_FDM)
    - ECC partial nonce leak。也是早有耳闻，只是没想到第一次见这个考点居然是在一个pwn题里……
    - 看到了一个不错的调试工具：[libdebug](https://github.com/libdebug/libdebug)
- [much-vulnerable-machine-1](https://github.com/x3ctf/challenges-2025/tree/main/crypto/much-vulnerable-machine-1)
    - ecdsa nonce leak攻击
    - 补充文章： https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care
        - reused nonce
        - leaked and biased nonce
        - bad nonce（nonce bit数过小）
        - https://cryptopals.com/sets/8/challenges/62.txt 也不错

## AES/DES

AES是很能出题的。DES则是放在这凑数的

- [t0y-b0x](https://blog.bi0s.in/2024/03/03/RE/t0y-b0x-bi0sCTF2024/)
    - Linear Cryptanalysis (AES with linearly dependent SBOX)。相关漏洞学习参考 https://hackmd.io/@vishiswoz/r10P7knwj 和 https://kevinliu.me/posts/linear-cryptanalysis/ 。SBOX是aes中唯一非线性的运算，如果SBOX操作线性了，就能使用线性相关的攻击
    - [Cracking AES Without any one of its Operations](https://medium.com/@wrth/cracking-aes-without-any-one-of-its-operations-c42cdfc0452f)
- [tag-series-1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/tag-series-1)
    - AES ECB。在key固定且可以进行query的情况下（每次query的明文不同）预测某个明文的最后一个密文块。其实很简单，因为ECB是分块加密的，只要最后一个密文块对应的明文不变即可
- [tag-series-2](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/tag-series-2)
    - 跟上面那题目标一样，但是是CBC。更详细的解析： https://docs.google.com/presentation/d/1FfM7ZblrqmNklG5NX9T5UyTDdEb5h1BRZTtwNrm_-mQ
- [admin](https://github.com/Thehackerscrew/CrewCTF-2024-Public/tree/main/challenges/crypto/admin)
	- AES GCM,已知两条明文及其对应密文+可控制加密用的IV（IV重用，不过更多时候叫nonce），要求伪造指定明文的密文
- [Lazy STEK](https://blog.soreatu.com/posts/writeup-for-lazy-stek-in-line-ctf-2022/)
    - AES GCM forbidden attack（nonce reused攻击）
    - 还是在这个[脚本](https://rbtree.blog/posts/2022-03-27-sage-script-for-aes-gcm/)里知道这题的。脚本内容为“在sagemath里如何将字节块转换为 $F_2^{128}$ 里的元素”
- [Conversationalist](https://github.com/JorianWoltjer/challenges/blob/main/1337up-live-2024/conversationalist)
    - AES GCM nonce reused攻击的实际案例。出问题的库是rust的[cocoon](https://crates.io/crates/cocoon)
    - 知识点和上面两道题一样。补充一篇文章： https://frereit.de/aes_gcm 。nonce重用后，和ctr模式类似，整个gcm就成了many time pad。不过gcm对每条消息都提供了验证tag，导致针对gcm模式的密文伪造攻击比ctr多了一步：构造多项式方程恢复验证用的key
- [Invisible Salamanders in AES-GCM-SIV](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/)
    - 构建一条`ciphertext+tag`使其用两个已知的不同密钥解密后得到两个不一样但有效的明文
- [DODOLOUF](https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#dodolouf)
    - AES-cbc字节反转攻击+python随机数预测（randcrack）。这题出现反转攻击的明文段属于python pickle序列化内容。有一点要注意，因为攻击后必定有几块解密出乱码，所以一般安排这些乱码出现在诸如username的等无伤大雅的字段。但是若原本存储username时用的是普通字符串（unicode类型）而不是bytestring，反序列化时就会出问题。所以要同时把pickle里记录字段类型的字节也改了
- [Desfunctional](https://berliangabriel.github.io/post/google-ctf-2024/)
    - DES的Complement Property。 $E(P)=C\Leftrightarrow E(\overline{P})=\overline{C}$ 。 $\overline{P}$ 指的是P的补码，即P^0xff
    - DES密钥字节的第0，8，16,...,184位为parity bit，即使这些bit被改变后也不影响解密结果
    - 此题使用的是3-DES CBC。3-DES不影响这个性质，不过注意CBC的构造，分成多个块后只有第一个块按照该性质解密后需要手动异或0xff。原因在于CBC加密前会与前一个密文块进行异或，只有第一块只跟iv异或。 $E(P_1\bigotimes 0xff\bigotimes iv)=E(P_1\bigotimes iv\bigotimes 0xff)=C_1\bigotimes 0xff(C_1=P_1\bigotimes iv)$ 。下一个块加密时得到 $E(P_2\bigotimes 0xff\bigotimes C_1)=P_2\bigotimes P_1$ ，0xff被抵消掉了。因此解密后直接得到 $P_2$ 而不是 $P_2\bigotimes 0xff$
- [decrypt then eval](https://octo-kumo.me/c/ctf/2024-ductf/crypto/decrypt-then-eval)
  - aes cfb猜明文。cfb模式是 $C=E\bigotimes P$ （具体见 https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB) ）,假如知道C和P，就能找到E，进而自己伪造密文。前提是key和iv重用且我们有足够的oracle
  - [官方wp](https://github.com/DownUnderCTF/Challenges_2024_Public/tree/main/crypto/decrypt-then-eval)处理了更复杂的情况
  - 其他解法： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#decrypt-then-eval
- [cbc](https://github.com/rerrorctf/writeups/tree/main/2024_09_06_CSAWQuals24/crypto/cbc)
    - aes cbc padding oracle attack。题目有个oracle可以解密任意密文，返回密文是否解密成功。目标是解密指定密文
    - 附赠一个rust工具：[rustpad](https://github.com/Kibouo/rustpad)
- [AES Overdrive](https://mcsch.dev/posts/glacierctf-2024)
    - 假如AES只执行一轮，利用明文攻击可以恢复其密钥。使用工具[aeskeyschedule](https://github.com/fanosta/aeskeyschedule)的做法： https://johan6337.github.io/posts/write-up-glacierctf-2024
    - 搜"Low Data Complexity Attack"的时候发现我之前居然见过类似的题目，见Shmooving 3
- [Subathon](https://github.com/WorldWideFlags/World-Wide-CTF-2024/blob/main/Cryptography/Subathon)
    - aes sbox如果有一个重复的字节（即有一个字节不存在于sbox），则可以利用oracle恢复最后一轮的轮密钥，进而破解密文
    - 这题sbox里不会出现的字节是0xea。根据最后一轮的操作（`sub_bytes`,`shift_rows`,`add_round_key`），sub_bytes产生的结果绝对不会有0xea，shift_rows也不会改变这个结果，add_round_key也只是异或。因此假如有一个orcacle（可以得到随机明文的加密结果），用0xea异或其密文，则异或结果不可能是最后一轮的轮密钥。利用这点慢慢排除可能的轮密钥字节就能得到确切的结果
- [AYES](https://github.com/Seraphin-/ctf/blob/master/2025/irisctf/ayes.md)
    - 翻转aes sbox指定索引处的指定bit,通过oracle（输入明文获取其密文）恢复密钥。wp的做法我没怎么看懂，比赛时发现和上一题Subathon很像，就直接用了。也能恢复密钥，在我看来还更好理解许多。见 https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#ayes
- [Enchanted Oracle](https://connor-mccartney.github.io/cryptography/other/EnchantedOracle-UofTCTF2025)
    - aes cbc padding oracle attack，但目标是伪造已知明文的密文。关键是要倒着来推：随便生成16个字节当密文块后通过oracle获得其明文，然后异或期望明文，就能得到下一个密文块。重复此步骤即可
    - 看[另一篇wp](https://merkletr.ee/ctf/2025/uoftctf/aescbc)时发现竟然有人写过Padding Oracle Attack的论文： https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf
    - 好吧这个知识点早就被研究烂了，相关的python库都有几个： https://github.com/Dvd848/CTFs/blob/master/2018_picoCTF/Magic%20Padding%20Oracle.md
    - 个人做法： **Enchanted Oracle**
- [Timed AES](https://www.da.vidbuchanan.co.uk/blog/uoftctf-timed-aes.html)
    - 错误的AES实现导致的side channel attack。问题出在aes的sub_bytes_inv用了下面的代码：
    ```c
    for (size_t i = 0; i < 256; i++)
    {
        if (sbox[i] == num) return i;
    }
    ```
    题目还提供了每次运行后的纳秒级用时记录。可以看出for循环的运行次数等同于`inverse_sbox[num]`，两者间有相关性。可以用[numpy.corrcoef](https://numpy.org/doc/2.1/reference/generated/numpy.corrcoef.html)找到相关性最好的byte
    - aes有10轮，每轮都会调用subBytesInv，而且每轮的expandKey都不一样，所以都会有影响。不过wp说correlation function会将这些内容看作噪音忽略掉
    - AES/DES轮密钥逆向工具： https://github.com/SideChannelMarvels/Stark
    - 官方wp： https://github.com/UofTCTF/uoftctf-2025-chals-public/blob/master/timed-aes 。原理一样不过脚本要复杂些

## Z3使用

开一个新的合集，用于记录那些和z3有关的crypto题目。但是优先级较低，记录在这里的题不能包含上面的RSA，格等内容（除非两者都有）

- [rps-casino](https://7rocky.github.io/en/ctf/other/dicectf/rps-casino/)
    - LFSR的另类实现（选取异或的bit时使用位移，一次更新4轮，输出4个bit）,以及其对应的z3实现
    - 模运算通常会破坏线性。例如本题输出的4bit的数字会模3，导致只能用z3强行解初始state
    - 其他wp： https://github.com/quasar098/ctf-writeups/tree/main/dicectf-2024/rps-casino 。bitvec不知为何无法使用，便用bool类型代替
- [Quantum L3ak](https://github.com/lrnzsir/ctf-writeups/tree/main/L3akCTF%202024/Quantum%20L3ak)
    - python qiskit量子计算+z3实现MersenneTwister并预测Random生成的随机数

## Math

记录数学题。可以预测这个分类一年都积攒不了几道题……

- [V for Vieta](https://berliangabriel.github.io/post/ductf-2024/)
	- 这题要求找到满足 $\frac{a^2 + ab + b^2}{2ab + 1}=k$ 的(a,b)对。结果wp就说了句[Vieta jumping](https://en.wikipedia.org/wiki/Vieta_jumping) （韦达跳跃）就没了……看了眼百科，在Constant descent Vieta jumping处看出了端倪，相关的[Vieta's formula](https://en.wikipedia.org/wiki/Vieta%27s_formulas) （韦达定理）似乎也有用。尝试把wp讲得更详细点：
	1. 首先把式子写成a的方程： <br>
	$\frac{a^2 + ab + b^2}{2ab + 1}=k$ <br>
	$a^2 + ab + b^2=k(2ab + 1)$ <br>
	$a^2+ab+b^2-2kab-k=0$ <br>
	$a^2+(b-2kb)a+(b^2-k)=0$ <br>
	2. 根据韦达定理，假如其中一个根是a，那么另一个根是 $a'=-\frac{b-2kb}{1}-a=-(b-2kb)-a$
	3. a=0的情况下，容易看出 $b=\sqrt{k}$ ，以r代替。此时替换新a''=b， $b'=a'=-(r-2kr)-a=-(1-2k)r-a$ 。新出现的(a'',b')也是满足条件的一组(a,b)值。继续这么推下去就能拿到无数组想要的值
	4. 百科里用这个方法递减可能的解，直到最小。为啥我们这越来越大？因为百科里默认0 < $x^2$ < b < a，这里我们初始b > a，懒得证明（菜）但是感觉这样替换结果越来越大
	5. 为啥可以把a''换成b，b'换成a'？这里看原始式子就简单得多， $\frac{a^2 + ab + b^2}{2ab + 1}=k$ 里明显a和b的值交换不影响k
- [Kleinvieh 2](https://mindcrafters.xyz/writeups/nullconctf-2025-crypto)
    - 好的其他部分我都明白，唯独卡在不知道怎么用数学表示同一条message重复n次。答案是，将长度为S的message重复一次等同于将message乘上 $10^S+1$

## 其他

1. Crypto库根据已有信息构建私钥并解密

如果给出的是flag.enc和public.key这种形式的题目，平时的方法可能会解出乱码，需要利用私钥文件来解密。
```python
from Crypto.PublicKey import RSA
import gmpy2
import base64
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
p=0
q=0
n=p*q
e=65537
phi=(p-1)*(q-1)
d=gmpy2.invert(e,phi)
with open("flag.enc",'rb') as f:
    c_bytes=f.read()
rsa_components=(n,e,int(d),p,q)
arsa=RSA.construct(rsa_components)
rsakey=RSA.importKey(arsa.exportKey())
rsakey=PKCS1_OAEP.new(rsakey)
decrypted=rsakey.decrypt(c_bytes)
print(decrypted)
```

3. python Crypto库读取公钥
```python
from Crypto.PublicKey import RSA
key1=RSA.importKey(open('public1.pub').read())
print(f"n={key1.n}\ne={key1.e}")
```
4. 离散对数问题（Discrete Logarithm ProblemDLP）。一般的对数 $a^b=c$ ，求得b可以直接用 $log_a(c)$ 。但是在加上模运算的情况下就要使用离散对数了。 $a^b=c\mod d$ ，使用sympy的离散对数函数。

```python
m = 0
c = 0
n=0
from Crypto.Util.number import *
import sympy
x=sympy.discrete_log(n,c,m)  #参数顺序：sympy.discrete_log(模数，结果，底数)
print(long_to_bytes(x))
```
也可用[网站](https://www.alpertron.com.ar/DILOG.HTM)计算. https://github.com/hollowcrust/TJCTF-2023/blob/main/crypto.md#2-ezdlp

或者sagemath脚本。
```py
#g^x = s mod p, find x
g =
s =
p =
Fp = IntegerModRing(p) 
g_modp = Fp(g) 
s_modp = Fp(s)
x = discrete_log(s_modp, g_modp)
print(x)
```

5. 海明码（汉明码）问题。例题：[H■m■i■g](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/moectf/Misc/H%E2%96%A0m%E2%96%A0i%E2%96%A0g.md)。今天又遇见一道题：[鸡藕椒盐味](https://buuoj.cn/challenges#%E9%B8%A1%E8%97%95%E6%A4%92%E7%9B%90%E5%91%B3)，也是海明码，没想到直接用当时写的脚本就能出答案。
```python
import hashlib
def hamming_correct(bitblock):
    result=''
    for t in range(4):
        bits=[bit for i,bit in enumerate(bitblock) if i&(1<<t)]
        if bits.count(1)%2==0:
            result+='0'
        else:
            result+='1'
    return int(result[::-1],2)
code=[1,1,0,0,1,0,1,0,0,0,0,0]
wrong_pos=hamming_correct(code)
code[wrong_pos]=int(not code[wrong_pos])
c=''.join([str(i) for i in code])
md=hashlib.md5()
md.update(c.encode("utf8"))
flag = md.hexdigest()
print(flag)                   
```
以及其他人的脚本：[PARtly bintastic](https://github.com/Cryptonite-MIT/niteCTF-2023/tree/main/crypto/partly_bintastic)

6. rsa题目时要看清楚密文即证书的格式。有些题密文和n等信息会以文件的形式给出，有可能是bytes形式，可以直接long_to_bytes，但也有可能是base64编码后的形式。解密前注意这些细节，能省去很多怀疑人生的时间。
7. polybius方阵密码爆破。常见的方阵密码用数字1，2，3，4，5表示，不过任何5个元素都能表示polybius密文，比如aeiou。这里有个思维惯性，可能会下意识认为方阵排列形式就是aeiou，但可能并不是这样，aioue也不是不行。不同的排列组合会影响解密的结果。故需要爆破，利用下面的脚本：

```python
import itertools
s="aeoiu"
ciper="ouauuuoooeeaaiaeauieuooeeiea"
sumresult=[]
numsumresult=[]
for i in itertools.permutations(s,5):#找出所有全排列
    sumresult.append("".join(i))
for i in sumresult:
    temp=""
    for j in ciper:
        temp+=str(i.index(j)+1)
    numsumresult.append(temp)
for i in numsumresult:
    flag=""
    for j in range(0, len(i),2):
        xx=(int(i[j])-1)*5+int(i[j+1])+96
        if xx>ord('i'):
            xx+=1
        flag+=chr(xx)
    print(flag)
```

来源:[[BJDCTF2020]Polybius](https://blog.csdn.net/m0_52727862/article/details/119043003)

8. 猪圈密码+动物密码。例题:[[NPUCTF2020]Classical Cipher](https://blog.csdn.net/m0_52727862/article/details/119043219)
9. [四方密码](https://zh.wikipedia.org/zh-my/%E5%9B%9B%E6%96%B9%E5%AF%86%E7%A2%BC)，可用[网站](http://www.metools.info/code/four-square244.html)进行解密。例题:[四面八方](https://blog.csdn.net/LingDIHong/article/details/112684896)
10. 伪代码题。题目会给出伪代码文件，要求写出其任意代码实现。如：

```
get buf unsign s[256]
get buf t[256]
we have key:whoami
we have flag:????????????????????????????????

for i:0 to 256
    set s[i]:i

for i:0 to 256
    set t[i]:key[(i)mod(key.lenth)]

for i:0 to 256
    set j:(j+s[i]+t[i])mod(256) //前面从来没有出现过j，没出现过的实现时默认设为0
        swap:s[i],s[j]
//下面这段开始执行前要把i和j都归0，python里面for循环影响计数变量后会影响外面的
for m:0 to 38
    set i:(i + 1)mod(256)
    set j:(j + S[i])mod(256)
    swap:s[i],s[j]
    set x:(s[i] + (s[j]mod(256))mod(256))
    set flag[m]:flag[m]^s[x]

fprint flagx to file
```

这种题一般来说不难，重点是要注意把变量清0。此题脚本：

```python
s=[]
t=[]
key="whoami"
with open('file.txt','rb') as f:
    cipher=f.read()
for i in range(256):
    s.append(i)
for i in range(256):
    t.append(ord(key[i%len(key)]))
j=0
for i in range(256):
    j=(j+s[i]+t[i])%256
    s[i],s[j]=s[j],s[i]
i=j=0
for m in range(38):
    i=(i+1)%256
    j=(j+s[i])%256
    s[i],s[j]=s[j],s[i]
    x=(s[i]+(s[j]%256))%256
    print(chr(cipher[m]^s[x]),end='')
```

11. python解密aes。题目:[[ACTF新生赛2020]crypto-aes](https://buuoj.cn/challenges#[ACTF%E6%96%B0%E7%94%9F%E8%B5%9B2020]crypto-aes)

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
enc_flag=b'\x8c-\xcd\xde\xa7\xe9\x7f.b\x8aKs\xf1\xba\xc75\xc4d\x13\x07\xac\xa4&\xd6\x91\xfe\xf3\x14\x10|\xf8p'
output=91144196586662942563895769614300232343026691029427747065707381728622849079757
key=long_to_bytes(output)[:16]*2
iv=long_to_bytes(bytes_to_long(long_to_bytes(output)[16:])^bytes_to_long(key[16:]))
aes = AES.new(key,AES.MODE_CBC,iv)
flag = aes.decrypt(enc_flag)
print(flag)
```

12. Many Time pad攻击（利用空格异或其他字符会转大小写的特性）。例题:[不止一次](../../CTF/moectf/2022/Crypto/不止一次.md)
13. 希尔密码（hill）。例题:[[UTCTF2020]hill](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Crypto/%5BUTCTF2020%5Dhill.md)
14. 秘密共享（Secret sharing）的Asmuth-Bloom方案。例题:[[AFCTF2018]花开藏宝地](../../CTF/BUUCTF/Crypto/[AFCTF2018]花开藏宝地.md)
15. ecc（椭圆曲线加密算法）入门。[链接](https://www.pediy.com/kssd/pediy06/pediy6014.htm)。
16. 伏羲六十四卦解密脚本。

[来源及题目](https://blog.csdn.net/weixin_44110537/article/details/107494966)

```python
s='升随临损巽睽颐萃小过讼艮颐小过震蛊屯未济中孚艮困恒晋升损蛊萃蛊未济巽解艮贲未济观豫损蛊晋噬嗑晋旅解大畜困未济随蒙升解睽未济井困未济旅萃未济震蒙未济师涣归妹大有'
dic={'坤': '000000', '剥': '000001', '比': '000010', '观': '000011', '豫': '000100', '晋': '000101', '萃': '000110', '否': '000111', '谦': '001000', '艮': '001001', '蹇': '001010', '渐': '001011', '小过': '001100', '旅': '001101', '咸': '001110', '遁': '001111', '师': '010000', '蒙': '010001', '坎': '010010', '涣': '010011', '解': '010100', '未济': '010101', '困': '010110', '讼': '010111', '升': '011000', '蛊': '011001', '井': '011010', '巽': '011011', '恒': '011100', '鼎': '011101', '大过': '011110', '姤': '011111', '复': '100000', '颐': '100001', '屯': '100010', '益': '100011', '震': '100100', '噬嗑': '100101', '随': '100110', '无妄': '100111', '明夷': '101000', '贲': '101001', '既济': '101010', '家人': '101011', '丰': '101100', '离': '101101', '革': '101110', '同人': '101111', '临': '110000', '损': '110001', '节': '110010', '中孚': '110011', '归妹': '110100', '睽': '110101', '兑': '110110', '履': '110111', '泰': '111000', '大畜': '111001', '需': '111010', '小畜': '111011', '大壮': '111100', '大有': '111101', '夬': '111110', '乾': '111111'}
li=[]
k=0
for i in range(len(s)):
    if k ==1:
        k=0
        continue
    try:
        li.append(dic[s[i]])
    except:
        t=''
        t=t+s[i]+s[i+1]
        li.append(dic[t])
        k=1
ss=''.join(li)
res=''
for i in range(0,len(ss),8):
    res+=chr(eval('0b'+ss[i:i+8]))
print(res)
```

17.  [梅森旋转算法](https://liam.page/2018/01/12/Mersenne-twister/)（Mersenne Twister Algorithm，简称 MT）相关[考点](https://badmonkey.site/archives/mt19937.html)。
18.  python的随机数（如random.getrandbits()）基于梅森旋转算法MT。MT19937能做到生成 1≤k≤623 个32位均匀分布的随机数，如果我们获取了624个，解下来的随机数就能用[randCrack](https://github.com/tna0y/Python-random-module-cracker)预测了。例题:[[GKCTF 2021]Random](https://blog.csdn.net/m0_57291352/article/details/119655082)
19.  Many time pad攻击（利用[汉明距离](https://baike.baidu.com/item/%E6%B1%89%E6%98%8E%E8%B7%9D%E7%A6%BB/475174)。

[题目及来源](https://codeleading.com/article/68135872581/)

```python
import string
from binascii import unhexlify
from itertools import *


def bxor(a, b):  # xor two byte strings of different lengths
    if len(a) > len(b):
        return bytes([x ^ y for x, y in zip(a[:len(b)], b)])
    else:
        return bytes([x ^ y for x, y in zip(a, b[:len(a)])])


def hamming_distance(b1, b2):
    differing_bits = 0
    for byte in bxor(b1, b2):
        differing_bits += bin(byte).count("1")
    return differing_bits


def break_single_key_xor(text):
    key = 0
    possible_space = 0
    max_possible = 0
    letters = string.ascii_letters.encode('ascii')
    for a in range(0, len(text)):
        maxpossible = 0
        for b in range(0, len(text)):
            if (a == b):
                continue
            c = text[a] ^ text[b]
            if c not in letters and c != 0:
                continue
            maxpossible += 1
        if maxpossible > max_possible:
            max_possible = maxpossible
            possible_space = a
    key = text[possible_space] ^ 0x20
    return chr(key)


salt = "WeAreDe1taTeam"
si = cycle(salt)
b = unhexlify(
    b'hex')
plain = ''.join([hex(ord(c) ^ ord(next(si)))[2:].zfill(2) for c in b.decode()])
b = unhexlify(plain)
print(plain)

normalized_distances = []

for KEYSIZE in range(2, 40):
    n = len(b) // KEYSIZE
    list_b = []
    for i in range(n - 1):
        list_b.append(b[i * KEYSIZE: (i + 1) * KEYSIZE])

    normalized_distance = 0
    for i in range(len(list_b) - 1):
        normalized_distance += hamming_distance(list_b[i], list_b[i + 1])
    normalized_distance = float(normalized_distance) / (KEYSIZE * (len(list_b) - 1))

    normalized_distances.append(
        (KEYSIZE, normalized_distance)
    )
normalized_distances = sorted(normalized_distances, key=lambda x: x[1])
print(normalized_distances)

for KEYSIZE, _ in normalized_distances[:5]:
    block_bytes = [[] for _ in range(KEYSIZE)]
    for i, byte in enumerate(b):
        block_bytes[i % KEYSIZE].append(byte)
    keys = ''
    try:
        for bbytes in block_bytes:
            keys += break_single_key_xor(bbytes)
        key = bytearray(keys * len(b), "utf-8")
        plaintext = bxor(b, key)
        print("keysize:", KEYSIZE)
        print("key is:", keys)
        s = bytes.decode(plaintext)
        print(s)
    except Exception:
        continue
```

21. 通过分析重合指数破解类似维吉尼亚的密码。

[题目及来源](https://blog.csdn.net/weixin_44110537/article/details/107947158)

```python
#重合指数的应用:
import gmpy2
c=open('cipher','r').read()
best_index=0.065
sum=0
dic_index={'a': 0.08167,'b': 0.01492,'c': 0.02782,'d':0.04253,'e': 0.12702,'f':0.02228,'g': 0.02015,'h':0.06094,'i':0.06966,'j':0.00153,'k':0.00772,'l':0.04025,'m':0.02406,'n':0.06749,'o':0.07507,'p':0.01929,'q':0.00095,'r':0.05987,'s':0.06327,'t':0.09056,'u':0.02758,'v':0.00978,'w':0.02360,'x':0.00150,'y':0.01974,'z':0.00074}
def index_of_coincidence(s):
    '''
    计算字符串的重合指数(所有字母出现频率的平方和)
    :param s: 给定字符串
    :return: 重合指数
    '''
    alpha='abcdefghijklmnopqrstuvwxyz'#给定字母表
    freq={}#统计字母频率(frequency)
    for i in alpha:
        freq[i]=0
    #先全部初始化为0
    for i in s:
        freq[i]=freq[i]+1
    #统计频率
    index=0
    for i in alpha:
        index = index + (freq[i] * (freq[i] - 1)) / (len(s) * (len(s) - 1))
    return index
def index_of_coincidence_m(s):
    '''
    计算明文s中的各字母的频率与英文字母中的频率的吻合程度.
    :param s:明文s
    :return:吻合程度
    '''
    alpha = 'abcdefghijklmnopqrstuvwxyz'  # 给定字母表
    freq = {}  # 统计字母频率(frequency)
    for i in alpha:
        freq[i] = 0
    # 先全部初始化为0
    for i in s:
        freq[i] = freq[i] + 1
    # 统计频率
    index = 0
    for i in alpha:
        index = index + freq[i] / len(s) * dic_index[i]
    return index
def get_cycle(c):
    '''
    求出最符合统计学的m,n的最小公共周期,方法为通过爆破足够大的周期样本,观察成倍出现的周期.
    计算方法为解出每一个子密文段的重合指数和然后求平均值 再与最佳重合指数相减 误差在0.01以内.
    :param c: 密文
    :return: 公共周期列表
    '''
    cycle=[]
    for i in range(1,100):
        average_index=0#平均重合指数初始化为0
        for j in range(i):
            s = ''.join(c[j+i*x] for x in range(0,len(c)//i))
            index=index_of_coincidence(s)
            average_index+=index
        average_index=average_index/i-best_index
        if abs(average_index)<0.01:
            cycle.append(i)
    return cycle
cycle=get_cycle(c)
print(cycle)#[6, 12, 18, 24, 30, 36, 42, 48, 54, 60, 66, 72, 78, 84, 90, 96]

#通过计算得到cycle都是6的倍数,因此cycle最小很有可能为6

cycle=6

#开始爆破keys

def decrypt(c,i,j):
    '''
    通过i,j解出与之相对应的密文段
    :param c: 密文段
    :param i:与明文相乘的key
    :param j: 位移j(维吉尼亚密码)
    :return: 明文段
    '''
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    m=''
    for x in c:
        m+=alpha[((alpha.index(x)-j)*gmpy2.invert(i,26))%26]
    return m
def get_key(c):
    '''
    得到某一密文段的单个字符key i j
    方法为暴力枚举所有的可能性,找到最符合统计学规律的 i,j 即该密文段的重合指数与最佳重合指数误差小于0.01
    :param c: 密文段
    :return: i,j
    '''
    for i in range(26):
        if  gmpy2.gcd(i,26)!=1:#i对26的逆元不只一个,造成明文不唯一,因此不符合条件.
            continue
        for j in range(26):
            m=decrypt(c,i,j)
            index=index_of_coincidence_m(m)
            if abs(index-0.065)<0.01:
                return (i,j)
def get_all_key(s,cycle):
    '''
    得到一个周期内的所有的密文段的key
    :param s: 原密文
    :param cycle: 周期
    :return: 无
    '''
    for i in range(cycle):
        temps=''.join([s[i+x*cycle] for x in range(0,len(s)//cycle)])
        print(get_key(temps))
get_all_key(c,6)
# (19, 10)
# (7, 9)
# (23, 3)
# (19, 24)
# (7, 14)
# (23, 15)
#此时我们大致可以推测出:keya=[19,7,23],keyb=[10,9,3,24,14,15],因此根据题目给的式子,我们就可以还原出明文了.
plaintext=''
keya=[19,7,23]
keyb=[10,9,3,24,14,15]
len_a=len(keya)
len_b=len(keyb)
alpha='abcdefghijklmnopqrstuvwxyz'
for i in range(len(c)):
    plaintext+=alpha[((alpha.index(c[i])-keyb[i%len_b])*gmpy2.invert(keya[i%len_a],26))%26]
print(plaintext)
```
22. lfsr爆破mask。例题:[LittLe_FSR](../../CTF/moectf/2022/Crypto/LittLe_FSR.md)
23. [Schmidt-Samoa 密码体系](https://www.ruanx.net/schmidt-samoa/)。
24. 求斐波那契数列大数取模值可利用[皮萨诺周期](https://blog.csdn.net/caozhk/article/details/53407845)。例题:[[INSHack2019]Crunchy](https://www.bilibili.com/read/cv13950329)
25. [希尔密码](https://hstar.me/2020/08/hill-cipher-study/)（hill cipher，线性替换密码）。例题：[hill-hard](../../CTF/LA%20CTF/Crypto/hill-hard.md)
26. [subgroup confinement attack on Diffie-Hellman](https://crypto.stackexchange.com/questions/27584/small-subgroup-confinement-attack-on-diffie-hellman)。链接证明里涉及的[定理](/笔记/Crypto/%E6%8A%BD%E8%B1%A1%E4%BB%A3%E6%95%B0/%E6%8A%BD%E8%B1%A1%E4%BB%A3%E6%95%B0%EF%BC%881-29%EF%BC%89.md).

[例题及来源](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/crypto/Compromised/writeup.md)

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad


p = "prime"
g = 65537
prime_fac = ["factors"]
w = prime_fac[1]
k = (p-1)//w
ct = bytes.fromhex('0123456789abcdef')
iv = ct[:AES.block_size]
ct = ct[AES.block_size:]

# generator for subgroup
sub_gen = pow(g, k, p)
m = 1
while m <= w:
    key = pow(sub_gen, m, p)
    key = sha256(long_to_bytes(key)).digest()
    print('Key:', key.hex(), end='\r')
    aes = AES.new(key, AES.MODE_CBC, iv)
    try:
        flag = aes.decrypt(ct)
        flag = unpad(flag, AES.block_size).decode()
        if flag.startswith('p_ctf{'):
            break
    except ValueError:
        pass
    finally:
        m += 1

print('Key:', key.hex())
print('Flag:', flag)
```

27. md5算法的[特性](https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities)：

```
if h(a) = h(b),
then h(a||c) = h(b||c)
where, a, b and c are strings and || is concatenation
```

例题：[Broken Hash](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/crypto/BrokenHash/writeup.md)

28. [CustomAESed](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/crypto/customAESed/writeup.md)
- AES的[CTR模式](https://wumansgy.github.io/2018/11/03/AES%E7%9A%84CTR%E6%A8%A1%E5%BC%8F%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86%E8%AF%A6%E8%A7%A3/)的模拟加密与解密。

```python
#解密
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import unpad
from hashlib import sha256

ct = "ciphertext"
iv = ct[:12]
ct = ct[12:]
block_size = AES.block_size
ctr = Counter.new(nbits=32, prefix=iv[:8], suffix=iv[8:], initial_value=1)
key = sha256("128bit_secretkey".encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
pt = cipher.decrypt(ct)
pt = unpad(pt, block_size)
print(pt.decode())
```

- 汉明码（[hamming code](https://en.wikipedia.org/wiki/Hamming_code#General_algorithm)）的加密与解密

```python
from Crypto.Util.number import *
from math import log2

# pt is same as in above code
bin_text = pt.decode()
txt_len = len(bin_text)
decoded_text = ''
parity_bits = ''
n_parity_bits = int(log2(txt_len))+1
for x in range(n_parity_bits):
    parity_bit = 0
    for bit in range(1, txt_len+1):
        if bit & (2**x) == 2**x:
            parity_bit ^= int(bin_text[bit-1])
    parity_bits = str(parity_bit) + parity_bits
err_pos = int(parity_bits, 2)
if err_pos != 0:
    err_bit = '1' if bin_text[err_pos-1]=='0' else '0'
    bin_text = bin_text[:err_pos-1] + err_bit + bin_text[err_pos:]
x = 0
for bit in range(1, txt_len+1):
    if bit == (2**x):
        x += 1
        continue
    decoded_text += bin_text[bit-1]
decoded_text = long_to_bytes(int(decoded_text, 2))
print(decoded_text.decode())
```

- 获取AES的[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)模式下的GMAC（Galois Message Authentication Code）。使用GCM的AES加密即可获得GMAC。

```python
from Crypto.Cipher import AES
from Crypto.Util.number import *
from hashlib import sha256
from base64 import b64encode

key = sha256("128bit_secretkey".encode()).digest()
iv = ""
cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

# decoded_text is obtained in the above code
ct, tag = cipher.encrypt_and_digest(decoded_text)
encoded_tag = b64encode(tag)
print(encoded_tag.decode())
```

29. [Blocks and Boxes](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/crypto/Blocks_and_Boxes/writeup.md)
- propagating cipher block chaining（[PCBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC))）
- Caesar's box cipher(特征是密文的长度为平方数)
30. AES侧信道攻击（power trace analysis）。使用相同密钥加密不同已知明文，通过测量CPU的能源消耗推断出密钥（已知密文也可以）。下面为一些相关链接。
- [Breaking AES with side channel analysis](https://www.youtube.com/watch?v=whhM_P7xMMU)
- [DPA & CPA applied on AES Attack](https://yan1x0s.medium.com/side-channel-attacks-part-2-dpa-cpa-applied-on-aes-attack-66baa356f03f)
- [CPA的python实现](https://teamrocketist.github.io/2018/11/14/Crypto-SquareCtf-2018-C4-leaky-power/)。

如果题目给出16进制的明文和列表形式的trace，就可以直接用下面的脚本：

```python
import numpy as np
textins=[]
traces=[]
num_trace=339
for i in range(num_trace):
    path=f"traces/trace{i}.txt"
    with open(path) as f:
        d=f.read().split('\n')
        plain=bytes.fromhex(d[0])
        textins.append(plain)
        traces.append(eval(d[1]))
HW = [bin(n).count("1") for n in range(0,256)]

sbox=(
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16)

def intermediate(pt, keyguess):
    return sbox[pt ^ keyguess]

traces = np.array(traces)
pt = textins
bestguess = []
if bestguess == []:

    numtraces = np.shape(traces)[0]-1
    numpoint = np.shape(traces)[1]

    bestguess = [0]*16
    for bnum in range(0, 16):
        cpaoutput = [0]*256
        maxcpa = [0]*256
        for kguess in range(0, 256):
            #Initialize arrays & variables to zero
            sumnum = np.zeros(numpoint)
            sumden1 = np.zeros(numpoint)
            sumden2 = np.zeros(numpoint)

            hyp = np.zeros(numtraces)
            for tnum in range(0, numtraces):
                hyp[tnum] = HW[intermediate(pt[tnum][bnum], kguess)]


            #Mean of hypothesis
            meanh = np.mean(hyp, dtype=np.float64)

            #Mean of all points in trace
            meant = np.mean(traces, axis=0, dtype=np.float64)

            #For each trace, do the following
            for tnum in range(0, numtraces):
                hdiff = (hyp[tnum] - meanh)
                tdiff = traces[tnum,:] - meant

                sumnum = sumnum + (hdiff*tdiff)
                sumden1 = sumden1 + hdiff*hdiff 
                sumden2 = sumden2 + tdiff*tdiff

            cpaoutput[kguess] = sumnum / np.sqrt( sumden1 * sumden2 )
            maxcpa[kguess] = max(abs(cpaoutput[kguess]))


        bestguess[bnum] = np.argmax(maxcpa)

    key = ''
    for b in bestguess: 
        key += "%02x"%b
    print("Best Key Guess: %s" % key)
```
31. [Classic Game Theory](http://itsvipul.com/writeups/Trellix_Hax_2023/GameTheory.html)
- MD5函数的默认初始状态如下：

```
A = 0x67452301
B = 0xefcdab89
C = 0x98badcfe
D = 0x10325476
```

如果使用的初始状态不同，md5的结果也会不同。可以通过修改[脚本](https://github.com/Utkarsh87/md5-hashing/blob/master/md5.py)里的初始值来获取自定义的md5函数。
- 彩虹表攻击（rainbow table attack）。本质上还是爆破出哈希值的全部可能性后查表。
32. [DSA](https://github.com/xalanq/jarvisoj-solutions/blob/master/crypto/DSA.md)
- DSA签名算法[介绍](https://ctf-wiki.org/crypto/signature/dsa/#k_1)
- 随机密钥k共享攻击脚本：

```python
from Crypto.PublicKey import DSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA1
import gmpy2

pubkey_file = 'dsa_public.pem'
file_1 = ['./packet3/message3', './packet3/sign3.bin']
file_2 = ['./packet4/message4', './packet4/sign4.bin']

pubkey = DSA.import_key(open(pubkey_file, 'r').read())

y = pubkey.y
g = pubkey.g
p = pubkey.p
q = pubkey.q

print('y =', y)
print('g =', g)
print('p =', p)
print('q =', q)

def get_rs(signature):
    der_seq = DerSequence().decode(signature, strict=True)
    return int(der_seq[0]), int(der_seq[1])

hm1 = int(SHA1.new(open(file_1[0], 'rb').read()).hexdigest(), 16)
hm2 = int(SHA1.new(open(file_2[0], 'rb').read()).hexdigest(), 16)
r, s1 = get_rs(open(file_1[1], 'rb').read())
_, s2 = get_rs(open(file_2[1], 'rb').read())

print('r =', r)
print('hm1 =', hm1)
print('s1 =', s1)
print('hm2 =', hm1)
print('s2 =', s2)

print('cracking')

ds = s2 - s1
dhm = hm2 - hm1
k = gmpy2.mul(dhm, gmpy2.invert(ds, q))
k = gmpy2.f_mod(k, q)
tmp = gmpy2.mul(k, s1) - hm1
x = tmp * gmpy2.invert(r, q)
x = gmpy2.f_mod(x, q)
print('x =', x)
```
33. 进制转换。

- base47（已知编码表）解码
```python
from Crypto.Util.number import long_to_bytes
def base47(cipher,dic):
    print(long_to_bytes(sum([dic.index(cipher[i]) * (len(dic) ** (len(cipher) - i - 1)) for i in range(len(cipher))])))
```
- base4爆破解码
```python
import itertools
from Crypto.Util.number import *
s=''
t = []
for k in itertools.permutations('0123'):
    m = ''
    for i in s:
        if i == t[0]:
            m += k[0]
        elif i == t[1]:
            m += k[1]
        elif i == t[2]:
            m += k[2]
        elif i == t[3]:
            m += k[3]
    m = long_to_bytes(int(m, 4))
    if b'flag' in m:
        print(m)
        break
```
- base64爆破解码
  - 根据base64的原理，base64是一种把二进制值变成文本数据的方式。在输入是文本的情况下，3个原始字符对应的就是4个base64编码后的字符。所以可以对编码后的base64字符4个4个的进行爆破，只要还原出来的3个原始字符在可见字符范围内即可。出来的结果需要手动重组。
```python
import base64
import itertools
x=""
def check_4(base64_part):
    _temp=[]
    results=[]
    for i in range(4):
        if base64_part[i].isalpha():
            _temp.append((base64_part[i].upper(),base64_part[i].lower()))
        else:
            _temp.append((base64_part[i],base64_part[i]))
    n=map(tuple, itertools.product(_temp[0],_temp[1],_temp[2],_temp[3]))
    for i in set(n):
        s='%s%s%s%s'%i
        try:
            result=base64.b64decode(s.encode()).decode()
            if result.isprintable():
                results.append(result)
        except:
            pass
    return(results)
l=[]
for i in range(int(len(x)/4)):
    l.append(check_4(x[i*4:i*4+4]))
for i in l:
    print(i)
```

34. [shamir秘密共享](https://blog.sagiri.tech/index.php/archives/55/)（secret sharing）[解密脚本](https://github.com/adviksinghania/shamir-secret-sharing/blob/main/shamir_secret_galois.py)。以下是简略版，仅保留原脚本的解密功能。

```python
class ShamirSecret:
    def __init__(self) -> None:
        pass
    def extended_gcd(self, a, b):
        """Extended Euclidean Algorithm."""
        x = 0
        last_x = 1
        y = 1
        last_y = 0
        while b != 0:
            quot = a // b
            a, b = b, a % b
            x, last_x = last_x - quot * x, x
            y, last_y = last_y - quot * y, y

        return last_x, last_y

    def galois_div(self, num, den, p):
        """
        Division in integers modulus p means finding the inverse of the
        denominator modulo p and then multiplying the numerator by this
        inverse.

        Inverse of an integer can be found using the Extended Euclidean Algorithm.
        (Note: inverse of A is B such that A*B % p == 1)

        Compute num / den modulo prime p

        To explain what this means, the return value will be such that the
        following is true: den * galois_div(num, den, p) % p == num

        Parameters
        ----------
        num: int
            Numerator
        den: int
            Denominator
        p: int
            Prime Number

        """
        inv, _ = self.extended_gcd(den, p)
        return num * inv

    def reconstruct(self, rand_shares, prime) -> int:
        """
        Reconstruct the secret with random shares and a prime.

        Parameters
        ----------
        rand_shares: tuple
            Containing pairwise tuples of random shares.
        prime: int
            The prime number for the galois field.

        Returns
        -------
        sigma: int
            The reconstructed secret

        Example
        -------
        >>> s.reconstruct(s.random_shares(), s.prime)
        1234

        """
        l = len(rand_shares)  # length: number of random shares
        x_s = tuple(map(lambda x: x[0], rand_shares))  # x values of shares
        y_s = tuple(map(lambda x: x[1], rand_shares))  # y values of shares

        def PI(vars):  # product of inputs (PI)
            acc = 1
            for v in vars:
                acc *= v

            return acc

        nume = tuple()
        deno = tuple()
        for j in range(l):
            nume += (PI(x_s[m] for m in range(l) if m != j), )
            deno += (PI(x_s[m] - x_s[j] for m in range(l) if m != j), )

        den = PI(deno)
        num = sum(self.galois_div(nume[i] * den * y_s[i] % prime, deno[i], prime) for i in range(l))
        sigma = (self.galois_div(num, den, prime) + prime) % prime

        return sigma
s = ShamirSecret()
shares=[]
prime=0
print('\nReconstructed Secret:', s.reconstruct(shares,prime))
```
35. 以下的java aes加密是最基础的默认情况，只设置了key：

```java
SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(), "AES");
Cipher cipher = Cipher.getInstance("AES");
cipher.init(1, secretKeySpec);
return Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes()));
```

那么默认IV为`00000000000000000000000000000`，模式为`AES/ECB/PKCS5Padding`

36. [SCAlloped_potatoes](https://hackmd.io/9_WE-HinSYqFQyKubluRuw?view#SCAlloped_potatoes---484---Medium)
- rsa side-channel attack：通过分析power trace恢复私钥。如果用matplotlib将powertrace的波形图绘制出来，会发现波形图的起伏对应私钥的各个字节（需要放大才能看到）。大概约10个数据为一组，高峰为1，中间值为0。
```python
power = eval(open("data.txt").read())

from matplotlib import pyplot as plt
plt.plot(power)
plt.show()

byt = []
msg = ""
for i in range(len(power)):
    if power[i] < 125: # low voltage seperator
        if byt:
            chunks = [] # condense groups of 10
            for j in range(0, len(byt), 10):
                chunks.append(sum(byt[j:j+10]) / 10)
            
            # walk chunks
            j = 0
            byt = "0"
            while j < len(chunks):
                if j < len(chunks) - 1 and chunks[j] < 175 and chunks[j + 1] > 175:
                    byt += "1"
                    j += 2
                else:
                    byt += "0"
                    j += 1
            msg += chr(int(byt, 2))
            byt = []
    else:
        byt.append(power[i]) 
print(msg)
```
37. [scherbius-machine](https://meashiri.github.io/ctf-writeups/posts/202312-pingctf/#scherbius-machine)
- enigma爆破。在知道大部分解密参数后可以尝试爆破完整参数
- https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#scherbius-machine
38. [quoted-printable](http://web.chacuo.net/charsetquotedprintable)编码。如果flag包含中文，cyberchef可能解密出乱码，用给的网站链接并把字符集选为utf8即可。
39. 当铺密码。
```python
s ='田由中人工大王夫井羊'
code=""
code = code.split(" ")
w = ''
for i in code:
    k=""
    for j in i:
       k+=str(s.index(j))
    w+=chr(int(k))
print(w)
```

40. [[NPUCTF2020]Mersenne twister](https://blog.csdn.net/weixin_44110537/article/details/108436309)
- 梅森旋转算法（Mersenne twister,mt73991伪随机）的爆破。若攻击者能获取624个寄存器状态，可以直接逆向。若不足则需要[爆破](https://liam.page/2018/01/12/Mersenne-twister/) 。
41. [PRNG](https://github.com/tamuctf/tamuctf-2023/tree/master/crypto/prng)
- 针对[linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator)（LCG）的预测攻击：给出prng的前十个数字（种子未知）。找出接下来的10个数字。使用[脚本](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/parameter_recovery.py)恢复初始参数，或者直接交互：
```python
#https://ctftime.org/writeup/12046
from pwn import *
class Rand:
    def __init__(self, seed,m,a,c):
        self.m = m
        self.a = a
        self.c = c
        self.seed = seed
        if seed % 2 == 0: # initial state must be odd
            self.seed += 1

    def rand(self):
        self.seed = (self.a * self.seed + self.c) % self.m
        return self.seed

r = remote("", 443)
r.recvline()

numbers = [int(r.recvline().rstrip()) for _ in range(10)]

from functools import reduce
from math import gcd

def egcd(a, b):
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modinv for {} does not exist'.format(a))
    return x % m

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)


def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

m, a, c = crack_unknown_modulus(numbers)
rand = Rand(numbers[-1], m, a, c)

for i in range(10):
    r.sendline(str(rand.rand()))
r.interactive()
```
- 类似题目：
    - [LCG](https://github.com/google/google-ctf/tree/master/2023/quals/crypto-lcg).这题只用了6个。详细解析文章： http://www.reteam.org/papers/e59.pdf
    - [Thermopolium](https://meashiri.github.io/ctf-writeups/posts/202307-odysseyctf/#thermopolium),脚本来自 https://tailcall.net/posts/cracking-rngs-lcgs/ 。发现5个竟然也可以（有人说理论上4个就够了）
    - [LCG](https://flocto.github.io/writeups/2023/deadsecctf/lcg-writeup/).无法求逆元时的特殊情况。如果想求 $x=a*b^{-1}\mod n$ 且 g=gcd(a,gcd(b,n)), can divide a,b,n by g and then take the inverse
42. 多种密码的python攻击脚本：https://github.com/jameslyons/python_cryptanalysis 。其中一个脚本可用于攻击变种维吉尼亚密码。
```python
from chall_patched import Vigenot as Vigenere
from itertools import permutations
from math import log10

ctext = 
ctext = ctext.upper()


# from https://github.com/jameslyons/python_cryptanalysis/blob/master/ngram_score.py
class ngram_score(object):
    def __init__(self,ngramfile,sep=' '):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
        self.ngrams = {}
        for line in open(ngramfile):
            key,count = line.split(sep) 
            self.ngrams[key] = int(count)
        self.L = len(key)
        self.N = sum(self.ngrams.values())
        #calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key])/self.N)
        self.floor = log10(0.01/self.N)

    def score(self,text):
        ''' compute the score of text '''
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text)-self.L+1):
            if text[i:i+self.L] in self.ngrams: score += ngrams(text[i:i+self.L])
            else: score += self.floor          
        return score

# https://github.com/jameslyons/python_cryptanalysis/blob/master/quadgrams.txt
qgram = ngram_score('quadgrams.txt')
# https://github.com/jameslyons/python_cryptanalysis/blob/master/trigrams.txt
trigram = ngram_score('trigrams.txt')


# from https://github.com/jameslyons/python_cryptanalysis/blob/master/break_vigenere.py
# keep a list of the N best things we have seen, discard anything else
class nbest(object):
    def __init__(self, N=1000):
        self.store = []
        self.N = N

    def add(self, item):
        self.store.append(item)
        self.store.sort(reverse=True)
        self.store = self.store[:self.N]

    def __getitem__(self, k):
        return self.store[k]

    def __len__(self):
        return len(self.store)


# init
N = 100
for KLEN in range(3, 20):
    rec = nbest(N)

    for i in permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 3):
        key = ''.join(i) + 'A' * (KLEN - len(i))
        pt = Vigenere(key).decipher(ctext)
        score = 0
        for j in range(0, len(ctext), KLEN):
            score += trigram.score(pt[j:j + 3])
        rec.add((score, ''.join(i), pt[:30]))

    next_rec = nbest(N)
    for i in range(0, KLEN - 3):
        for k in range(N):
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                key = rec[k][1] + c
                fullkey = key + 'A' * (KLEN - len(key))
                pt = Vigenere(fullkey).decipher(ctext)
                score = 0
                for j in range(0, len(ctext), KLEN):
                    score += qgram.score(pt[j:j + len(key)])
                next_rec.add((score, key, pt[:30]))
        rec = next_rec
        next_rec = nbest(N)
    bestkey = rec[0][1]
    pt = Vigenere(bestkey).decipher(ctext)
    bestscore = qgram.score(pt)
    for i in range(N):
        pt = Vigenere(rec[i][1]).decipher(ctext)
        score = qgram.score(pt)
        if score > bestscore:
            bestkey = rec[i][1]
            bestscore = score
    print(next_rec.store)
    print(bestscore, 'Vigenere, klen', KLEN, ':"' + bestkey.lower() + '",', Vigenere(bestkey).decipher(ctext).lower())
```
其中chall_patched为题目的变种维吉尼亚密码的解密实现。[Vigenot](https://github.com/tamuctf/tamuctf-2023/tree/master/crypto/vigenot)

43. AES-128省去mix_columns步骤时的攻击。mix_columns帮助AES打乱明文与密文之间的联系。如果省去这一步，会导致改动明文的1个字节也仅会改动密文的一个字节，那么就能通过与服务器交互获取每个位置明文对应的密文，从而破解密文。
```python
from pwn import *
import binascii

HOST = 
PORT = 

characters = string.ascii_letters + string.digits
# array for knowning where to unshift all the bytes after the operations
#注意改动一位明文对应着改动的密文不在同一个位置。下表记录了两者之间的对应关系，如改动1索引处的明文会导致索引9处的密文改变
unshift = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]

r = remote(HOST, PORT)

r.recvuntil(b'flag:\n')
ctxt = r.recvline().decode().strip()
print("Here's the challenge to decrypt: %s" % ctxt)

# create blocks of each alphanumeric character to encrypt
ptxt = ""
for letter in characters:
	ptxt += letter * 16 
ptxt = binascii.hexlify(ptxt.encode())

# send the plaintext and receive the encrypted version
r.recvuntil(b'hex:')
r.sendline(ptxt)
r.recvuntil(b'blocks:\n')
enc = r.recvline().decode().strip()

decrypted = [''] * 16
response = ""
for i in range(len(ctxt) // 2):
	byte_c = ctxt[2 * i : 2 * (i+1)]

	if i == 16:
		response = "".join(decrypted)
		
	char_ind = i % 16
	
	# iterate through all letters and check to find the matching one
	for j in range(len(characters)):
		index = 32 * j + 2 * char_ind
		byte_e = enc[index : index + 2]

		# if we have a match add the character to the right spot
		if byte_e == byte_c:
			decrypted[unshift[char_ind]] = characters[j]

response += "".join(decrypted)
print("Decrypted version: %s" % response)
r.recvuntil(b'answer?')
r.sendline(response.encode())
r.recvuntil(b'flag:\n')
flag = r.recvline().decode().strip()

r.close()

print("The flag is: %s" % flag)
```
[Shmooving](https://github.com/tamuctf/tamuctf-2023/tree/master/crypto/shmooving)

44. AES-128 ECB省去sub_bytes步骤时的攻击。S_BOX是AES中唯一不是线性的步骤，因此移去这一步等于可以用某个线性方程解出明文。此时AES就像仿射密码，可以用c=Ap+k表示（参考这篇[帖子](https://crypto.stackexchange.com/questions/20228/consequences-of-aes-without-any-one-of-its-operations)）。其中p是明文，c是密文，A需要自行计算。通过将征程AES移除add_round_key步骤然后加密128个输入，每个输入只有一位是1，其余是0。于是出来的128个密文就是A矩阵的列。接着用已知明文/密文对获取K，就能解出p了。完整脚本与例题:[Shmooving 2](https://github.com/tamuctf/tamuctf-2023/tree/master/crypto/shmooving-2)

45. [Shmooving 3](https://github.com/tamuctf/tamuctf-2023/tree/master/crypto/shmooving-3)
- 仅一轮的AES-128-ECB并省去mix_columns步骤。相关参考链接：
  - [One round of AES-128(有mix_columns)](https://crypto.stackexchange.com/questions/80743/one-round-of-aes-128)
  - [Low Data Complexity Attacks on AES](https://eprint.iacr.org/2010/633.pdf)
  - [The Effects of the Omission of Last Round's MixColumns on AES](https://www.sciencedirect.com/science/article/pii/S0020019010000335)
  - [On the security of inclusion or omission of MixColumns in AES cipher](https://www.semanticscholar.org/paper/On-the-security-of-inclusion-or-omission-of-in-AES-AlMarashda-Alsalami/e13e7d71861290e218b57307a09dda040978375f)
46. [DSA签名算法](https://ctf-wiki.org/en/crypto/signature/dsa/)需要在每次签名时使用不同的明文或不同的公钥。如果一直使用相同的公钥签名相同的明文，仅让私钥x随机变化，会导致攻击者获取多个签名后相互减，并取gcd即可获取的明文。[DSA?](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/cry/dsa)
47. [SHA256-CTR](https://github.com/AVDestroyer/CTF-Writeups/blob/main/sdctf2023/sha256-ctr.md)
- 使用sha256作为AES-CTR模式下counter的加密函数：有出现[hash length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack)的风险（很多hash类函数都有这个漏洞，包括md5）
  - hash length extension attack简述：已知Hash(message1)和message1的长度（无需确切知道message1的内容），且可控制接下来的message2。那么就能获得Hash(message1||message2)的值，其中||表示拼接两条信息。
  - 注意实施攻击时需要有特殊的padding。当计算Hash(secret)时，需要将secret的长度pad成56字节的倍数，接着再在后面加上8字节。遵循以下规则：
    - 先在secret后加上字节`\x80`
    - 然后使用`\x00`将secret的长度pad成56字节的倍数
    - 最后将secret的bit的长度（不包括添加的`\x80`和`\x00`）以大端转为长度为8bytes。例如32字节的secret就是256 bit长，转为byte就是`(256).to_bytes(8,'big')=\x00\x00\x00\x00\x00\x00\x01\x00`
  - 实现脚本：https://github.com/stephenbradshaw/hlextend .使用方法如下：
```py
sha = hlextend.new('sha256')
new_meta = sha.extend(b'content', b'known', length, hash)
#已知SHA256(secret)的结果hash，想要在secret+known的后面添上content并在secret的值未知的情况下获取SHA256(secret+known+content)，length为secret的长度。运行函数可得到一串值value，SHA256(secret+value)=SHA256(secret+known+content)
#脚本里有解释，另一道类似的例题：https://github.com/TJCSec/tjctf-2023-challenges/tree/main/crypto/drm-1
```
- 小端里的拼接字节技巧。假设有counter的计数为0x12345678，小端存储结果为0x78 0x56 0x34 0x12。如果想在0x12后面填上任意字节但是counter的值未知，可以用以下公式计算：`byte*(1 << (numBytes*8))`。byte表示想拼接的字节，numBytes表示counter的字节长度，或者想要位移的字节数（想在多少字节后面拼接）。例如想在刚刚counter后添加0x9a，加上`0x9a*(1 << (4*8))`即可。
- 如何用python subprocess.run配合hlextend与oracle交互：[forgeme](https://github.com/An00bRektn/CTF/tree/main/live_events/nahamcon_23/crypto_forgeme)
- 其他学习资源：
    - https://www.youtube.com/watch?v=6QQ4kgDWQ9w
    - https://www.synopsys.com/blogs/software-security/forging-sha-1-mac-using-length-extension-attack-python/
    - [ForgeMe 1](https://github.com/mohnad-0b/programming/tree/main/CTF/NahamConCTF_2023%20Crypto/FrogeMe%201):使用工具[HashPump](https://github.com/bwall/HashPump)
    - https://notateamserver.xyz/nahamcon-2023-crypto/#forgeme-1-and-2 :使用[hash_extender](https://github.com/iagox86/hash_extender)
48. [Forcing a file’s CRC to any value](https://www.nayuki.io/page/forcing-a-files-crc-to-any-value):该脚本可以将一个文件的crc改为任意值，通过在指定偏移处插入构造的字节（这些字节不一定可见）。用法：`python3 forcecrc32.py FileName ByteOffset NewCrc32Value`,表示将FileName对应文件的内容改为NewCrc32Value，构造用的字节插入在ByteOffset偏移处。
49. [Uniform](https://github.com/HeroCTF/HeroCTF_v5/tree/main/Crypto/Uniform)
- Mersenne Twister随机数预测。题目给出来自`random.uniform(0, 2**32-1)`的624个数字，要求预测第625个数字。注意由于uniform的输出是float，不能直接套用接收int的预测器。改动的脚本使用z3，已经在wp里了。
- uniform函数内部实现：`uniform(a, b)=a + (b - a)*random.random()`,那么可以经过简单的数学运算恢复random.random。有了random.random，就能恢复a>>5和b>>6了（下面给出的另一个版本脚本看得更清楚）。这两个数就是要提交进untwister的数。
```python
from pwn import *
from z3 import *
from random import Random
from itertools import count
from time import time
import logging

SYMBOLIC_COUNTER = count()

def r_float(n1, n2):
    """ https://github.com/deut-erium/RNGeesus
        get the two 32-bit random generated numbers to get 1 float number in the range of [0,1]
    """
    a = n1>>5
    b = n2>>6
    # 2**53 = 9007199254740992.0
    # 2**26 = 67108864
    return (a*67108864.0+b)*(1.0/9007199254740992.0)

def float_to_2_randnumber(f):
    """ do the reverse here of r_float function above
        converting float number back to the 2 random number (before bit shift)
    """
    n = int(f * 9007199254740992.0)
    return n // 67108864, n % 67108864

class Untwister:
    """ https://github.com/icemonster/symbolic_mersenne_cracker/blob/main/main.py
    """
    def __init__(self):
        name = next(SYMBOLIC_COUNTER)
        self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
        self.index = 0
        self.solver = Solver()

    #This particular method was adapted from https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/
    def symbolic_untamper(self, solver, y):
        name = next(SYMBOLIC_COUNTER)

        y1 = BitVec(f'y1_{name}', 32)
        y2 = BitVec(f'y2_{name}' , 32)
        y3 = BitVec(f'y3_{name}', 32)
        y4 = BitVec(f'y4_{name}', 32)

        equations = [
            y2 == y1 ^ (LShR(y1, 11)),
            y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
            y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
            y == y4 ^ (LShR(y4, 18))
        ]

        solver.add(equations)
        return y1

    def symbolic_twist(self, MT, n=624, upper_mask=0x80000000, lower_mask=0x7FFFFFFF, a=0x9908B0DF, m=397):
        '''
            This method models MT19937 function as a Z3 program
        '''
        MT = [i for i in MT] #Just a shallow copy of the state

        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = LShR(x, 1)
            xB = If(x & 1 == 0, xA, xA ^ a) #Possible Z3 optimization here by declaring auxiliary symbolic variables
            MT[i] = MT[(i + m) % n] ^ xB

        return MT

    def get_symbolic(self, guess):
        name = next(SYMBOLIC_COUNTER)
        ERROR = 'Must pass a string like "?1100???1001000??0?100?10??10010" where ? represents an unknown bit'

        assert type(guess) == str, ERROR
        assert all(map(lambda x: x in '01?', guess)), ERROR
        assert len(guess) <= 32, "One 32-bit number at a time please"
        guess = guess.zfill(32)

        self.symbolic_guess = BitVec(f'symbolic_guess_{name}', 32)
        guess = guess[::-1]

        for i, bit in enumerate(guess):
            if bit != '?':
                self.solver.add(Extract(i, i, self.symbolic_guess) == bit)

        return self.symbolic_guess


    def submit(self, guess):
        '''
            You need 624 numbers to completely clone the state.
                You can input less than that though and this will give you the best guess for the state
        '''
        if self.index >= 624:
            name = next(SYMBOLIC_COUNTER)
            next_mt = self.symbolic_twist(self.MT)
            self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
            for i in range(624):
                self.solver.add(self.MT[i] == next_mt[i])
            self.index = 0

        symbolic_guess = self.get_symbolic(guess)
        symbolic_guess = self.symbolic_untamper(self.solver, symbolic_guess)
        self.solver.add(self.MT[self.index] == symbolic_guess)
        self.index += 1

    def get_random(self):
        '''
            This will give you a random.Random() instance with the cloned state.
        '''
        #logger.debug('Solving...')
        start = time()
        self.solver.check()
        model = self.solver.model()
        end = time()
        #logger.debug(f'Solved! (in {round(end-start,3)}s)')

        #Compute best guess for state
        state = list(map(lambda x: model[x].as_long(), self.MT))
        result_state = (3, tuple(state+[self.index]), None)
        r = Random()
        r.setstate(result_state)
        return r


ut = Untwister()
io = remote('static-01.heroctf.fr', 9000)
context.log_level = 'DEBUG'

for i in range(624):
    a = float(io.recvline().strip().decode())
    # uniform(a, b) is calculated by a + (b-a) * rand_number, rand_number is in [0,1]
    # https://github.com/python/cpython/blob/main/Lib/random.py
    # now a = 0, b = 2 ** 32 - 1
    n1, n2 = float_to_2_randnumber(a / (2**32-1))
    ut.submit((bin(n1)[2:]).rjust(27, '0') + '?????')
    ut.submit((bin(n2)[2:]).rjust(26, '0') + '??????')

r1 = ut.get_random()
nn1 = r1.getrandbits(32)
nn2 = r1.getrandbits(32)
ans = r_float(nn1, nn2) * (2**32 - 1)
```
50. [Deseret Alphabet](https://www.2deseret.com/):形如`𐐒𐐀 𐐎𐐌 𐐏𐐅 𐐝𐐀 𐐓𐐀 𐐇𐐙 𐐔𐐇𐐝𐐀𐐡𐐇𐐓 𐐣𐐀𐐤𐐞 𐐐𐐊𐐤𐐆 𐐒`
51. [squishy](https://meashiri.github.io/ctf-writeups/posts/202305-tjctf/)
- 不安全的rsa签名。rsa签名为 $m^d\mod n$ ，但签名用的公钥和私钥不能与加密时用的一样，或是签名时不要直接使用明文，先用某种哈希函数求其hash值再签名。当攻击者已知m和签名使用的公钥时，就能在私钥未知的情况下利用交互获取m的签名
    - 选取 $m_1\not ={m}$ ,利用交互获取其签名 $s_1=m_1^d\mod n$
    - 计算 $m_2=m\*m_1^{-1}$ ,获取其签名 $s_2=m_2^d\mod n=(m\*m_1^{-1})^d\mod n$
    - 计算 $s=s_1\*s_2=(m_1\*m\*m_1^{-1})^d\mod n=m^d\mod n$ ，即为m的签名
52. [spring](https://medium.com/@laithxl_79681/hsctf-2023-spring-challenge-823d78d41fc2)
- java(java.util.Random)随机数预测工具[ReplicatedRandom](https://github.com/fta2012/ReplicatedRandom/tree/master)使用。获取两个int随机数（nextInt()）或一个double（nextDouble()）或一个long（nextLong()）的情况下即可预测接下来所有由Random输出的随机数。提交long数字时记得在数字后加个`L`,表示是long。
- python版本的预测java long随机数输出的脚本：https://github.com/Cr4ckC4t/crack-java-prng/blob/main/crack-nextLong.py .参考wp2:https://kos0ng.gitbook.io/ctfs/ctfs/write-up/2023/hsctf/cryptography#spring-48-solves
53. [e](https://github.com/TJCSec/tjctf-2023-challenges/tree/main/crypto/e)
- coppersmith:m高位泄露。此题完整m的位数未知，需要爆破。wp里的脚本比一般的coppersmith实现复杂，参考：https://www.cryptologie.net/article/222/implementation-of-coppersmith-attack-rsa-attack-using-lattice-reductions/
- 其他wp：https://pseudoleon.github.io/tjctf-23/#cryptoe
54. [keysmith](https://github.com/TJCSec/tjctf-2023-challenges/tree/main/crypto/keysmith)
- 给出m和 $c\equiv m^e\mod n$ ，在加密时使用的公钥(n,e)未知的情况下构建另一组公钥 $(n_1,e_1)$ （可与原公钥相同），使得 $c=\equiv m^{e_1}\mod n_1$ 且 $m\equiv c^{d_1}\mod n_1$ 。 https://crypto.stackexchange.com/questions/8902/given-a-message-and-signature-find-a-public-key-that-makes-the-signature-valid 。大致步骤如下（根据wp里的脚本改动）：
    - 选取p和q，p-1和q-1均为光滑数且p（p-1的分解结果）与q（q-1的分解结果）都是m的二次剩余。选取的p和q应该满足 $m\equiv c^{d_p}\mod p,m\equiv c^{d_q}\mod q$
    - 利用离散对数找到上一步提到的 $d_p$ 和 $d_q$ 。应存在d满足 $d\equiv d_p\mod p-1,e\equiv d_q\mod q-1$ 。那么利用crt即可恢复这样的d。
    - `(p-1)*(q-1)`即为phi，`p*q`即为n，d对phi求逆元即为e。公钥+私钥生成完成。
- 其他wp：https://pseudoleon.github.io/tjctf-23/#cryptokeysmith
55. [AdventurersKnapsack](https://born2scan.run/writeups/2023/06/02/DanteCTF.html#adventurers-knapsack),[wp2](https://meashiri.github.io/ctf-writeups/posts/202306-dantectf/#adventurers-knapsack)
- 背包加密问题（knapsack）的攻击：
  - [Lenstra–Lenstra–Lovász (LLL) lattice basis reduction](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)
  - [Low Density attack on low-density knapsacks](https://static.aminer.org/pdf/PDF/000/119/853/solving_low_density_knapsacks.pdf)
- low density attack: For a given set of positive integers $A = \{a_1,..., a_n\} (a_i\not ={a_j})$ and a given positive integer s, determining whether there exists a subset of A with its sum being s, or finding a vector $e = (e_1, . . . , e_n) ∈ \{0, 1\}^n$ satisfying $Σ_{i=1}^n a_i·e_i = s$ , is called the subset sum problem (or the knapsack problem), and is known as an NP-hard problem in general. Low-density attack is a method which works effectively against subset sum problems with low density. The density of the subset sum problem d is defined by $d=\frac{n}{log_2[max(pubk)]}$ 。pubk是背包加密的公钥，或者说上面指定的集合A。max(pubk)=max( $a_i$ )。有以下两种针对此种情况的方法：
  - Lagarias and Odlyzko (LO) algorithm (works on d < 0.6463)
  - [Coster, Joux, LaMacchia, Odlyzko, Schnorr, and Stern (CJLOSS)](https://www.di.ens.fr/~fouque/ens-rennes/sac-LLL.pdf) algorithm(works on d < 0.9408)。创建一个`M*M`的单位矩阵（M为公钥长度+1），其矩阵的最后一行换为0.5，最后一列除最后一项填写N\*公钥(N大于公钥长度的平方根)，而最后一项填上密文。然后使用LLL算法进行格基规约。结果矩阵中的一个向量就是明文的bit。
  - [脚本](https://github.com/hyunsikjeong/LLL)
  ```py
    from Cryptodome.Util.number import *
    ct=
    pubk=
  
    def rotate(l):
        return [l[-1]]+l[:-1]
  
    # one of the papers describing the attack (there are many), "Bi, Jingguo, Xianmeng Meng, and Lidong Han. "Cryptanalysis of two knapsack public-key cryptosystems." Cryptology ePrint Archive (2009)."
  
    base = [1]+[0]*179
    M=[]
    N=15 # >sqrt(180)，大于公钥长度平方根
  
    # creating lattice matrix
    for i in range(180):
        M.append(base+[N*pubk[i]])
        base=rotate(base)
    M.append([0.5]*180+[N*ct])
  
    B=matrix(QQ,M).LLL()
    for row in B:
        if all(abs(k) == 0.5 for k in row[:-1]):
            sol = row
    sol = ''.join(['0' if j==1/2 else '1' for j in sol[:-5]])
    print(long_to_bytes(int(sol,2)))
  ```
- 似乎不同密度的knapsack构造矩阵进行格基规约时，构造的矩阵内部的数字不同，而且会影响结果。例如[knapsack](/CTF/moectf/Crypto/knapsack.md)这题的方法放在这题就解不出来。
56. [Casino](https://kos0ng.gitbook.io/ctfs/ctfs/write-up/2023/hsctf/cryptography#casino-101-solves)
- AES CTR已知明文翻转bit攻击(AES CTR bitflipping)。假设明文有n字节且已知，那么获取其密文后可以将密文修改成指定结果，使其解密时输出想要的明文。只需将密文与明文和期望输出明文异或即可（字节的位置不能错）
```py
pt='abc'
expect='def'
ct=AES.Encrypt("CTR",pt,key,nonce)
ct[0]^='a'^'d'
ct[1]^='b'^'e'
ct[2]^='c'^'f'
print(AES.Decrypt("CTR",ct,key,nonce))
#def
```
- python可用科学计数法用较少的字节数表示大数。如`1e9`.或者`float("nan")`，也是三字节。
57. [signature-i](https://github.com/BCACTF/bcactf-4.0/tree/main/signature-i)
- rsa签名伪造：[Bleichenbacher's RSA signature forgery based on implementation error](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/). 此攻击基于PKCS-1 padding的错误实现+e为3。
  - PKCS-1 padding格式如下：`00 01 FF FF FF ... FF 00  ASN.1  HASH`，在按照正常RSA解出m后移走前面的padding即可获取hash。假如不检查hash后是否有多余字节就直接比对，如：`00 01 FF FF ... FF 00  ASN.1  HASH  GARBAGE`，那么攻击者就能构造一个立方数，其立方根即为构造的signature。
58. [signature-ii](https://github.com/BCACTF/bcactf-4.0/tree/main/signature-ii)
- 椭圆曲线签名（elliptic curve digital signature，ecc）算法及验签：https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
- 签名参数k共用攻击：签名算法里的k应该是随机且每次签名都不同的。若相同，攻击者在获取两对签名(r,s)和(r,s')以及其对应的明文后即可获取第三个使用相同k的签名(r,s'')所对应的明文。操作如下：
  - $k=\frac{m-m'}{s-s'}$
  - $d_A=\frac{sk-m}{r}$ ( $d_A$ 为私钥)
  - $s''\*k=m''+rd_A$
  - $m=s''\*k-rd_A$
59. [winterfactory](https://github.com/MathVerg/WriteUp/tree/master/GPN2023/winterfactory)
- [Winternitz One-Time Signature](https://junhaideng.github.io/2021/12/24/cryptography/signature/wots/) scheme介绍。
  - 该签名scheme签名m的过程简述如下：
    - 使用某种哈希函数H获得H(m)，并选择数字w。接着将H(m)分成多块 ( $b_i$ )，每份 $log_2(w)$ bits。然后将每份 $b_i$ 转换为 $log_2(w)$ bit长度的unsigned整数，称为 $v_i$ 。计算校验和： $c=\sum_i(w-v_i)$ ,将其拼接到b后。
    - 对每份 $b_i$ 都选择一个随机数 $p_i$ ，作为私钥。私钥的大小等同于之前选择的hash函数的输出大小。
    - 将每个私钥 $p_i$ hash w次，得到的结果 $P_i$ 即为公钥。( $P_i = H^{(w)}(p_i)$ )
    - 最后将每个私钥 $p_i$ hash $v_i$ 次： $s_i=H^{v_i}(p_i)$ 。 $s_i$ 拼接在一起即为签名结果。
  - 验签步骤：
    - 提供签名 $s_i$ ，将签名hash $w-v_i$ 次。若提供的签名正确，结果应等于公钥 $P_i$ 。 $H^{w-v_i}(s_i)=H^{w-v_i}(H^{v_i}(p_i))=H^w(p_i)=P_i$
- 此题介绍了一种当私钥被使用多次的攻击。不过局限性较大，签名结果checksum的一半被泄露，且事先已获取一组明文与其签名。
60. [number-lock](https://github.com/MathVerg/WriteUp/tree/master/GPN2023/number-lock)
- Differential Fault Attack (DFA) on [AES](https://zhuanlan.zhihu.com/p/78913397)（128）
  - 相关文章（原理）和工具：
    - https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
    - https://github.com/Vozec/AES-DFA
  - 题目特征点
    - 允许攻击者在AES的某一轮加密处修改plain state为未知随机字节（fault）
    - 允许交互。攻击者输入明文，服务器返回对应的密文
    - 加密时的密钥固定。目标为利用有限的交互次数+fault破解使用的密钥
61. [signed_jeopardy](https://notateamserver.xyz/nahamcon-2023-crypto/#signed-jeopardy)
- ECDSA（椭圆曲线，ecc） nonce（k值）重用（reuse）导致的[签名伪造](https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a)。感觉和58条[signature-ii](https://github.com/BCACTF/bcactf-4.0/tree/main/signature-ii)类似，不过这题有不同的脚本
    - 继续补充看到的其他脚本：[Double-Whammy](https://mindflayer02-ctf-sec-notes.gitbook.io/mindflayer02-bisher-mohammads-ctf-writeups/nitectf-23/double-whammy)
    - 自动工具： https://github.com/Hungary23/ecc_cryptanalysis/
62. [Just One More](https://notateamserver.xyz/nahamcon-2023-crypto/#just-one-more)
- 利用矩阵与阶梯形矩阵解线性方程组。sagemath里构造出矩阵后，可用Matrix.rref()获取阶梯形矩阵。注意如果矩阵的阶数和未知数的数量不一样的话，结果的阶梯形矩阵会有差别。详情见wp。
- 也可用sympy linsolve： https://github.com/nzec/ctf-notes/tree/master/NahamCon23/Just%20One%20More
63. [RSA Outro](https://notateamserver.xyz/nahamcon-2023-crypto/#rsa-outro)
- 使用sympy解方程。
```py
from sympy import *
var('q')
solutions = solve(2*q*(q-1)-phi, q) #这里的方程结果为0，即 2*q*(q-1)-phi==0
q = solutions[1]
```
64. [order](https://github.com/hsncsclub/hsctf-10-challenges/tree/main/crypto/order)
- 数论寻找元素的阶（order， $a^x\equiv 1\mod p$ ,满足该条件最小的x）
    - 通过phi的因子来找（欧拉定理告诉我们 $a^{phi}\equiv 1\mod p$ ,于是phi可能为阶的倍数）：https://kos0ng.gitbook.io/ctfs/ctfs/write-up/2023/hsctf/cryptography#order-46-solves
    ```py
    from sympy.ntheory import *
    from Crypto.Util.number import long_to_bytes
    M = 
    sus = 
    a = 
    # sus**(t+1) == 1 (mod M)
    # note gcd(sus, M) = 1
    # order of sus (mod M) divides totient(M)
    # let's try determining the order
    order = -1
    for i in divisors(totient(M)):
        if pow(sus, i, M) == 1:
            order = i
            break
    print(order)
    # also, t == flag^-1 * a (mod M), and in particular t < M
    # order of sus (mod M) divides t+1, so just test multiples of order - 1 less than M
    # WOOOOOOOOOOOOOOOOOOOOOOOOOOOO
    # flag == a * t^-1 (mod M)
    for t in range(order-1, M, order):
        flag_long = a * pow(t, -1, M) % M
        flag_bytes = long_to_bytes(flag_long)
        if flag_bytes.startswith(b"flag{"):
            print(flag_bytes.decode())
            break
    ```
65. [Cursved](https://github.com/google/google-ctf/tree/master/2023/crypto-cursved)
- Schnorr signature scheme(基于ecc，椭圆曲线)。关于这种电子签名法，详细解析参考： https://www.btcstudy.org/2021/11/20/introduction-to-schnorr-signatures-by-suredbits/ ，单纯讲定义的简洁版： https://www.cnblogs.com/lsgxeva/p/12021636.html 。关于椭圆曲线本身再补充两个链接：
    - https://hackernoon.com/what-is-the-math-behind-elliptic-curve-cryptography-f61b25253da3
    - https://zhuanlan.zhihu.com/p/36326221
- [Pell conics over finite fields](https://arxiv.org/abs/2203.05290)：the points can form two different types of groups, depending on whether d is a square or a non-square in k, respectively。若d是模p的二次剩余，就有以下同构： $C(k)\simeq k^{\*}.C(k)\rightarrow k^{\*}(x,y)\mapsto x+sy$ ,where we fix a square root s of d in k. Hence, instead of solving a generically hard DLP over the Pell conic group law, we can solve it over $k^{\*}$ instead. 个人认为的关键点：ecc的安全性基于离散对数的计算难度，但如果像上面这样有Pell conic的存在且d是模p的二次剩余，就能将原本要计算的k域转为 $k^{\*}$ ,计算就能简单一点，从而破解私钥了。使用[cado-nfs](https://cado-nfs.gitlabpages.inria.fr/)计算。参考： https://discord.com/channels/984515980766109716/1120323829303083079/1122884985007898654
```py
p = 
D = 
F = GF(p)
dd = F(D).sqrt()

G = GX, GY = F(2), F(1)
assert GX^2 - D*GY^2 == 1
PUB = (F(), F())

φ = lambda x, y: (x - dd*y, x + dd*y)
ψ = lambda u, v: ((u + v)/2, (v - u)/(2*dd))

uG = φ(*G)[0]
uP = φ(*PUB)[0]
ell = ZZ(p//2)
assert is_prime(ell)
print(f"G: {uG^2}\nP: {uP^2}")
cadologG = 
cadologP = 
dlog1 = ZZ(GF(ell)(cadologP) / (cadologG))
dlog2 = ZZ(discrete_log_rho(uP^ell, uG^ell, operation='*', ord=2))
dlog = CRT(ZZ(dlog1), ZZ(dlog2), p//2, 2)
print(f"PRIVATE = {dlog}")
print(uG^dlog == uP)
#cadologG 和 cadologP计算方法： ./cado-nfs.py -dlp target=<value_G>,<value_P> ell=<p//2> <p>
```
66. [mhk2](https://github.com/google/google-ctf/tree/master/2023/crypto-mhk2)，[wp](https://mystiz.hk/posts/2023/2023-06-26-google-ctf-mhk2/)
- 修改版MHK2 cryptosystem攻击。此题与完整MHK2 cryptosystem实现方式的不同点在于：In MHK2 cryptosystem, the prime numbers $p_1$ and $p_2$ are randomly generated such that $\frac{p_i}{2}$ < $\sum _js_{ij}$ < $p_i$ . This is not our case – we fix it to $p_i=\sum _js_{ij}+2$ 。所以这道题提供的解法无法破解标准的MHK2 cryptosystem。
67. [myTLS](https://github.com/google/google-ctf/tree/master/2023/crypto-mytls)
- [Key Compromise Impersonation attacks (KCI)](https://www.cryptologie.net/article/372/key-compromise-impersonation-attacks-kci/):当攻击者可以获取client或server的private key后，即可实施中间人攻击，篡改加密的通信。根据不同的实现，篡改的方式不同。wp里列出了一种方式。
68. [ZIP](https://github.com/google/google-ctf/tree/master/2023/crypto-ziphard)
- 微型ZIP archiver python实现，或者也能称为PKZIP Stream Cipher。这种密码有[ZIP 明文攻击](https://flandre-scarlet.moe/blog/1685/)，可用[bkcrack](https://github.com/kimci86/bkcrack/tree/master)工具进行攻击。该工具要求至少知道12个字节的明文以及其对应密文（或者说明文对应密文的偏移），其中至少有8个字节是连续的。此题知道的12字节分布在两个不同的文件，前8个已知字节在flag.txt里，而另外5个在另一个文件。不过根据明文攻击的原理，前8个字节才是真正用于破解密钥的，后面的字节只是为了验证得到的密钥是否正确。所以可以将工具自行patch以下，参照wp里的做法。
- python里，若将字符串以`utf-8-sig`编码，除了字符串正常UTF-8编码，还会在结果前面加上Unicode byte order marker。Utf-8里这个marker为`ef bb bf`
- C语言爆破CRC脚本
69. [Three-Time Pad](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/crypto/three_time),[wp](https://github.com/daffainfo/ctf-writeup/tree/main/UIUCTF%202023/Three-Time%20Pad)
- 同样的密钥用于加密多个消息且密文已知，可直接用wp里的脚本恢复明文+key。不过这题其实没那么麻烦，只是记录一下脚本：https://github.com/Jwomers/many-time-pad-attack/tree/master ,即使密文长度不一样也可以用
70. [Morphing Time](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/crypto/morphing),[wp](https://tsumiiiiiiii.github.io/uiu-crypto/#morphing-time)
- [Elgamal Cryptosystem](https://en.wikipedia.org/wiki/ElGamal_encryption)：homomorphic under multiplication。
- 利用[tonelli shanks algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)解方程 $x^2\equiv a\mod p$
71. [At Home](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/crypto/at_home),[wp](https://github.com/P3qch/ctfs/tree/main/uiuctf2023/at_home)
- wp提供了一种利用z3求解 $ax\equiv b\mod p$ 的方法
72. [Crack The Safe](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/crypto/crack_the_safe),[wp](https://bronson113.github.io/2023/07/03/uiuctf-2023-writeups.html#crack-the-safe)
- Pohlig-Hellman discrete log Attack:对于离散对数 $g^x\equiv k\mod p$ （p为质数），若p-1（群的阶）为光滑数且最大的那个因子较小，则计算x的代价将降为那个最大的因子。需要使用[cado-nfs](https://github.com/cado-nfs/cado-nfs)（[gitlab](https://gitlab.inria.fr/cado-nfs/cado-nfs)）计算模不同因子下的指数后再用crt组合出原本的x。
- 另一种解法 https://github.com/Norske-Nokkelsnikere/writeups/tree/main/2023/uiuctf-2023/crack_the_safe 利用AES 128bit key的特点爆破出了key（cado-nfs无法安装，故只能利用sagemath算出前几个因子相关的对数，最后一个最大的算不出来）
    - 类似做法： https://pseudoleon.github.io/uiuctf-23/ 。两者都有Pohlig-Hellman的sagemath实现
73. [Group Projection](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/crypto/group_projection),[wp](https://github.com/ctfguy/My_CTF_Writeups/blob/main/UIUCTF%202023/Crypto/Group%20Project%20and%20Projection/solution.md)
- [Small subgroup confinement attack on Diffie-Hellman](https://crypto.stackexchange.com/questions/27584/small-subgroup-confinement-attack-on-diffie-hellman)
74. [Derik](https://github.com/AKSLEGION/Crypto-Writeups/tree/master/Crypto_CTF_2023/Derik)
- 对于不定方程 $x^3+y^3+z^3=nxyz$ ,0 < n < 81的已知解： http://matwbn.icm.edu.pl/ksiazki/aa/aa73/aa7331.pdf ，（<= 197）: https://mathoverflow.net/questions/384565/status-of-x3y3z3-6xyz
- 根据 https://zhuanlan.zhihu.com/p/642698403 ， 方程 $x^3+y^3+z^3=nxyz$ ，或者说三次齐次方程（cubic homogeneous equation），都与椭圆曲线等价（也不是说完全一样，两者之间有同态关系(不太确定是不是同态，birational isomorphism？)）。a homogeneous cubic in three variables with rational coefficients利用sagemath的[EllipticCurve_from_cubic](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/constructor.html#sage.schemes.elliptic_curves.constructor.EllipticCurve_from_cubic)即可做转换
```py
R.<x,y,z> = QQ[]
cubic = x^3 + y^3 + z^3 - 73 * x * y * z #三次齐次方程
P = [1,-1,0] #三次齐次方程的非零解，在上述方程所构成的curve C上defining a projective point
E = EllipticCurve_from_cubic(cubic, P, morphism=False) #当morphism=False，返回C在birational isomorphism映射后的Weierstrass elliptic curve（E）像
f = EllipticCurve_from_cubic(cubic, P, morphism=True) #若等于True，直接返回C到E的birational isomorphism
finv = f.inverse() #获取f的逆映射。既然f是从cubic curve到elliptic curve，这个就是从elliptic curve到cubic curve
R = E.gens()[0] #获取E上的生成元
PP = f(P)
print(finv(R)) #打印生成元映射到cubic curve的点
```
75. [TPSD](https://meashiri.github.io/ctf-writeups/posts/202307-cryptoctf/#tpsd)
- 求解不定方程（丢番图方程，diophantane equation） $x^3+y^3+z^3=1$ 的任意bit长度解。这个方程的解一定满足 $(9a^4)^3+(3a-9a^4)^3+(1-9a^3)^3=1$ (或者 $(9a^4)^3+(-3a-9a^4)^3+(1+9a^3)^3$ ，来源 https://github.com/AKSLEGION/Crypto-Writeups/tree/master/Crypto_CTF_2023/TPSD),且只有最后一个数字可能是质数。插入不同的a值即可获取不同的解。
    - 论文：https://www.ams.org/journals/mcom/2007-76-259/S0025-5718-07-01947-3/S0025-5718-07-01947-3.pdf
    - wiki： https://en.wikipedia.org/wiki/Sums_of_three_cubes
76. [Blobfish](https://meashiri.github.io/ctf-writeups/posts/202307-cryptoctf/#blobfish)
- 使用[bkcrack](https://github.com/kimci86/bkcrack)实施zip明文攻击爆破加密zip密码。此题zip内部的文件为png（Image.new('RGB', (800, 50))），因为png的前16个字节已知且固定，故可以实施明文攻击。
    - https://zhuanlan.zhihu.com/p/643106267 ：似乎前33（0x21）个都是一样的
77. [Bertrand](https://github.com/abhishekg999/CTFWriteups/tree/main/CryptoCTF/Bertrand)
- [Hilbert curve](https://en.wikipedia.org/wiki/Hilbert_curve):一种连续分形空间填充曲线，一条无限长的曲线可完全填充有限的二维空间。利用它可以将一个任意数字独特地映射到一个2d点（单射，可逆）
78. [ASlv1](https://github.com/AKSLEGION/Crypto-Writeups/tree/master/Crypto_CTF_2023/ASIv1)
- 模上的矩阵与向量相乘。其实就是正常的矩阵操作然后把每个结果模制定的数就好了。对于Ax=b其中x和b都是向量，A是矩阵的方程，可以用sagemath自带的solve_right来解决(估计类似的xA=b就用solve_left)。wp里的解法尝试将矩阵行规约（elementary row reduction operation），应该是solve_right的本质。不过solve_right要考虑矩阵是否满秩和线性系统的复杂度，参考 https://zhuanlan.zhihu.com/p/643106267 和 https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#asiv1
79. [Trex](https://github.com/AKSLEGION/Crypto-Writeups/tree/master/Crypto_CTF_2023/Trex)
- 求解不定方程 $x^2 + y^2 - xy = a * z^3$ ， $z = 3a,y = 6a^2,x = -b/2 = y/2 = 3a^2$ 。这类方程的思路是可以把整个方程本身看作普通的基于x的一元二次方程，然后根据求根公式的判别式 $b^2=4ac$ ，我们可以让提供的x，y和z满足这一条件（根一样会比较简单），然后基于这一条件推出x，y和z与a的关系。
80. [Roldy](https://github.com/AKSLEGION/Crypto-Writeups/tree/master/Crypto_CTF_2023/Roldy)
- python pyope模块实现了order-preserving encryption，意味着如果a < b 那么 enc(a) < enc(b)，即加密函数单调递增。在给出密文和oracle后，可利用binary search解密密文。前提是oracle满足以下条件：
    - oracle拥有无限次交互机会
    - oracle会返回用户输入的任意明文的密文
    - 明文按照单个字符一个一个加密
81. [Barak](https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#barak),[wp](https://zhuanlan.zhihu.com/p/642698403)
- 曲线方程 $x^3+y^3+c=dxy$ 同样可以利用sagemath里三次齐次方程转椭圆曲线的函数[EllipticCurve_from_cubic](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/constructor.html#sage.schemes.elliptic_curves.constructor.EllipticCurve_from_cubic)转椭圆曲线，只需引入一个变量z来把它变成齐次式 $x^3+y^3+cz^3=dxyz$ ，当z=1时即为原方程。映射完成后原曲线方程上的离散对数问题Q=mP就可以在椭圆曲线上用discrete_log完成。
    - 这个曲线方程其实是椭圆曲线的[Hessian形式](https://link.zhihu.com/?target=https%3A//en.wikipedia.org/wiki/Hessian_form_of_an_elliptic_curve),通过代数运算可以直接代回成Weierstrass形式。 https://ctfnote.leg.bzh/pad/s/SL4mIXF3b
- sagemath里面可以检查曲线方程是什么类型的曲线
```py
x,y=ZZ['x,y'].gens()
eq=
Curve(eq).genus()
#若输出1，说明曲线方程是椭圆曲线。可以去 https://www.hyperelliptic.org/EFD/ 查看它是椭圆曲线的什么形式
```
- 在椭圆曲线中，若Q=mP（over GF(p)）且m小于P的阶小于p，那么离散对数求出m后不一定是原来的m，真正的m类似模运算，为x+n|P|
82. [Risk](https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#risk)
- [A New Attack on Special-Structured RSA Primes](https://einspem.upm.edu.my/journal/fullpaper/vol13saugust/8.pdf): 当RSA的p和q有特殊结构时，可以对其实施攻击。 $p=a^m+r,q=b^m+s$ . $n=pq=(a^m+r)(b^m+s)=a^mb^m+sa^m+rb^m+rs\equiv sa^m+rb^m+e(\mod a^mb^m)$
- 如果已知两个数m和n的乘积与和，可构造 $f(x)=(x-m)(x-n)$ ，即一元二次方程，然后求根，两个根即为m和n。
- RSA当e与phi不互素时，对p和q分别对c开e次根，然后利用crt组合出原本的m。在[NCTF2019]easyRSA那里提过，包括wp，这里再提供几种不同的做法
    - https://zhuanlan.zhihu.com/p/642698403 ：开根+crt的不同脚本
83. [Keymoted](https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#keymoted)
- Z/nZ上ECC类似RSA的加密。思路与正常RSA差不多，必要的一步也是分解n,然后求逆元。
```py
Z = Zmod(n)
E = EllipticCurve(Z, [a, b]) #定义椭圆曲线
C = E(encx, ency) #C=me，encx和ency是结果密文C的x和y坐标
Ep = EllipticCurve(GF(p), [a, b]) #定义p和q下的椭圆曲线
Eq = EllipticCurve(GF(q), [a, b])
od = Ep.order() * Eq.order() #获取phi
d = pow(e, -1, od)
M = d * C
print(long_to_bytes(int(M.xy()[0])))
```
或者参考 https://zhuanlan.zhihu.com/p/643176962 ，在p和q下分别求离散对数，然后crt。

84. [Big](https://zhuanlan.zhihu.com/p/643355092)
- [Cocks IBE scheme](https://en.wikipedia.org/wiki/Cocks_IBE_scheme)：基于二次剩余（quadratic residuosity）的加密方式
- [韦达定理](https://baike.baidu.com/item/%E9%9F%A6%E8%BE%BE%E5%AE%9A%E7%90%86/105027)+sagemath利用kronecker求二次剩余
- n=pq，当q=int(str(p)[::-1])时，可以快速分解n
- 其他wp
    - https://hackmd.io/@taiyaki/BJbEomuF2#Big-169-pts-23-solves-Hard
    - https://shiho-elliptic.tumblr.com/post/722391959624433664/crypto-ctf-2023-writeup-en
85. [Marjan](https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#marjan),[wp](https://zhuanlan.zhihu.com/p/643355092)
- 基于ECC的类似ecdsa的签名算法。当k较小时，可以转化为NHP问题然后利用格和格基规约（如LLL）来解
- 验签算法实现时要考虑签名参数的非平凡性，否则攻击者可能可以将某个参数置为0然后消除方程的未知数。
86. [Shevid](https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#shevid)
- [Supersingular isogeny key exchange(SIDH)](https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange)（论文介绍： https://eprint.iacr.org/2019/1321.pdf ）破解： https://eprint.iacr.org/2022/975 。针对该加密的Castryck-Decru攻击脚本： https://github.com/GiacomoPope/Castryck-Decru-SageMath
    - 其他wp（用作脚本使用参考）
        - https://zhuanlan.zhihu.com/p/643416297
        - https://shiho-elliptic.tumblr.com/post/722391959624433664/crypto-ctf-2023-writeup-en
87. [Byeween](https://blog.maple3142.net/2023/07/09/cryptoctf-2023-writeups/#byeween)
- 给定随机椭圆曲线E和E上一点Q，找到所有满足 $2P=Q,P\in E$ 的P。使用sagemath的division_points。
    ```py
    E = EllipticCurve()
    Q = E(x,y,z)
    for x in Q.division_points(2):
        print(",".join(map(str, x.xy())))
    #配合sage_eval和coefficient： https://shiho-elliptic.tumblr.com/post/722391959624433664/crypto-ctf-2023-writeup-en
    ```
    - 构造方程解法： https://zhuanlan.zhihu.com/p/643355092
88. ecc上的[Smart's Attack](https://ariana1729.github.io/2021/05/31/SmartAttack.html)。当一个椭圆曲线additive transfer（anomalous curve）时，则可以进行Smart's Attack，能够在线性时间内解决ecc上的dlp问题。
 - additive transfer指the order of the elliptic curve group is equal to the order of the underlying prime field. 感觉用sagemath里的api比较好解释：
```py
Ep = EllipticCurve(GF(p), [a, b]) #p-1: the order of the underlying prime field. 要是p不是质数的话可能会是别的数，质数的话就是p-1
Ep.order() #曲线加法群的阶（the order of the elliptic curve group）
```
- 攻击脚本：https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py
- 可以在这里查看什么样的曲线容易受到transfer相关的攻击： https://safecurves.cr.yp.to/transfer.html
- 关于如何判断曲线是否anomalous以及另一个版本的smart attack脚本，可以参考[这题](https://github.com/sahuang/my-ctf-challenges/tree/main/vsctf-2023/crypto_ecc-fantasy)的生成函数。感觉特征应该是`E.trace_of_frobenius() == 1`
89. [rsalcg2](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/crypto/rsalcg2),[wp](https://hackmd.io/@keymoon/S100q2xch)
- [half GCD(hgcd)算法](https://www.cnblogs.com/whx1003/p/16217087.html)在特殊情况下的加速。hgcd用于计算多项式的gcd，比欧几里得算法要快。
90. [The Vault 2](https://github.com/rwandi-ctf/ctf-writeups/blob/main/amateursctf2023/the%20vault%202.md)
- 三个立方和方程以及四个立方和方程的参数化
    - https://en.wikipedia.org/wiki/Sum_of_four_cubes_problem
    - https://www.alpertron.com.ar/FCUBES.HTM
    - https://github.com/aparker314159/ctf-writeups/blob/main/AmateursCTF2023/the-vault-2.md
91. [Weak Primes](https://github.com/rwandi-ctf/ctf-writeups/blob/main/amateursctf2023/weak%20primes.md)
- coppersmith补充
    - The coppersmith method uses lattice reduction to find small integer solutions to a polynomial modulo a factor of n that is $\geq n^{\beta}$
    - Setting $\beta\approx 0.5$ and $f(x)=2^{2047}+x$ , it will find an integer solution to x such that $2^{2047}+x\equiv 0\mod m$ where m|n, $m\geq n^{\beta}$ (the smaller the difference between m and $n^{\beta}$ the better)
92. [Non-Quadratic Residues](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2023/crypto/non-quadratic-residues),[wp](https://github.com/GabrieleDellepere/writeups/blob/main/AmateursCTF/non-quadratic-residue-writeup.md)
- amm开根法应用的特殊情况。假如有 $x^a\equiv b\mod c$ 其中a，b和c已知，amm开根法可用于恢复x。若a可分解，可以参照wp里的做法，分别开分解后的质数次根。如`a=2*3*5*7`，就在模c的基础上开2次根，然后开出的结果拿去开3次根，结果再拿去开5次根……一直到恢复x
    - 指数较小的甚至直接用sagemath构造多项式就能开出来
    ```py
    P.<x> = PolynomialRing(Zmod(b))
    pol=x^a-c
    roots=pol.roots()
    ```
93. [gcd-query](https://enscribe.dev/blog/actf-2023/gcd-query/)
- $x\equiv -n\mod gcd(x+n,m)$
94. [flatcrypt](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-09-14-CSAW-CTF-Quals/README.md#100-crypto--flatcrypt)
- [CRIME](https://en.wikipedia.org/wiki/CRIME) oracle攻击。攻击条件：
    1. 可输入内容与服务器进行交互
    2. 输入的内容被拼接到flag后并返回压缩的内容。压缩方式诸如gzip，zlib等都可以
    - 原理（以zlib举例）：当压缩的内容有重复部分时,压缩内容的长度会比没有重复部分的短。可利用这点猜测出之前的内容是什么
    ```py
    import zlib
    print(len(zlib.compress(b"good_secret"))) #19
    print(len(zlib.compress(b"good_secret" + b"good"))) #21
    print(len(zlib.compress(b"good_secret" + b"baad"))) #23
    ```
    脚本： https://github.com/mpgn/CRIME-poc/tree/master
- [Criminal](https://github.com/rerrorctf/writeups/blob/main/2024_04_07_TamuCTF24/cry/criminal/criminal.md):CRIME攻击的`zlib.compress`+`ChaCha20_Poly1305`版本。不知为何，做这题的时候上面的脚本跑不了，最后还是抄 https://ctftime.org/writeup/27105 （这个题里是Salsa20）出来的。 https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#criminal
95. [signer](https://meashiri.github.io/ctf-writeups/posts/202307-imaginaryctf/#signer)
- crc32无法防止collsion，也无法防止数据被篡改。在给定一个crc32值后，可以利用[工具](https://github.com/theonlypwner/crc32)逆向算法，获取该crc32值对应的字符串
96. [MCTEENX](https://xhacka.github.io/posts/writeup/2023/07/29/MCTEENX/)
- 利用bkcrack爆破ZipCrypto Store： https://www.anter.dev/posts/plaintext-attack-zipcrypto/
- 利用CyberChef爆破异或密码的key（cribdrag）
97. [Fermentation](https://xa21.netlify.app/blog/tfcctf-2023/Fermentation/)
- [aes cbc翻转字节攻击](http://www.f0und.icu/article/28.html)。可以在不知道key和iv的情况下，通过修改密文实现解密出来的明文为攻击者期望的内容
98. [Polypoint](https://maxniederman.com/posts/ctf/lit-2023/polypoint/)
- 线性方程组缺少一个完全未知的方程的解法。之前见过缺少一个方程组的线性系统，但是那个未知的方程解已知。这题完全不知道。当线性系统缺少方程时，方程组有解且有无数个解，这时就需要通过设置解的范围来确定唯一的的解。wp作者使用的软件为Mathematica
```
Encoded = Import["encoded.csv"]; //导入文件
X = Encoded[[All, 1]];
Y = Encoded[[All, 2]]; //将文件中第二列全部内容存入Y
V = Function[x, Power[x, Range[0, 10]]]; //构造一个函数，参数为x，返回x 0-10幂次组成的数列
M = V /@ X; //将函数作用于X中的每一元素
p = {p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11};
SolutionBounds = Cuboid[ //构造一个解的范围。根据wp，p1的下限是0，上限是2^(78 * 8)；其余的下限是10^11，上限是10^12
        Join[{0}, Table[10^11, 10]],
        Join[{2^(78 * 8)}, Table[10^12, 10]]
    ];
Solution = Solve[M.p == Y &&  p ∈ SolutionBounds, p, Integers]
Flag = First[p1 /. Solution]
Print[ByteArrayToString[ByteArray[IntegerDigits[Flag, 2^8]]]]
```
- 某些情况下可以用z3： https://nolliv22.com/writeups/lit%20ctf%202023/polypoint
99. [The Door to the Xord](https://demo.hedgedoc.org/s/aCKUEfByW)
- 获取MT19937连续的624个32-bit输出后，即可预测接下来的随机数。参考 https://www.schutzwerk.com/en/blog/attacking-a-rng/ ，工具： https://github.com/anneouyang/MT19937 。因为其state有19968 bit，624个32 bit就是624×32=19968
- mt19937是线性的，就算只能获取32-bit输出与一个固定未知值的异或结果，仍然也是线性的。只需要在z3里实现mt19937即可
- 如果不能获取32 bit输出而是其n倍bit，可以将n倍bit转为32 bit。因为其输出是倒着拼接的
```py
import random
random.seed(0)
print([hex(random.getrandbits(32)) for _ in range(8)])
random.seed(0)
print(hex(random.getrandbits(256)))
#['0xd82c07cd', '0x629f6fbe', '0xc2094cac', '0xe3e70682', '0x6baa9455', '0xa5d2f34', '0x42485e3a', '0xf728b4fa']
#0xf728b4fa42485e3a0a5d2f346baa9455e3e70682c2094cac629f6fbed82c07cd
```
100. [are YOU smarter than Joseph-Louis Lagrange????](https://github.com/programmeruser2/ctf-solutions/tree/main/litctf/2023/lagrange)
- 使用[wolfram](https://www.wolframalpha.com/)解方程+Lagrange Interpolation。当知道任意数量的点后，Lagrange Interpolation可用于给出满足所有输出点的一个函数方程
101. [E(Z/C)LCG](https://meashiri.github.io/ctf-writeups/posts/202308-litctf/#cryptoezclcg)
- 椭圆曲线（ecc）的参数恢复。Weierstrass形式的椭圆曲线方程为 $y^2=x^3+ax+b$ ，若已知曲线上任意两个点，就能恢复a和b。 https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/parameter_recovery.py
- 注意当g=ax，其中x是椭圆曲线上的点，a是常数的话，已知g，a求x要用离散对数（还是要根据定义来，这里的乘法不是常规意义上的乘法，是椭圆曲线自己定义的）
102. [All in One](https://meashiri.github.io/ctf-writeups/posts/202308-cybergonctf/#all-in-one)
- 维吉尼亚密码（Vigenere）decoder。这个decoder的字符集较广而且区分大小写，网上常见的decoder都解不出来
103. [CryptoGRAPHy 1](https://ctfnote.leg.bzh/pad/s/Z_QKPfErn)
- Graph Encryption Scheme(GES)。似乎和给定两点后图表内连接两点的最短路径有关系。属于对称加密，因为已知key后就能直接解密服务器提供的最短路径
104. [CryptoGRAPHy 2](https://ctfnote.leg.bzh/pad/s/dZNZbd-9e)
- 只要有足够的query次数和泄露的token，可以从加密后的最短路径构造出single-destination shortest path (SDSP) tree。具体操作为query每个（除destination本身）node到destination的最短路径，然后建立token到node的映射即可
105. [Noisy CRC](https://ctfnote.leg.bzh/pad/s/haum5HonP)
- CRC16的本质是在二进制多项式域(`GF(2)[x]`)上的除法。给定要求CRC的key p(x)和生成多项式q(x),CRC16算法会做一个多项式长除法，返回 $p(x)\*x^{16}$ 除以q(x)的余数。如果可以控制q(x)，就能在获取多个CRC值后利用CRT恢复p(x)
- 特别地，如果CRC值被混在其他随机值内，可以选择 $x^6$ 的倍数作为多项式。这样其余数一定也是 $x^6$ 的倍数，而随机值是倍数的可能性很小
- 另一个[wp](https://7rocky.github.io/en/ctf/other/sekai-ctf/noisy-crc/)用dfs来爆破正确的crc值组合
- 还有个[wp](https://imp.ress.me/blog/2023-08-28/sekaictf-2023#noisy-crc)利用composite moduli的性质。假设有多组 $f_i(x)=g(x)\*h_i(x)$ ，那么求 $res=s(x)\mod g(x)\*h_i(x)$ ，每组的res模g(x)的结果应该是一样的（要求g(x)不可约）
106. [cryptoGRAPHy 3](https://7rocky.github.io/en/ctf/other/sekai-ctf/cryptography-1-2-3/#cryptography-3)
- tree isomorphism, which defines a one-to-one relation between the nodes of two trees. python的etworkx模块提供了tree_isomorphism函数来找到同构
- 这篇wp里还有cryptoGRAPHy 1和2更详细的解释
107. [RandSubWare](https://imp.ress.me/blog/2023-08-28/sekaictf-2023#randsubware)
- 针对[代换-置换网络(Substitution–permutation network)](https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network)的[差分攻击(differential attack)](https://ioactive.com/differential-cryptanalysis-for-dummies/)。差分攻击简述就是分析明文与密文之间的差距（差距的定义不同密码，不同，可以是异或的值，也可以是别的东西），然后爆破密钥，哪个密钥最符合之前得到的差距，哪个就可能是最可能的密钥。选择明文+爆破攻击
- 可用差分攻击的特征：
    - SPN密码轮数较少（例如5轮）。small number of rounds means that differences in ciphertext are poorly diffused
    - 对于好的SPN密码，明文中1 bit的更改应导致输出中一半的bit更改。如果这个值较低（如0.4），大概率有问题
- 出题人的自动化模块，利用z3: https://github.com/deut-erium/auto-cryptanalysis
108. [Diffecientwo](https://imp.ress.me/blog/2023-08-28/sekaictf-2023#diffecientwo)
- 利用z3找到[布隆过滤器(bloom filter)](https://zhuanlan.zhihu.com/p/43263751)的碰撞（collision）。布隆过滤器的实现一般会使用murmurhash3（`import mmh3`）
- https://www.josephkirwin.com/2018/04/07/z3-hash-inversions/ 。用这里面的代码硬找所要求hash的明文也是可以的，就是时间比较长。这篇里面还提到了一个z3使用tips： https://www.josephkirwin.com/2017/11/16/constraint-solver-tips/
- 注意脚本内使用了z3.LShR而不是单纯的`>>`。z3中的整数默认是有符号的，不这么做可能会得到unsat
109. [Lottery](https://meashiri.github.io/ctf-writeups/posts/202309-csaw/#lottery)
- 一个ticket可以从1-70中选6个不同的数字，开奖时越多数字匹配就能得到越多奖。多少个ticket才能保证一定盈利？利用fano planes构造特殊数字组即可。参考 https://www.youtube.com/watch?v=zYkmIxS4ksA 。解法不唯一
- 又找到了一道差不多的题：[Rigged Lottery](https://chronopad.gitbook.io/nahamcon-ctf-2024/rigged-lottery)。这个wp的脚本更简单一点。原论文的相关repo： https://github.com/prowlett/lottery-guaranteed-win
110. [Linear Aggressor](https://muuu.net/2023-09-18/)
- [linear regression model](https://en.wikipedia.org/wiki/Linear_regression)
111. [Blocky Noncense](https://github.com/osirislab/CSAW-CTF-2023-Quals/tree/main/crypto/blocky%20noncense)
- ECDSA中nonce的选取应该完全随机。如果使用了cubic congruential generator，会导致所有nonce之间都有一定的关系，可通过related nonce attack获取私钥（对于cubic congruential generator来说需要6个签名）。论文： https://eprint.iacr.org/2023/305.pdf
112. [Circles](https://github.com/osirislab/CSAW-CTF-2023-Quals/tree/main/crypto/circles)
- [Moser's Circles pattern](https://3blue1brown.substack.com/p/revisiting-mosers-circle-problem)。该序列以`1, 2, 4, 8, 16`开头，看起来像2的n次方，但后续则与2的n次方渐行渐远
113. [arc3](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/crp/arc3)
- RC4攻击。与[普通RC4](https://github.com/C0nstellati0n/NoobCTF/blob/main/%E7%AC%94%E8%AE%B0/Tools/%E5%B7%A5%E5%85%B7%E8%84%9A%E6%9C%AC.md#rc4%E5%8A%A0%E5%AF%86%E8%84%9A%E6%9C%AC)不同的是，这里的RC4更像个RNG，S盒为打乱顺序的0-255数字序列，i和j均为随机一个索引，每次输出`S[(S[i] + S[j]) % 256]`。明文的前1000个字节已知，尝试爆破200000轮运行后的RC4的输出序列
114. [random](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/crp/random)
- 64位机器上的C#默认使用`xoshiro256**`作为其PRNG。此题提供了在获取i到i+2000(共2000个输出)个`rng.Next(256)`后如何获取第i-1个`rng.Next(256)`的输出
115. [SSS](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/crp/sss)
- 利用largrange polynomial计算多项式在某一点上的值
- [Fast Fourier transform](https://en.wikipedia.org/wiki/Fast_Fourier_transform)（FFT）以及inverse FFT. FFT is equivalent to evaluating the polynomial at every power of the root of unity used; the inverse FFT (normal FFT using an inverted root of unity) is equivalent to interpolating the polynomial
- Bluestein's algorithm
- 为了理解这题去看了傅里叶分析的介绍： https://zhuanlan.zhihu.com/p/19763358 ，还是啥也不懂
116. [Electronical](https://github.com/D13David/ctf-writeups/tree/main/buckeyectf23/crypto/electronical)
- aes ecb padding oracle attack. 特征是有oracle接收任意输入，拼接上flag后返回整体的加密结果。其他可用脚本：**Electronical**
117. [Real Smooth](https://github.com/nass15456/CTFs/blob/main/BuckeyeCTF/Real%20Smooth.md)
- chacha20 key/nonce reuse+明文攻击。chacha20的算法比较复杂，但是可以简易地理解成“对于明文中的每个字节，生成一个对应的密钥字节与其异或”。不同的key/nonce组合会生成不同的密钥字节（与key不同），因此重用一对key/nonce就成了many time pad。假如已知一对明文和密文，就能异或两者得到完整的密钥字节，进而解码其余密文
118. [coding](https://github.com/cscosu/buckeyectf-2023-public/tree/master/crypto-coding)
- [arithmetic coding](https://www.nayuki.io/page/reference-arithmetic-coding)
119. [Jack’s Worst Trials](https://berliangabriel.github.io/post/tcp1p-ctf-2023/)
- 当python网站使用`jwt.decode()`而没有指定具体使用的算法时，代表可能可以用公钥伪造JWT，然后用HS256算法验证。参考CVE-2017-11424，enables symmetric/asymmetric key confusion attacks against users using the PKCS1 PEM encoded public keys。利用工具 https://github.com/silentsignal/rsa_sign2n 可从两个jwt中计算公钥，然后伪造jwt
120. [Final Consensus](https://berliangabriel.github.io/post/tcp1p-ctf-2023/)
- Meet in the Middle attack(MITM),常用于double encryption scheme：
```
c1=encrypt(k1,plaintext)
c2=encrypt(k2,c1)
```
如果直接爆破k1和k2，时间复杂度为key space of k1\*key space of k2。但是可以把两者拆开，分别计算encrypt(k1,plaintext)和decrypt(k2,c2)。若两者结果匹配，我们就找到了(k1,k2)，时间复杂度要少上不少

121. [Strong Primes](https://blog.bithole.dev/blogposts/ctf-writeups/udctf-strong-primes/)
- python Crypto.Util里的getStrongPrime函数所生成的质数保证p-1里有一个因子是较大的质数。这并不意味着完全安全，因为那个较大的质数减去1仍然可能有很多很小的因子。故基于strongPrime的Diffie–Hellman协议仍然有机率可以使用Pohlig–Hellman算法求得离散对数
122. [Keyshare](https://github.com/eylau-ucsd/ctf-sols/tree/main/LakeCTF/KeyShare)
- ECC invalid curve attack。题目的oracle允许用户输入任意公钥（一个点的x和y坐标），并返回私钥（一个数）乘上公钥的结果。若oracle没有检查用户输入的点是否在程序自己定义的曲线上，即可使用invalid curve attack。攻击者可通过修改服务器上曲线的参数B来生成自己的曲线A，使离散对数在曲线A上的计算更加容易。曲线A的阶可以被分解成若干个小质数，在阶为小质数上的曲线计算离散对数要容易许多。获取多个小质数曲线的离散对数结果后可用CRT恢复原本大曲线上的离散对数。注意这些小质数的乘积要大于原本的大质数，若小于则有多个解，在可接受范围内一个一个试即可。对于这题,`b = 5432486176130386246309866246117127606417222221223493595694`非常光滑，只用一个就能恢复密钥
- 获取私钥k后，根据kP计算P只需乘上k在曲线上的逆元即可
123. [shuffled-aes](https://github.com/LosFuzzys/GlacierCTF2023_writeups/tree/main/crypto/shuffled-aes)
- 如果先执行10轮的SubBytes, AddRoundKey再执行10轮的ShiftRows, MixColumns, AddRoundKey，AES就不再安全了。因为后10轮的操作完全线性可逆，前10轮的操作可以通过请求多组明文密文对搭建对照表格
124. 当使用AES-CTR时，不要用同样的key-nonce pair加密多个明文。见 https://cedricvanrompay.gitlab.io/cryptopals/challenges/19-and-20.html 。因为CTR模式是用明文异或nonce的AES密文得到结果，如果多个明文用同一个nonce，结果就等于many time pad了。此时任意两个密文相异或等同于对应的两个明文异或；如果能猜测到其中一个明文，便能解码另一个明文
- 后面意识到这不仅是aes-ctr的特性，大部分块密码的ctr模式都是这个特点。比如Simon cipher：[Simon Says](https://github.com/rerrorctf/writeups/blob/main/2024_11_10_BlueHens24)
125. [MSS](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/crypto/%5BEasy%5D%20MSS)
- [Mignotte Secret Sharing](https://en.wikipedia.org/wiki/Secret_sharing_using_the_Chinese_remainder_theorem#Mignotte_threshold_secret_sharing_scheme)。一种利用CRT的秘密共享方式
126. [Knapsack](https://meashiri.github.io/ctf-writeups/posts/202312-backdoorctf/#knapsack)
- 当density of the matrix太高时，LLL无法解决这类knapsack问题。不过要是本身供选择的数字集合中的数字较少，可以考虑使用MITM攻击。除了subset sum，subset product也可以用MITM攻击，原理差不多，见subset product题型的[wp](https://tsumiiiiiiii.github.io/fh_crypto/#primes-festival)。设ans为要求的subset sum，将数字集合分为两半，在前一半尝试所有组合的可能性，并用一个字典记录值（记做s1，为key）和对应所使用的数字（为value）。然后尝试后一半所有组合的可能性，记为s2。计算ans-s2，若该键在字典里存在，即找到了目标
- 其他方法：若density只是稍微高了一点，可以随机选择几个数字，将其替换为subset sum里绝对不可能出现的数字。此时矩阵density下降，就能直接使用LLL了；或者爆破几个数字，拿剩下的数字构造density较小的矩阵。或者换种方式用LLL，再或者用BKZ方法: https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#knapsack
    - 有“BKZ可以解出某些LLL解不出来的题”的说法。以下是aparker314159的解释：BKZ is better at finding the shortest vectors than LLL, but it takes longer to run. You can change the BKZ block size parameter to adjust the tradeoff (higher block size means slower but more likely to find shortest vector; LLL is BKZ with block size 2)
    - https://connor-mccartney.github.io/cryptography/other/BackdoorCTF-2023-writeups#knapsack :硬要使用LLL在特殊情况下也是可以的（这篇wp继续加深我对格和LLL的理解）
127. [Drunk](https://meashiri.github.io/ctf-writeups/posts/202312-backdoorctf/#drunk)
- [Fernet](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/cryptography-and-encryption#fernet)对称加密密码。其key和cipher均与base64相似
128. [Curvy_Curves](https://connor-mccartney.github.io/cryptography/other/BackdoorCTF-2023-writeups#curvy_curves)
- William's p+1 factorisation
- 题目文件在[这里](https://tsumiiiiiiii.github.io/bdoorctf/#curvy-curves)可以找到。感觉像ECC上的RSA，同样是分解n后求逆元
129. [Accessible Sesamum Indicum](https://pshegger.github.io/posts/irisctf-2024/#accessible-sesamum-indicum)
- de Bruijn sequence([德布鲁因序列](https://halfrost.com/go_s2_de_bruijn/))。该序列满足任何其期望长度的substring都不会重复（例如期望长度为4，该字符串内任意一个长度为4的substring都不会重复。不同期望长度的德布鲁因序列的构造不同）。可用pwntools的cyclic_gen获取序列
130. [Integral Communication](https://nightxade.github.io/ctf-writeups/writeups/2024/Iris-CTF-2024/crypto/integral-communication.html)
- AES CBC翻转字节攻击。修改第i个块的解密结果后，第i-1块会解密出乱码。基本这种方式只能改一块，因为上一块的解密结果未知。除非以某种方式得知了修改当前块后上一块的解密结果（如题目特殊的oracle）。如修改第二块会影响第一块的解密结果，这时如果也想修改第一块，就要获取其被影响后的解密结果，然后改IV
- 更详细的解析wp： https://amateurs.team/writeups/IrisCTF-2024/integral-communication
131. [manykey](https://connor-mccartney.github.io/cryptography/ecc/manykey-IrisCTF-2024)
- ECDSA私钥伪造。给出一条明文及其签名和对应的公钥，构造一个可通过验证的私钥。验签公式如下： $(\frac{h}{s}\*G+\frac{r}{s}\*Q).x\equiv r\mod n$ 。r和s是签名的一部分，h是要验证的消息hash，G是选择的curve generator，Q是私钥指数d乘上G的结果。补充链接： https://toadstyle.org/cryptopals/61.txt
132. [Burrows–Wheeler Transform](https://www.dcode.fr/burrows-wheeler-transform):密文长得很像栅栏
133. [Music Sheet Cipher](https://www.dcode.fr/music-sheet-cipher):密文类似五线谱里的音符
134. [export-grade-cipher](https://github.com/UofTCTF/uoftctf-2024-chals-public/tree/master/Cryptography/export-grade-cipher)
- wp参考 https://kanzya.github.io/posts/UofTCTF/ 和 https://hackmd.io/@Wrth/UofTCTF-2024-EGC 。据出题人所说，此题为 https://web.archive.org/web/20000302000206/http://www.dvd-copy.com/news/cryptanalysis_of_contents_scrambling_system.htm 里提到的一种经典攻击，专门针对数据打乱类型的密码（Contents Scrambling System）
135. [What Next II](https://github.com/rhaeyx/ctf/tree/main/mapnactf/what-next-2)
- [randcrack](https://github.com/tna0y/Python-random-module-cracker)通过输入32bit的随机数来预测MT19937。如果获取的是256bit的数字(`getrandbits(256)`)，可以用[Extend MT19937 Predictor](https://github.com/NonupleBroken/ExtendMT19937Predictor)直接预测，无需手动将其分解为多个32bit随机数
- 这篇[wp](https://nolliv22.com/writeups/mapna%20ctf%202023/what-next-2)使用randcrack
136. [adapt](https://mystiz.hk/posts/2024/2024-02-03-tetctf-adapt/)
- immutable AVL tree：[cosmos/iavl](https://github.com/cosmos/iavl) （v0.19.7）下的proof伪造。可通过构造特殊node获取一个假的proof，用于证明某个特定的node在tree中不存在（但实际存在）
137. [winter](https://7rocky.github.io/en/ctf/other/dicectf/winter/)
- Winternitz One-Time Signature (WOTS)签名伪造。这是一个单次签名算法，一个私钥只能签名一条信息。若同时签两条，攻击者可以通过第一条消息的签名伪造第二条消息的签名。只需构造一个字符串，使该字符串的sha256输出的每一个字节都大于等于第一条消息的sha256输出的相应字节即可。相似考点在59条winterfactory时就已见过，实际做题时也想到了这个做法，但是没找到符合要求的两条消息……wp作者的做法更聪明，与其随机生成两条消息并比对它们的hash，不如设定一个阈值，让第一条消息的hash值的每个字节都大于这个阈值，而第二条消息的hash值的每个字节都小于这个阈值。或者使用c++爆破hash脚本： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#winter
- 其他wp： https://sylvainpelissier.gitlab.io/posts/2024-02-04-dicectf-winter/ 。利用已知的bitcoin hash加快爆破。这类有特殊性质的hash还可以在 https://beneri.se/hashgame/ 找到
138. [RSA-GCD](https://nolliv22.com/writeups/0xl4ugh%20ctf%202024/rsagcd)
- [modular binomial](https://www.ctfrecipes.com/cryptography/general-knowledge/maths/modular-arithmetic/modular-binomial)的运用
134. [Combinatorial Conundrum](https://github.com/Pamdi8888/My_CTF_Chals/tree/main/Combinatorial%20Conundrum)
- 假如要求满足`sum(x1+...+xN) = R`解的数量，其中0<=x<=R，公式为(N+R-1) 选 (R)；若Li<=x<=R，则：”subtract Li from each limit and also subtract sum(Li) from R, then apply the same formula“
- dp解法： https://writeup.gldanoob.dev/bitsctf/
135. [selamat pagi](https://sheeptester.github.io/longer-tweets/lactf/#cryptoselamat-pagi)
- 针对印度尼西亚语（Indonesian）的字母替换密码的分析及破解。可用工具： https://www.dcode.fr/monoalphabetic-substitution 。其他wp： https://docs.google.com/document/d/19YJiUPCGInwjKSYJaAApLTyc43-Ck_P11GqYTdXIQRI
- 利用wordlist的工具： https://github.com/JorianWoltjer/SubSolver
136. [prove it!](https://tsumiiiiiiii.github.io/lacrypto/)
- zero-knowledge proof:zk-snarks。不过这题其实和零知识证明没啥关系，主要还是利用离散对数和多项式解出目标
137. [SuperAES](https://s1lver-lining.github.io/wu/gcc2024/superaes/)
- 若LCG的模数m不是质数，在几轮迭代后，输出会固定为一个数。具体分析见wp
138. [.png.encrypto](../../CTF/PaluCTF/Writeup.md)
- LFSR已知明文攻击
139. [getting-closer](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/crypto/getting-closer-damn)
- https://math.stackexchange.com/questions/7473/prove-that-gcdan-1-am-1-a-gcdn-m-1 : $gcd(n^a-1,n^b-1)=n^{gcd(a,b)}-1$
140. [Raccoon Run](https://gist.github.com/ky28059/e9d0957313af0d38811e6e845dab7a41)
- 这题是很常规的randcrack预测python随机数。不过`random.getrandbits(32)`的结果被分成了多个部分，重新组装是个问题。另一个做法见 https://gist.github.com/austin-li/b4d1a7222d1b7b5da4b594f758230bb7
- python websocket库使用
141. [lightweight-crypto-guard-system](https://dunglq2000.github.io/mywriteups/TJCTF-2024.html#lightweight-crypto-guard-system)
- LCG的变种。给出LCG的输出 $x_1,x_{n+1},x_{2n+1},x_{3n+1}...$ (共六个)，恢复初始seed和a，b，m参数。其实和给出连续输出的LCG一样，只不过按照公式算出来的a是 $a^n$ ,b也是经过n次周期的结果
- 官方的脚本可能更好理解点： https://github.com/TJCSec/tjctf-2024-challenges/tree/main/crypto/lightweight-crypto-guard-system
142. [Paillien Tourist](https://github.com/L3AK-TEAM/L3akCTF-2024-public/tree/main/crypto/paillien-tourist)
- [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)的加密与解密
143. [Power Over All](https://github.com/Warriii/CTF-Writeups/blob/main/akasec/crypto_power_over_all.md)
- 寻找modular square roots。模某个质数的平方根用sagemath很好找，问题是这题要连续找55个。我就卡在了这点，因为每次可能的平方根都有两个，把这`2*55`个组合起来不知道要多久。我能想到用quadratic residue（二次剩余）淘汰一些根，但是脚本不知道咋写。leetcode白写了，看wp发现某种意义上这是个多源bfs问题
144. [Salad](https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#salad)
- [Unbalanced oil and vinegar scheme](https://en.wikipedia.org/wiki/Unbalanced_oil_and_vinegar_scheme)。个人感觉是个有点繁琐+诡异（对于数学废物）的公钥签名系统。wikipedia不是特别详细，更详细的介绍见这篇[论文](http://www.goubin.fr/papers/OILLONG.PDF)
- 此题的漏洞见论文第7节（pdf第8页）： solve a system of n randomly chosen quadratic equations in n + v variables, when $v ≥ n^2$
145. [dream-revenge](https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#dream-revenge)
- 现在只需要8个输出就能破解python random库的seed了……见 https://stackered.com/blog/python-random-prediction/ 。MT19937你不行啊（doge）
- 用的时候差点没搜到，添加关键词：mersenne twister，python随机数预测
- 如果已知种子是一个32位整数，则只需要6个输出就能破解。见[import rAnDoM](https://github.com/Cryptonite-MIT/niteCTF-2024/tree/main/crypto/import%20rAnDoM)
146. [Many Xor Shift](https://thr34dr1pp3r.gitbook.io/ctf/wanictf-2024/crypto-many-xor-shift)
- 使用矩阵与向量表达异或和位移等操作。常用来加速某些线性操作的组合
- 官方wp： https://qiita.com/KowerKoint/items/89d94343e6ceee32645c
147. [blinders](https://mystiz.hk/posts/2024/2024-06-24-google-ctf-1/)
- 一个[private set membership protocol](https://github.com/google/private-membership)的错误实现。这个协议可以让客户端得知自己手中的某个信息在服务器上有没有，但请求时服务器不会知道客户端手中具体是哪个信息，客户端也不会知道服务器上是否有其它信息
- 这题要求仅用两次query获知服务器上1-256个数字中缺了哪个。思路是，说到两次query找数字x，说明有一种分法可以将任意数字分为两种。于是就想到了奇偶数。叫我做我肯定想不到
148. [ZKPOK](https://mystiz.hk/posts/2024/2024-06-24-google-ctf-2/)
- 完全没看懂这题……作者用的符号标记看不懂……但还是有一些不错的工具可以记录。此题为Zero Knowledge Proof，使用了[Fiat-Shamir transform](https://www.zkdocs.com/docs/zkdocs/protocol-primitives/fiat-shamir/)将交互式的证明转换为无需交互的证明（简单来看就是把随机数的生成交给hash函数来做）
- md5碰撞工具：[fastcoll](https://github.com/brimstone/fastcoll)。给定一段前缀，在前缀后添加两段不同的内容使两者md5 hash值一致
- 如何求解形如 $x^2+ky^2\equiv m\mod n$ 的方程。见论文： https://dl.acm.org/doi/10.1109/TIT.1987.1057350
- 此题的求解脚本： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#ZKPOK
149. [Ilovecrackmes](https://github.com/perfectblue/ctf-writeups/tree/master/2024/googlectf-2024/rev-ilovecrackmes)
- [paillier cryptosystem](https://blog.openmined.org/the-paillier-cryptosystem/)。这个系统有同态的性质。所以在服务器给出一条密文和公钥后，能伪造出含有特定内容的另一条密文
150. [IDEA](https://mystiz.hk/posts/2024/2024-06-24-google-ctf-3)
- [IDEA](https://www.geeksforgeeks.org/simplified-international-data-encryption-algorithm-idea/)密码相关密钥攻击。能够flip密钥的指定bit并加密内容，在可接受的操作数量里恢复完整的key。相关论文： https://www.schneier.com/wp-content/uploads/2016/02/paper-key-schedule.pdf
151. [mceliece](https://github.com/google/google-ctf/tree/main/2024/quals/crypto-mceliece)
- [McEliece cryptosystem](https://en.wikipedia.org/wiki/McEliece_cryptosystem)。此题预期解是实现论文里提到的算法：[Distinguisher-Based Attacks on Public-Key
Cryptosystems Using Reed-Solomon Codes](https://arxiv.org/pdf/1307.6458)
152. [groups](https://github.com/Warriii/CTF-Writeups/blob/main/uiu24/crypto_groups.md)
- 生成一个大于512 bit的carmichael数k，并计算k上的离散对数。生成做法没啥技巧，参考[定理](https://en.wikipedia.org/wiki/Carmichael_number)爆破即可。计算离散对数时因为已经知道了其分解，可以参考wp实现一个自己的pohlig hellman
- 这还有个库：[Carmichael](http://github.com/drazioti/Carmichael)
- 生成carmichael数后计算离散对数也可以用这个网站： https://www.alpertron.com.ar/DILOG.HTM
153. [Key in a Haystack](https://berliangabriel.github.io/post/uiu-ctf-2024/)
- 这题大概是，一堆1024 bit的质数乘上一个40 bit的质数，找到这个40 bit的质数。原来Pollard’s p-1算法只要有一个因子p减上1是B-smooth就能用，所以这题可以自行选定一个较好的B值然后用这个算法碰运气
- 这个[网站](https://www.alpertron.com.ar/ECM.HTM)使用ECM法分解。ECM法复杂度取决于最小的因子，分解出40bit大概是两个小时
154. [Three Line Crypto](https://octo-kumo.me/c/ctf/2024-ductf/crypto/three-line-crypto)
- 一道很特别的异或题。感觉wp的思路值得记录
- 官方解法： https://github.com/DownUnderCTF/Challenges_2024_Public/tree/main/crypto/three-line-crypto 。使用hill climbing算法。这个算法是个概率算法，随机设置key值后用Bhattacharyya coefficient衡量解出的明文是否“足够英语”，如果结果更好就保存。不断重复直到恢复key
- 发现crib drag（已知/猜测明文攻击）解法是最简单的： https://connor-mccartney.github.io/cryptography/other/DUCTF-2024
- 又见到一个使用genetic algorithm（ [遗传算法](https://www.jianshu.com/p/ae5157c26af9) ）的wp: https://gist.github.com/maple3142/a2e30e0face353149f9dd8c9f2dccce9 。和官方wp的hill climbing算法有异曲同工之妙，利用运气随机结果+筛选更好的结果
155. [super-party-computation](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/crypto/super-party-computation)
- Lindell17 TSS protocol(Fast Secure Two-Party ECDSA Signing，见 https://aandds.com/blog/two-party-ecdsa.html )的错误实现导致攻击者可以恢复私钥。相关CVE编号为CVE-2023-33242
156. [tango](https://yun.ng/c/ctf/2024-ictf/crypto/tango)
- Salsa20属于stream cipher，这类密码本质上利用key（有时加个nonce）生成一串内容，然后与明文异或，结果就是密文。所以已知明文就能拿到密码流，key-nonce对不能重用。个人经验，这类stream cipher（还有aes-cbc。应该说是异或的锅）在固定key-nonce pair且有oracle的情况下基本是靠这个性质来伪造密文
- crc32的性质。有多组信息，只要每组信息长度一样且变化的字节位置一致，异或的crc32结果就是一样的。例：
```py
a="abccc"
b="aaccc"
c="adeee"
d="aceee"
assert crc32(a)^crc32(b)==crc32(c)^crc32(d)
```
- 更简单的做法： https://github.com/rerrorctf/writeups/tree/main/2024_07_19_Imaginary24/crypto/tango ，拿已知明文求出部分keystream然后加密自己的内容再拼接原本的密文即可
- [官方wp](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/tree/main/Crypto/tango)又用了crc32的另一个性质：`crc32(x ^ y ^ z) = crc32(x) ^ crc32(y) ^ crc32(z)`
157. [lcasm](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/blob/main/Crypto/lcasm)
- 输入linear congruential generator（lcg）的参数，使其连续输出三个已知的目标值。使用专门解线性模方程的脚本： https://github.com/nneonneo/pwn-stuff/blob/master/math%2Fsolvelinmod.py
- 其他做法： https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#lcasm
158. [Not an active field for a reason](https://yun.ng/c/ctf/2024-deadsec-ctf/crypto/not-an-active-field-for-a-reason)
- Neural cryptography中的[Tree parity machine](https://en.wikipedia.org/wiki/Neural_cryptography#Tree_parity_machine)。怎么也没想到有一天密码学和人工智能能扯上关系……
- 这题大概是让一个Tree parity machine C学习另外两个machine A和B之间建立的关系。有过度拟合的毛病，但这题没关系
- 更详细的wp： https://c0degolf.github.io/posts/writeup/deadsec-ctf/deadsec2024/ 。使用的攻击方式似乎名为[geometry attack](https://arxiv.org/pdf/0711.2411#page=33)
159. [Uncrackable Zip](https://abuctf.github.io/posts/IronCTF)
- 使用bkcrack工具进行zip已知明文攻击。若明文包含换行符，注意换行符使用的是LF还是CRLF。unix/linux使用前者，windows使用后者。提供bkcrack错误的明文会影响密码的破解
160. [Minecraft cipher](https://github.com/kevinychen/flame-ctf-writeups/blob/main/ironCTF-2024/minecraft-cipher.md)
- 给出4个lcg的后23位输出，爆破lcg。因为只有后23位输出有用，所以可以把全部操作看成是模`2^23`下的操作。不过不是很理解wp的爆破逻辑：we can build the correct pair incrementally by computing the possible values of `(a, b) mod 2`, then mod 4, then mod 8, etc. If we know the possible values of `(a, b) mod 2^n`, then the only possible values mod $2^{n+1}$ are `(a, b)`, `(a, b+2^n)`, `(a+2^n, b)`, `(a+2^n, b+2^n)`, and we can filter down to only the values that satisfy the conditions mod $2^{n+1}$
161. [ezLCG](https://github.com/XDSEC/MoeCTF_2024/blob/main/Official_Writeup/Crypto/MoeCTF2024%20Crypto%20Writeup.md)
- 比赛的时候搜了“dsa with lcg”，出来了这篇论文： https://cseweb.ucsd.edu/~mihir/papers/dss-lcg.pdf 。但使用这篇论文的前提是：
    - 获取至少两组dsa签名
    - dsa里生成nonce k的算法用的是lcg
    - 已知dsa和lcg的模数，且知道lcg的参数a

比赛时卡在第三点。题目给了五组签名，但不知道lcg的参数a。看wp才知道这五组签名都有用，正好能提炼出一个模p的一元二次方程。这种攻击应该叫“related nonce attack”吗？

162. [State](https://merkletr.ee/ctf/2024/heroctf/state)
- 给出rc4加密后的sbox（rc4加密会影响sbox，加密后的sbox和加密前就不一样了）和密文，逆向回明文
- 官方wp： https://github.com/HeroCTF/HeroCTF_v6/tree/main/Crypto/State
163. [Halloween](https://github.com/rerrorctf/writeups/blob/main/2024_10_25_HeroCTF24/crypto/halloween)
- [gostcrypto](https://github.com/drobotun/gostcrypto)库ctr模式实现漏洞。gostcrypto中的gostcipher本身没有什么漏洞，但这个库的实现导致ctr模式异或时用的nonce每0xff轮就会重复
164. [sha-home](https://gist.github.com/C0nstellati0n/cf6ae2c5e0e9fe1ecb532d257a56e101#sha-home)
- sha0 hash collision。相关论文： https://iacr.org/archive/fse2008/50860017/50860017.pdf
165. [Just Lattice](https://yun.ng/c/ctf/2024-wwctf/crypto/just-lattice)
- 结果这题和lattice没有关系……题目是个Learning with Errors (LWE)加密方案，本身是安全的加密方案。但这题设置的参数导致可能的私钥空间太小，直接爆破就能得到结果
- 官方wp不是最佳爆破方式，最佳方式见 **Just Lattice**
166. [simple-signing](https://github.com/UofTCTF/uoftctf-2025-chals-public/tree/master/simple-signing)
- 针对python tuple的hash的preimage attack（找到某个hash值的对应的明文）。 https://ctf.0xff.re/2022/fcsc_2022/khal-hash 讲的更详细
167. [Chess](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/crypto_Chess)
- xorshift128 prng破解。这题比较特殊，只能获取prng生成值的lsb，不过还是能利用sagemath的BooleanPolynomialRing构造线性方程组解出state
- 也可以用工具： https://github.com/StroppaFR/mathrandomcrack
168. [Based-sbox](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/crypto_Based-sbox)
- Feistel network类型密码攻击。给定明文对应的密文，要求恢复密钥。这题是7轮的Feistel结构，轮函数`_f`在 $F_{2^{64}}$ 下完全线性，为 $F(x):\frac{1}{x}+c$ ，c为常数。故可以用 $F_{2^{64}}$ 中整数（环？）与多项式环的同构，用sagemath实现一个多项式GF下的Feistel，再用PolynomialRing多项式代表未知的key，跑一遍Feistel，即可构成有关密钥的多项式方程组
- wp利用XL算法（eXtended Linearization algorithm）求方程组的根。和groebner_basis()与ideal()目标差不多，不过XL适合稀疏方程组，在这题的表现下更快。sagemath的gb的基础设置在这题可能会超时，参考 https://github.com/DagurB/informalWriteups/tree/master/srdnlen/basedsbox ，用`singular:slimgb`可以提高速度。或者直接用“更好”的gb实现： https://www.singular.uni-kl.de/Manual/4-0-3/sing_396.htm 。属于密码学中的代数攻击（Algebraic attack）
- 整数转多项式：首先把数字转成二进制，比如0x1b的二进制是`00011011`。然后从右往左看，每个1就代表一个 $x^n$ 项的系数。比如0x1b的多项式表示为 $x^4+x^3+x+1$ 。在这个同构下，异或`^`和加法`+`之间可以相互转换
169. [babyrng](https://github.com/x3ctf/challenges-2025/tree/main/crypto/babyrng)
- 破解splitmix rng。其实论文里已经讲了： https://gee.cs.oswego.edu/dl/papers/oopsla14.pdf 的第13页右下角。然而这题是用haskell，我找到了[源码](https://github.com/haskellari/splitmix/blob/master/src/System/Random/SplitMix.hs)，但是死也看不懂它怎么生成的数字，于是硬生生把源码改了。后面看大家的wp才发现效果等同于模个数而已……
- 其他做法：**babyrng**