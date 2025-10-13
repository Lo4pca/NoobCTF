# Prime_in_prime

$N=2g(2gab+a+b)+1=(2ga+1)(2gb+1)$ 。先前我们已经知道2ga+1和2gb+1为质数，因此目标是找到a和b

$h=\frac{(N-1)}{2g}$ ； $h=2gab+a+b$ 。其中a和b和g的位数差不多，因此 $\frac{a}{g},\frac{b}{g}$ 的整数部分最大只有1。意味着直接将h除以g得到的值非常接近于2ab，最多相差2( $\lfloor\frac{h}{g}\rfloor=2ab+\lfloor\frac{a}{g}\rfloor+\lfloor\frac{b}{g}\rfloor$ )

展开N得到 $N=4abg^2+2ag+2bg+1$ 。如果让 $s_1=a+b,s_2=ab$ ，则有 $N=4g^2s_2+2gs_1+1\Rightarrow s_1=\frac{N-1-4g^2s_2}{2g}$

有了 $s_1$ 后解二次方程 $(x-a)(x-b)=x^2-s_1x+s_2=0$ 就能得到a和b了
```py
#感谢chatgpt帮忙
from Crypto.Util.number import long_to_bytes, inverse
import math
N=
e=
g=
enc=
h = (N - 1) // (2 * g)
t = h // g
for delta in (0,1,2):
    if (t - delta) % 2 != 0:
        continue
    s2 = (t - delta) // 2
    num = N - 1 - 4 * (g**2) * s2
    if num % (2 * g) != 0:
        continue
    s1 = num // (2 * g)
    D = s1*s1 - 4*s2
    if D < 0:
        continue
    sq = int(math.isqrt(D))
    if sq*sq != D:
        continue
    a = (s1 + sq) // 2
    b = (s1 - sq) // 2
    if a*b != s2:
        continue
    p = 2*g*a + 1
    q = 2*g*b + 1
    if p*q != N:
        continue
    print(long_to_bytes(pow(enc, inverse(e, (p-1)*(q-1)), N)))
    break
```