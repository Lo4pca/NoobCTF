# happyRSA

题目的power_tower_mod指的是 $a^{a^{a^{...}}}$ ，一共叠k次。让AI帮我分析一下题中幂塔的性质

……然后它就直接给了我 $x\equiv n_{phi}+1\mod (n_{phi})^2$ 的结论。我跑了几轮实验，发现是对的……假如 $a\equiv b\mod m^k$ ，就有 $am^s\equiv bm^s\mod m^{k+s}$ 。继续实验发现 $x-1=n_{phi}(n_{phi}+1)$ 。所以直接对x开方就能得到 $n_{phi}$ ，进而构造一元二次方程解出p和q

```py
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
n = 
e = 
c = 
x = 
s=iroot(x-1,2)[0]+1
discrim = s**2 - 4*n
test, _ = iroot(discrim, 2)
assert _
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
chatgpt的作答：

假设t=p+q-1，a=t+1， $x\equiv a^{\uparrow\uparrow r}\mod t^3$ ,根据[Generalized Binomial Theorem](https://math.libretexts.org/Bookshelves/Combinatorics_and_Discrete_Mathematics/Combinatorics_(Morris)/02%3A_Enumeration/07%3A_Generating_Functions/7.02%3A_The_Generalized_Binomial_Theorem),二项式展开后 $(1+t)^E\equiv 1+Et+\frac{E(E-1)}{2}t^2\mod t^3$ （大于 $t^2$ 的项都被模掉了）

递归中使用了模数 $\phi(t^3)$ ，而 $\phi(m^k)=m^{k-1}\phi(m)$ ，所以 $\phi(t^3)=t^2\phi(t)$

又因为 $a=t+1\equiv 1\mod t$ ，所以无论幂塔有多高，上层指数E都满足 $E\equiv 1\mod t$ ，因为底数就等于1模t，所以无论幂有多复杂，结果都是1

代回上面的二项式展开，就有了 $x\equiv 1+t\mod t^2$

然后继续用 $E\equiv 1+t\mod t^2$ 的结论代入上述二项式展开（可能是因为这一层计算的x就是下一层的E？），得到 $x\equiv 1+t+t^2\mod t^3$

这……这对吗？