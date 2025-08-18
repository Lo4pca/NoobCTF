# d-phi-enc

[题目](https://github.com/y011d4/my-ctf-challenges/tree/main/2023-HackTMCTF-2023/crypto/d-phi-enc)

我裂开了，这题算是比赛里最简单的crypto了，非预期解一大堆，但是我还是没做出来=(。也是，既不会sagemath又不会抽象代数的我，怎么可能做出来……

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from secret import flag
assert len(flag) == 255
e = 3
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
print(f"{n = }")
print(f"{enc_d = }")
print(f"{enc_phi = }")
print(f"{enc_flag = }")
```

题目还算是正常的rsa，但是e很小，同时给出了phi和d的密文。然而flag非常大，导致我们不能用普通低加密指数的思路做。出题人的[预期解](https://github.com/y011d4/my-ctf-challenges/blob/main/2023-HackTMCTF-2023/crypto/d-phi-enc/sol/README.md)思路已经写得很清楚了（但我还是不知道z是哪来的，r.h.s又是什么。未来人报道：这应该是right hand side的缩写）。将d和phi的密文分别记为 $E_d, E_{\phi}$ ，有：

$$
\begin{align*}
0 &= (k\phi + 1)^3 - (ed)^3 \\
&= k^3 E_{\phi} + 3k^2 \phi^2 + 3 k \phi + 1 - e^3 E_d \mod n \\
&= k^3E_{\phi} + 3k^2(1 - p - q)^2 + 3k(1 - p - q) + 1 - e^3 E_d \mod n \\
\end{align*}
$$

$ed\equiv 1\mod phi$ ，于是 $(k\phi + 1)=ed$ 。第二步完全是把数字乘出来;第三步能发现将phi换为了1 - p - q。这是因为在模n下，两者相等。看最后的结果，k不大（经测试永远是2，不过下面的脚本还是爆破了，范围同样不大），可以爆破确切的值，那整个多项式的未知数只有1 - p - q了，把模n转换为m\*n（ $k^3E_{\phi} + 3k^2(1 - p - q)^2 + 3k(1 - p - q) + 1 - e^3 E_d-m\*n=0$ ,同余性质），尝试对该多项式开方，如果开成功了，就能得到p+q的值（原本开出的根应该为1 - p - q，但是脚本写方程时写了1，又把p+q看为一个整体p_q，故开出来的就是p+q了，`1-(p+q)=1-p-q`）。那有了p+q和n（pq），不就能解出p和q了吗？脚本里面是用了另一个变量为z的整数多项式环来开根开出p和q，不过直接解方程也是可以的。

解题脚本如下（加上我查[文档](https://doc.sagemath.org/html/en/tutorial/tour_polynomial.html)的注释）：

```python
from Crypto.Util.number import long_to_bytes

with open("./output.txt") as fp:
    exec(fp.read())

e = 3

for k in range(3):
    for m in range(100):
        PR = PolynomialRing(ZZ, names=["p_q"]) #创建一个整数（ZZ）上的多项式环（PolynomialRing），变量名为p_q
        p_q = PR.gens()[0] #这里不太清楚，感觉是获取多项式环上的变量参与运算
        f = (k^3 * enc_phi + 3 * k^2 * (1 - p_q)^2 + 3 * k * (1 - p_q) + 1) - enc_d * e^3 - m * n
        roots = f.roots()
        if len(roots) > 0:
            print(k, m, roots)
            PR = PolynomialRing(ZZ, names=["z"])
            z = PR.gens()[0]
            g = z ** 2 - int(roots[0][0]) * z + n
            p, q = g.roots(multiplicities=False) #https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_element.html#sage.rings.polynomial.polynomial_element.Polynomial.roots，如果multiplicities=False，仅返回唯一根
            """ var('p q')
            eq1=p+q==roots[0][0]
            eq2=p*q==n
            print(solve([eq1,eq2],p,q)) """#这样也能解出p和q
            phi = (p - 1) * (q - 1)
            d = int(pow(e, -1, phi))
            print(long_to_bytes(int(pow(enc_flag, d, n))))
```

在比赛的discord里看到了另一个更简洁的方法。

```python
from Crypto.Util.number import long_to_bytes

e = 3
n = 24476383567792760737445809443492789639532562013922247811020136923589010741644222420227206374197451638950771413340924096340837752043249937740661704552394497914758536695641625358888570907798672682231978378863166006326676708689766394246962358644899609302315269836924417613853084331305979037961661767481870702409724154783024602585993523452019004639755830872907936352210725695418551084182173371461071253191795891364697373409661909944972555863676405650352874457152520233049140800885827642997470620526948414532553390007363221770832301261733085022095468538192372251696747049088035108525038449982810535032819511871880097702167
enc_d = 23851971033205169724442925873736356542293022048328010529601922038597156073052741135967263406916098353904000351147783737673489182435902916159670398843992581022424040234578709904403027939686144718982884200573860698818686908312301218022582288691503272265090891919878763225922888973146019154932207221041956907361037238034826284737842344007626825211682868274941550017877866773242511532247005459314727939294024278155232050689062951137001487973659259356715242237299506824804517181218221923331473121877871094364766799442907255801213557820110837044140390668415470724167526835848871056818034641517677763554906855446709546993374
enc_phi = 3988439673093122433640268099760031932750589560901017694612294237734994528445711289776522094320029720250901589476622749396945875113134575148954745649956408698129211447217738399970996146231987508863215840103938468351716403487636203224224211948248426979344488189039912815110421219060901595845157989550626732212856972549465190609710288441075239289727079931558808667820980978069512061297536414547224423337930529183537834934423347408747058506318052591007082711258005394876388007279867425728777595263973387697391413008399180495885227570437439156801767814674612719688588210328293559385199717899996385433488332567823928840559
enc_flag = 24033688910716813631334059349597835978066437874275978149197947048266360284414281504254842680128144566593025304122689062491362078754654845221441355173479792783568043865858117683452266200159044180325485093879621270026569149364489793568633147270150444227384468763682612472279672856584861388549164193349969030657929104643396225271183660397476206979899360949458826408961911095994102002214251057409490674577323972717947269749817048145947578717519514253771112820567828846282185208033831611286468127988373756949337813132960947907670681901742312384117809682232325292812758263309998505244566881893895088185810009313758025764867

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic() #https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_element.html#sage.rings.polynomial.polynomial_element.Polynomial.monic ,返回多项式除以系数的结果，不改变原本多项式

def FranklinReiter(f1, f2):
    return int(-gcd(f1, f2).coefficients()[0]) #返回多项式各项的系数

PR.<dd> = PolynomialRing(Zmod(n))
phi = (dd*e - 1)/2 #对照下面，x的值是dd，f是将d转为phi的多项式，两个M分别为d和phi
f1 = dd^e - enc_d 
f2 = phi^e - enc_phi
d = FranklinReiter(f1, f2)

flag = long_to_bytes(int(pow(enc_flag, d, n)))
print(flag)
```

脚本中的`phi = (dd*e - 1)/2`是因为：

$ed\equiv 1\bmod phi$<br>
$ed=k\*phi+1$<br>

根据测试，k永远是2，于是：

$\frac{ed-1}{2}=phi$<br>

这里使用了[Franklin-Reiter相关信息攻击](https://www.ruanx.net/rsa-attack-survey/)，原理可以参照[维基百科](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin%E2%80%93Reiter_related-message_attack)。这个攻击适用于以下情况：

采用相同的密钥对加密了两条消息 $M_1,M_2$ ，且满足 $M_1=f(M_2)\bmod N$ ，其中f是公开的多项式。那么，若e足够小（例如e=3），攻击者可以恢复 $M_1,M_2$ 。

做法如下。攻击者注意到M同时是以下两个多项式的根：

$g_1(x)=f(x)^e-C_1$<Br>
$g_2(x)=x^e-C_2$ 

于是x-M是这两个多项式的公因式。攻击者对 $g_1,g_2$ 做 gcd 即可获得x-M。应当注意，当e够大时，计算 gcd 的代价不可承受。因此 Franklin-Reiter 只能用于攻击e很小的情况。这种方法可以说是很巧妙了。

## Flag
> HackTM{Have you warmed up? If not, I suggest you consider the case where e=65537, although I don't know if it's solvable. Why did I say that? Because I have to make this flag much longer to avoid solving it just by calculating the cubic root of enc_flag.}