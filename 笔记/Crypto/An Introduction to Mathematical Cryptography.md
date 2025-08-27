# [An Introduction to Mathematical Cryptography](https://fenix.tecnico.ulisboa.pt/downloadFile/1407993358931421/An%20Introduction%20to%20Mathematical%20Cryptography%20[Hoffstein-Pipher-Silverman]%20(2014).pdf)

cryptohack服务器里有很多人推荐这本书，让我看看！

## An Introduction to Cryptography

第一章的内容比较基础，懒得做笔记了，直接从基础的题目做起（然而不一定做得出来……）

按正文中提到的练习顺序排序

### Exercise 1.6

（证明`Proposition 1.4`）

1. 如果a|b且b|c，则a|c

a|b说明b=xa,b|c说明c=yb。替换得到c=yxa，于是a|c

另外，我发现我总是记不住整除……b|a表示b能整除a，或者说a能被b整除：a=bc。b|a表示前者是后者的一个因数

2. 如果a|b且b|a，则 $a=\pm b$

a|b说明b=xa,b|a说明a=yb。有a=xya，xy是1。x和y皆为整数，于是要么两者都是1，或者两者都是-1

3. 如果a|b且a|c，则a|(b+c)且a|(b-c)

a|b说明b=xa,a|c说明c=ya。b+c=xa+ya=(x+y)a,b-c=xa-ya=(x-y)a。明显两者都含有a作为其因子

### Exercise 1.14

a和b均为整数，b大于0

1. 证明集合{ $a-bq:q\in Z$ } 中至少有一个非负整数

如果a > b，q=1时a-b为正整数

如果a=b，q=1时a-bq=0

如果a < b，q=0时a-bq=a

无论是哪种情况，均至少存在一个非负整数

2. 让r为`1`中描述的集合中的最小非负整数。证明 $0\leq r$ < b

如果a > b，r=a-bq中明显q越大r越小，此时最小的非负整数r由最大的满足"a-bq大于等于0“的q创造。若 $a-bq>=b$ ，说明此处仍存在更大的q，与前提矛盾。故 $0\leq r$ < b

a=b和a < b的情况下q的取值固定，参考上一题，一定小于b

（很明显我不会做证明题……以后这类题我的目标定为“能较为准确地用非正式语言表达出原因”，或者说“非正式证明”）

3. 证明存在满足 $a=bq+r,0\leq r$ < b的q和r

（我感觉我在1写的东西足够证明了，能给出每种情况下q和r的取值算不算证明它们存在？）

4. 假设有 $a=bq_1+r_1=bq_2+r_2,0\leq r_1$ < b, $0\leq r_2$ < b 。证明 $q_1=q_2$ 且 $r_1=r_2$

$r_1=a-bq_1$ ，因a和b固定，因此如果存在一个 $r_2=a-bq_2\not =r_1$ ，必定有 $q_1\not =q_2$ 。说明两者的差一定是b的倍数。最小的b的倍数是1，假设 $r_2-r_1=b$ ，即使 $r_1$ 取最小值0，仍有 $r_2=b$ ，不满足其应该小于b的定义。因此必须有 $r_1=r_2$ 。 $q_1=\frac{a-r_1}{b}$ , $q_2=\frac{a-r_2}{b}$ 。若 $r_1=r_2$ ，也有 $q_1=q_2$

### Exercise 1.12

1. 证明以下算法计算正整数 a 和 b 的最大公约数 g，以及方程 au + bv = gcd(a, b) 的整数解 (u,v)
    1. 让u=1，g=a，x=0，y=b
    2. 如果y=0，让v=(g−au)/b，返回(g,u,v)
    3. g除以y，余数为t:g=qy+t,0 ≤ t < y
    4. s=u−qx
    5. u=x 然后 g=y
    6. x=s 然后 y=t
    7. 返回第二步

第3步和第5、6步明显是辗转相除法：计算出g除去y的商q和余数t后，转而计算q和t的商和余数，因为两组数的gcd相同。第2步判断y==0就是在看上一个计算的式子余数是否为0，为0的话上个式子的商g就是原a和b的最大公因数。书中`Theorem 1.7 (The Euclidean Algorithm)`已经详细说明了原因

s，u和x我没看出来在干啥。但第二步返回的式子已经说明了为什么方程一定成立: $au+bv=au+b\frac{g-au}{b}=au+g-au=g$ (不过考虑到算法返回时的局限性，可能要证明g-au是b的倍数？)

问了问ai，u和x在每一次循环结束时都满足：
- $g=au+bv_g$
- $y=ax+bv_y$

s则是新一轮辗转相除法中y的等式中a的系数。 $t=g-qy=(au+bv_g)-q(ax+bv_y)=a(u-qx)+b(v_g-qv_y)$ 。而新的g等于旧的y，因此直接u=x即可

二三四五小问分别为实现算法、验证结果、处理b=0的edge case和使返回的u大于0，一起做了：
```py
from Crypto.Util.number import GCD
def egcd(a,b):
    if b==0:
        return a,1,0
    u,g,x,y=1,a,0,b
    while y!=0:
        q=g//y
        t=g%y
        s=u-q*x
        u,g=x,y
        x,y=s,t
    v=(g-a*u)//b
    if u==0:
        u+=b//g
        v-=a//g
    return g,u,v
def check(a,b):
    g,u,v=egcd(a,b)
    return g == GCD(a, b) and a*u + b*v == g
assert check(527, 1258) and check(228, 1056) and check(163961, 167181) and check(3892394, 239847) and check(0,0)
```
### Exercise 1.11

a和b为正整数

1. 假设有整数u和v满足au+bv=1，证明gcd(a,b)=1

假设gcd(a,b)=d,有正整数x和y满足xdu+ydv=d(xu+yv)=1。若 $d\not =1$ ，有 $xu+yv=\frac{1}{d}$ ，不是一个整数。而这是不可能的。因此只能有d=1，即gcd(a,b)=1

2. 假设有整数u和v满足au+bv=6，一定有gcd(a,b)=6吗？如果不是，请给出一个具体的反例，并概述gcd(a,b)的所有可能值（describe in general all of the possible values of gcd(a,b)）

被题目带偏了……我想着gcd(a,b)只有一个固定的值，所以回答“不是”的这个分支肯定是不对的，因为gcd(a,b)哪来的“可能值”？但这题说的“可能值”其实是接下来的这个意思

书接上文，xdu+ydv=d(xu+yv)=6， $xu+yv=\frac{6}{d}$ ，只能推出d|6，推不出d=6。因此如果有au+bv=6，gcd(a,b)的值一定是6的因子，1，2，3或者6

举例：2\*3+2\*0=6，gcd(2,2)=2

3. 假如 $(u_1,v_1),(u_2,v_2)$ 都是方程au+bv=1的解，证明a能整除 $v_2-v_1$ ，b能整除 $u_2-u_1$

$au_1+bv_1-(au_2+bv_2)=0$ ， $a(u_2-u_1)+b(v_2-v_1)=0$ ，所以 $v_2-v_1=-\frac{a(u_2-u_1)}{b}$ ，必须是整数

如果 $b|u_2-u_1$ ，证明完成

……

然后我就卡在这里了

跑去找chatgpt指点，发现我忘记用上一小题证出的结论了……

如果方程au+bv=x有解，说明gcd(a,b)|x。x=1的情况下只有gcd(a,b)=1。 $a(u_2-u_1)=-b(v_2-v_1)$ ，于是 $a|b(v_2-v_1)$ 。因为a和b互质，所以 $a|(v_2-v_1)$ 。 $b|(u_2-u_1)$ 的证明类似

就这么简单……

4. 更一般地，设 g = gcd(a,b)，且 $(u_0,v_0)$ 是 au + bv = g 的一个整数解。证明：对于某个整数 k，所有其他解的形式均为 $u = u_0 + \frac{kb}{g}$ 和 $v = v_0 − \frac{ka}{g}$ （`Theorem 1.11`的第二部分）

$a(u_0 + \frac{kb}{g})+b(v_0 − \frac{ka}{g})=au_0+\frac{akb}{g}+bv_0-\frac{bka}{g}=au_0+bv_0=g$ ，确实是解

问题在于如何证明所有的解都是这种形式

假设有另一组解 $(u_1,v_1)$ 满足 $au_1 + bv_1 = g$ 。如果 $u_1\not =u_0 + \frac{kb}{g}$ , $u_1-u_0\not =\frac{kb}{g}$ ,不存在k使得 $(u_1-u_0)g=kb$

两个方程相减并让两边都乘上g: $ag(u_1-u_0)+bg(v_1-v_0)=0$ , $g(u_1-u_0)=\frac{bg(v_1-v_0)}{a}$ ，矛盾。因此不存在不形如 $u_0 + \frac{kb}{g}$ 的解。v的证明类似

bruh这明显有问题，没法确认式子的右边整除

（又）问了chatgpt，事实证明前提全是整数的证明里不要出现除法，因为没法确认整除；额外再去证明一定整除的话困难且繁琐

假如gcd(a,b)=g，一定有x和y满足gx=a且gy=b，且x和y互质。又到了最好用的两式相减： $a(u_2-u_1)=-b(v_2-v_1)$ ， $gx(u_2-u_1)=-gy(v_2-v_1)$ ， $x(u_2-u_1)=-y(v_2-v_1)$ 。和上一题类似，有 $x|v_2-v_1,y|u_2-u_1$ 。因此存在 $k_1,k_2$ 满足 $k_1x=v_2-v_1,k_2y=u_2-u_1$ ； $u_1=u_2-k_2y=u_2-k_2\frac{b}{g}$ 。v的情况类似，得证

事实又证明，第4小题在第3小题后面是有原因的（

又没注意运用上一小题的结论，吃一堑吃一堑（

### Exercise 1.15

整数 $m\geq 1$ 。假设 $a_1\equiv a_2\mod m,b_1\equiv b_2\mod m$ ，证明 $a_1\pm b_1\equiv a_2\pm b_2\mod m$ ; $a_1b_1\equiv a_2b_2\mod m$

（Proposition 1.13(a)）

$a_1=mx_1+k_1,a_2=mx_2+k_1$ ; $b_1=my_1+k_2,b_2=my_2+k_2$ 。 $a_1+b_1=m(x_1+y_1)+k_1+k_2$ ; $a_2+b_2=m(x_2+y_2)+k_1+k_2$ 。两者除去m的余数都是 $k_1+k_2$ （不过 $k_1+k_2$ 可能大于m，这时就没法说是余数了。但不妨碍两者相等），因此两者在模m的意义下相等。减法的证明类似

我懒得展开乘法的式子了，但是很明显两个式子的展开结果中均只有 $k_1k_2$ 项不是m的倍数。这两者相等，于是原式在模m的意义下相等

另外，在Proposition 1.13(b)的唯一性证明里，不知道为什么式子中突然冒出来个 $\beta_1$ 。可能是打错了？应该是 $b_1$ 的

### Remark 1.16

Z/mZ是Z以主理想mZ构成的商环，而 0,1,...,m−1 实际上是构成 Z/mZ 元素的同余类的陪集代表

我将记录商环的内容直到我能记住它是什么意思（

- mZ={ $mk|k\in Z$ }
- 理想：mZ是Z里的加法子群，且具有吸收性（Z中的任意元素与mZ中的元素相乘仍在mZ中）
- 主理想：由单个元素生成（m）
- 商环Z/mZ：其元素是同余类（cosets），形如a+mZ={ $a+mk|k\in Z$ }
- 代表元（coset representatives）：代表整个同余类，如1可以代表 { $1+mk|k\in Z$ }，因为同余类中的所有元素的余数都是1

（无脑的重复后我开始对这些东西有印象了）

### Exercise 1.25

让N，g和A为正整数（N不一定是质数）。证明以下算法——`Sect.1.3.2(The Fast Powering Algorithm)`的低内存使用变种——返回 $g^A\mod N$ 。 $\lfloor x\rfloor$ 为最大整数函数，即将 x 向下舍入到最接近的整数

1. a=g，b=1
2. 循环直到A=0
3. 如果 $A\equiv 1\mod 2$ ， $b=ba\mod N$
4. $a=a^2\mod N,A=\lfloor\frac{A}{2}\rfloor$
5. 如果A大于0，返回第2步
6. 返回b

好像没什么需要特别证明的？书里已经讲了，可以把指数A写成 $A=A_0+2A_1+2^2A_2+2^3A_3+...+2^rA_r,A_i\in$ {0,1}。 $A_i$ 为A的二进制形式的第i位，算法中模2和除以2的操作就是在取出 $A_i$ 。于是原问题就变成了计算 $g^{A_0}g^{2A_1}g^{2^2A_2}...g^{2^rA_r}$ 。 $g,g^2,g^{2^2},g^{2^{2^2}}...$ ，每一项都是前一项的平方，所以程序可以通过 $a=a^2\mod N$ 不断计算每一项，然后根据 $A_i$ 的值决定是否将当前值乘入b。最后的b自然是 $g^A\mod N$ 的结果

### Exercise 1.28

让{ $p_1,p_2,...,p_r$ }为质数的集合，且 $N=p_1p_2...p_r+1$ 。证明N可以被某个集合外的质数整除。利用这一事实推断质数必定有无穷多个

根据唯一分解定理， $N=p_1^{i_1}p_2^{i_2}...p_m^{i_m}$ 。因集合中的所有质数均无法整除N，但N一定可以唯一地分解成m个不同质数的乘积；因此必定存在一个集合之外的质数整除N

如果质数没有无穷多个，我们便可以构造一个集合列出全部的质数。但利用上方的构造方式构造出的N可以被集合外的质数整除，与先前假设矛盾。因此质数必定有无穷多个

### Exercise 1.31

让p为质数。证明 $ord_p$ 具有如下性质：
1. $ord_p (ab) = ord_p (a) + ord_p (b)$ (因此 $ord_p$ 类似对数，因为它能将乘法转换为加法)

假设 $ord_p(a)=x,ord_p(b)=y$ ，则a的质因数分解里有 $p^x$ ，b的质因数分解里有 $p^y$ 。两者相乘后的结果的质因数分解中自然有 $p^{x+y}$

2. $ord_p(a+b)\geq min(ord_p(a),ord_p(b))$

沿用先前的假设。让 $x \geq y \geq 0$ ， $a=p^xm,b=p^yn$ 。则 $a+b=p^y(p^{x-y}m+n)$ 。若 $p^{x-y}m+n$ 的分解结果中包含p（这种情况只有x=y且p|m+n），则 $ord_p(a+b)$ 大于y，否则等于y。但无论如何都不会小于y

3. 如果 $ord_p(a)\not =ord_p(b)$ ,则 $ord_p(a+b)=min(ord_p(a),ord_p(b))$

基本已经在上一小问看出来了。 $ord_p(a+b)$ > $min(ord_p(a),ord_p(b))$ 的条件是x=y且p|m+n。因为如果x不等于y的话， $p^{x-y}m$ 一定是p的倍数。此时因为n不是p的倍数，所以p一定无法整除 $p^{x-y}m+n$ ，进而 $ord_p(a+b)$ 只能等于y

满足性质1和2的函数称为赋值（valuation）， $ord_p(a)$ 指p在a的质因数分解中的指数

### Exercise 1.43

考虑密钥为 $k = (k_1,k_2)$ 的仿射密码(affine cipher)，其加密和解密函数如下：
- $e_k(m)\equiv k_1m+k_2\mod p$
- $d_k(c)\equiv k_1'(c-k_2)\mod p$
- $k_1'=k_1^{-1}\mod p$

2. 假设p是公共参数，为什么仿射密码无法抵御已知明文攻击（known plaintext attack）？恢复密钥需要多少组明文/密文对？

（1太简单所以跳过）

两组（ $m_1\not=m_2$ ）

$k_1m_1+k_2-(k_1m_2+k_2)=k_1(m_1-m_2)\mod p$ ,  $k_1=(c_1-c_2)*(m_1-m_2)^{-1}\mod p$

$k_2=c_1-k_1m_1\mod p$

4. 假设p不是公共参数。此时仿射密码是否仍受到已知明文攻击？假设如此，恢复私钥大概需要多少组明文/密文对？

（3也跳过因为答案和2一样）

假设拿了三组密文
- $c_1=k_1m_1+k_2-a_1p$
- $c_2=k_1m_2+k_2-a_2p$
- $c_3=k_1m_3+k_2-a_3p$

先把 $k_2$ 消掉:
- $k_1(m_1-m_2)-(a_1-a_2)p$
- $k_1(m_2-m_3)-(a_2-a_3)p$

然后把 $k_1$ 消掉：
- $k_1(m_1-m_2)(m_2-m_3)-(m_2-m_3)(a_1-a_2)p$
- $k_1(m_2-m_3)(m_1-m_2)-(m_1-m_2)(a_2-a_3)p$
- $((m_1-m_2)(a_2-a_3)-(m_2-m_3)(a_1-a_2))p$

这是一个p的倍数。意味着 $(c_1-c_2)(m_2-m_3)-(c_2-c_3)(m_1-m_2)$ 的因子中包含p

拿到p后就和2一样了