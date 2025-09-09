# [An Introduction to Mathematical Cryptography](https://fenix.tecnico.ulisboa.pt/downloadFile/1407993358931421/An%20Introduction%20to%20Mathematical%20Cryptography%20[Hoffstein-Pipher-Silverman]%20(2014).pdf)

cryptohack服务器里有很多人推荐这本书，让我看看！

## An Introduction to Cryptography

第一章的内容比较基础，懒得做笔记了，直接从基础的题目做起（然而不一定做得出来……）

按正文中提到的练习顺序排序，会跳过一些简单的题

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

### Exercise 1.44

考虑如下定义的希尔密码（Hill cipher）：

- $e_k(m)\equiv k_1m+k_2\mod p$
- $d_k(c)\equiv k_1^{-1}(c-k_2)\mod p$

其中 $m,c,k_2$ 为n维的列向量， $k_1$ 为 $n\times n$ 的矩阵

2. 解释为什么希尔密码无法抵御已知明文攻击

假设有三组明文/密文对：
- $c_1=k_1m_1+k_2\mod p$
- $c_2=k_1m_2+k_2\mod p$
- $c_3=k_1m_3+k_2\mod p$

两两相减得到:
- $k_1(m_2-m_3)\mod p$
- $k_1(m_1-m_2)\mod p$

是一个线性方程组（用行向量表示）：

$$
k_1
\begin{pmatrix}
m_2-m_3 \\
m_1-m_2
\end{pmatrix}
=\begin{pmatrix}
c_2-c_3 \\
c_1-c_2
\end{pmatrix}
$$

（我不想打markdown了，直接来sagemath代码）

```py
#第三小问的例子
P=GF(11)
m1=vector(P,[5,4])
m2=vector(P,[8,10])
m3=vector(P,[7,1])
c1=vector(P,[1,8])
c2=vector(P,[8,5])
c3=vector(P,[8,7])
c=Matrix(P,[c2-c3,c1-c2])
m=Matrix(P,[m2-m3,m1-m2])
k1=c.T*m.T.inverse() #题目用的是列向量，但sagemath用的是行向量
k2=c1-k1*m1
def encrypt(m):
    return k1*m+k2
assert encrypt(m1)==c1 and encrypt(m2)==c2 and encrypt(m3)==c3
```
4. 解释为什么涉及字母排列的简单替换密码可视作希尔密码的特例

$k_2$ 为零向量， $k_1$ 为置换矩阵（[置换矩阵](https://zh.wikipedia.org/wiki/%E7%BD%AE%E6%8D%A2%E7%9F%A9%E9%98%B5)可以把基向量重新排列，完全符合这题的需求）

```py
p_list = [2, 1, 3] #1->2, 2->1, 3->3
perm = Permutation(p_list).to_matrix()
original=vector([1,2,3])
print(perm*original)
```
（二级结论真好用啊）

### Exercise 1.5

(从这里开始，做的是正文没提到的Exercises中比较有意思的题)

假设有一个由26个字母组成的字母表

1. 有多少种简单替换密码？

`26!`，具体分析在书中讲过，见第4页，`1.1.1`

2. 如果某个字母的加密结果是其本身，则称该字母是固定的（fixed）。有多少种简单替换密码满足：
    1. 没有固定字母
    2. 至少有一个固定字母
    3. 正好有一个固定字母
    4. 至少有两个固定字母

（不会证明，最后只有代码）

(1). 让我们使用瞪眼法，写一个函数观察规律
```py
import itertools
letters=''
length=len(letters)
count=0
for i in itertools.permutations(letters,length):
    flag=True
    for j in range(length):
        if i[j]==letters[j]:
            flag=False
            break
    if flag:
        count+=1
        print(f"{''.join(i)} {count}")
```
注意到无论letters的长度是多少，其输出永远可以按开头字母分成n-1组。拿n=5的一组举例：
```
badec 1
baecd 2
bcaed 3
bcdea 4
bcead 5
bdaec 6
bdeac 7
bdeca 8
beacd 9
bedac 10
bedca 11
```
如果剔除开头的b，注意到剩下的字符串中除了以a开头的内容数量是2，其余数量都是3

如果选a，那么剩下的三个字母的排列数量等于`n=3`时的情况；如果选除了a以外的字母，整体四个字母的排列数量等于`n=4`时的情况。于是总结公式：f(i)=(i-1)*(f(i-1)+f(i-2))

实验发现对接下来的几个n都正确，但由于n=26时数量太大，无法模拟来验证公式是否准确

那问问chatgpt吧。我非常确信这道题在组合数学里也有，说不定它能给我搜到正确答案（？）

好的答案正确。这类问题叫错排数（subfactorial，也叫derangement）。上面的式子是等价递推，也有直接的公式：

$$!n=n!\Sigma_{k=0}^n\frac{(-1)^k}{k!}$$

(2). 至少有一个固定字母的排列数量=全排列数量-错排的数量

$$n!-!n$$

(3). 如果一个字母固定的话，剩下的字母必须都是不固定的，即错排数

(4). 一定要用前几小题的结论.jpg

至少有两个固定字母的排列数量=全排数-错排数-只有一个字母固定的排列数量

然后代一下第二小题的结论

=至少有一个固定字母的排列数量-只有一个字母固定的排列数量

```py
import functools
@functools.cache
def derangement(n):
    if n==1:
        return 0
    elif n==2:
        return 1
    else:
        return (n-1)*(derangement(n-1)+derangement(n-2))
def factorial(n):
    if n==0 or n==1:
        return 1
    return n*factorial(n-1)
def one_fixed(n):
    if n==1:
        return 1
    return n*derangement(n-1)
def at_least_one_fixed(n):
    return factorial(n)-derangement(n)
def at_least_two_fixed(n):
    return at_least_one_fixed(n)-one_fixed(n)
```

### Exercise 1.13

让 $a_1,a_2,...,a_k$ 满足 $gcd(a_1,a_2,...,a_k)=1$ 。证明方程 $a_1u_1 +a_2u_2 +···+a_ku_k=1$ 有整数解 $u_1,u_2,...,u_k$

提示：反复使用拓展欧几里得算法，即`Theorem 1.11`

假设 $gcd(a_1,a_2)=g_1$ ，根据`Theorem 1.11`，一定有整数解 $u_{x_1},u_{x_2}$ 满足 $a_1u_{x_1}+a_2u_{x_2}=g_1$ 。然后引入 $a_3$ ,有 $g_1u_{x_3}+a_3u_{x_4}=gcd(g_1,a_3)=g_2$ 。重复以上步骤，最后会得到 $g_{k-1}u_{x_{2k-3}}+a_ku_{x_{2k-2}}=gcd(g_{k-1},a_k)=1$

然后倒推回去。因为有满足 $a_iu_m+a_ju_n=g_{k-1}$ 的整数解 $u_m,u_n$ ，所以也有满足 $a_iu_{m'}+a_ju_{n'}=g_{k-1}u_{x_{2k-3}}$ 的整数解。以此递推回第一项即可完整证明（请忽略我的下标，属于是梦到什么写什么了）

找chatgpt将我的梦话改成更正式的证明：

用记号

$$
g_r=\gcd(a_1,\dots,a_r)\quad(r\ge 2).
$$

**归纳断言（裴蜀对多元）：** 对每个 $r\ge2$，存在整数 $c_{1,r},\dots,c_{r,r}$ 使

$$
g_r=\sum_{i=1}^r c_{i,r}a_i.
$$

- $r=2$ 时，由扩展欧几里得，存在 $c_{1,2},c_{2,2}$ 使

$$
g_2=\gcd(a_1,a_2)=c_{1,2}a_1+c_{2,2}a_2.
$$

- 设命题对 $r-1$ 成立，即

$$
g_{r-1}=\sum_{i=1}^{r-1} c_{i,r-1}a_i.
$$

  再对 $(g_{r-1},a_r)$ 应用二元裴蜀，取整数 $\alpha_r,\beta_r$ 使

$$
g_r=\gcd(g_{r-1},a_r)=\alpha_r\,g_{r-1}+\beta_r\,a_r.
$$

  代入归纳式得

$$
g_r=\alpha_r\Big(\sum_{i=1}^{r-1} c_{i,r-1}a_i\Big)+\beta_r a_r
      =\sum_{i=1}^{r-1} (\alpha_r c_{i,r-1})a_i+\beta_r a_r.
$$

  于是取 $c_{i,r}=\alpha_r c_{i,r-1}\ (1\le i\le r-1)$，$c_{r,r}=\beta_r$ 即可。

归纳完成。最后把 $r=k$ 且 $g_k=\gcd(a_1,\dots,a_k)=1$ 代入，就得到

$$
1=\sum_{i=1}^k c_{i,k}\,a_i,
$$

这就是所求的整数解 $u_i=c_{i,k}$。

（chatgpt额外指出不要用那堆不好追踪乱七八糟的下标）

### Exercise 1.19

假设 $g^a\equiv 1\mod m$ 且 $g^b\equiv 1\mod m$ 。证明 $g^{gcd(a,b)}\equiv 1\mod m$

有u和v满足 $au+bv=gcd(a,b)$ 。 $g^{au+bv}=g^{au}g^{bv}=(g^{a})^u(g^b)^v=1\times 1\equiv 1\mod m$

### Exercise 1.23

m为奇数，a为任意整数。证明 $2m+a^2$ 永远不会是完全平方数

提示：如果一个数是完全平方数，那么它模4的可能值有哪些？

分类讨论：
- 若 $x\equiv 0\mod 4$ ，则 $x^2\equiv 0\mod 4$
- 若 $x\equiv 1\mod 4$ ，则 $x^2\equiv 1\mod 4$
- 若 $x\equiv 2\mod 4$ ，则 $x^2\equiv 0\mod 4$
- 若 $x\equiv 3\mod 4$ ，则 $x^2\equiv 1\mod 4$

可以看出一个完全平方数模4的余数只有0或者1。m是奇数，故可以写成2x+1的形式。所以原式等于 $2(2x+1)+a^2\equiv 2+a^2\mod 4$ 。无论 $a^2$ 模4等于0还是1，其整体模4的结果均不会是0或1

（这题最难的地方已经在提示里了。为什么会想到拿模4作分类啊？）

### Exercise 1.24

3. 解同余方程组：
- $x\equiv 4\mod 7$
- $x\equiv 5\mod 8$
- $x\equiv 11\mod 15$

x=4+7y, $4+7y\equiv 5\mod 8$ ；y=7。因此x=53可以满足前两个式子。此后任何满足53+56k的数都是前两个方程的解

$53+56k\equiv 11\mod 15$ ;k=3。因此x=53+56\*3=221是一个该方程组的解。此后任何满足221+7\*8\*15k的数都是该方程组的解

（crt你好）

4. 如果gcd(m,n)=1，那么：
- $x\equiv a\mod m$
- $x\equiv b\mod n$

对任意a，b有解。并举例说明gcd(m,n)=1是必要的

x=my+a, $my+a\equiv b\mod n,y=(b-a)m^{-1}$ 。只要m和n互质，即 $m^{-1}\mod n$ 存在，一定有解

懒得举例了，总之如果逆元算不出来就寄（

### Exercise 1.27

考虑如下同余方程 $ax\equiv c\mod m$

1. 证明当且仅当gcd(a,m)|c时方程有解

如果gcd(a,m)=1，直接求a的逆元即可解出方程

如果 $gcd(a,m)=g\not =1$ ， $ga'x\equiv c\mod m$ 。若g|c，又可以写成 $ga'x\equiv gc'\mod dm'\Rightarrow a'x\equiv c'\mod m'$ 。重复以上步骤，直至gcd(a',m')=1

若 $gcd(a,m)\not =1$ 且 $g\nmid c$ ，从以上方程可知无法求出g对m的逆元，因此不可解

2. 如果方程有解，证明正好有gcd(a,m)个不同的解

（提示仍然是使用`Theorem 1.11`）

（我不会，请AI教我）

如果有一个解 $x_0$ 满足 $a'x_0\equiv c'\mod m'$ ，对任意 $0\leq t\leq g-1$ ，令 $x_t=x_0+tm'$ ，则 $ax_t\equiv ga'(x_0+tm')\equiv ga'x_0\equiv a'x_0\mod m'$

上述解两两均不相同。若 $x_i\equiv x_j\mod m$ ，则 $x_i-x_j=(t_i-t_j)m'\equiv 0\mod gm'\Rightarrow t_i-t_j|g$ 。唯一的可能性是 $t_i=t_j$

假如有解没有落入上述集合中，意味着某个x满足 $a'x\equiv c'\mod m'$ ,则 $x\equiv x_0,x=x_0+km',k\in Z$ 。让k=qg+r，有 $x=x_0+qgm'+rm'\equiv x_0+rm'\mod m$ 。但r按照定义有 $0\leq r\leq g-1$ ，因此必定落于上述集合中

每个解形如 $x\equiv x_0+t\frac{m}{g}\mod m$ （唯一一处和`Theorem 1.11`有间接关系的地方，此处结论类似当时的结论）

### Exercise 1.33

假设p为质数，有质数q整除p-1

1. $a\in F_p^{\*}$ ， $b=a^{\frac{p-1}{q}}$ 。证明要么b=1，要么b的阶为q

$b^q=a^{p-1}=1$ 。如果另一个q'同样满足这个条件，即 $b^{q'}=a^{\frac{q'(p-1)}{q}}=1$ ;则若将p-1表示为kq，原式等于 $a^{q'k}=1$ 。根据`Proposition 1.29`，a的阶应整除q'k；同时，a的阶应整除qk。除非a=1，否则必然有q'=q

问了下chatgpt，它说思路基本是对的，但是太冗余了（

直接使用`Proposition 1.29`即可。 $b^q=1$ ，因此ord(b)|q。q是质数，因此ord(b)=1或者ord(b)=q。若是前者，说明b=1，否则b的阶就是q

（chatgpt还是说得太轻了）

2. 假设我们要在 $F_p^{\*}$ 里找到一个q阶的元素。利用(1)，我们可以随机选择元素 $a\in F_p^{\*}$ 并检查 $b=a^{\frac{p-1}{q}}\not =1$ 。该检查通过的概率是多少？换句话说，计算如下比例：

$$\frac{\sharp\{a\in F_p^{\*}:a^{\frac{p-1}{q}}\not =1\}}{\sharp F_p^{\*}}$$

提示：使用`Theorem 1.30`(Primitive Root Theorem)

$F_p^{\*}$ 中的每个元素都是某个原根g的x（大于0小于p-1）次方，因此 $a^{\frac{p-1}{q}}=g^{\frac{x(p-1)}{q}}$ 。b是否等于0取决于是否有 $\frac{x(p-1)}{q}\equiv 0\mod p-1$ 。换句话说， $x\equiv 0\mod q$ 。 $F_p^{\*}$ 中能被q整除的数有 $\frac{p-1}{q}$ 个，所以不能被q整除的数有 $p-1-\frac{p-1}{q}$ 。因此题目要求的比例为 $\frac{p-1-\frac{p-1}{q}}{p-1}=\frac{q-1}{q}$

### Exercise 1.35

假设有一个质数p， $q=\frac{1}{2}(p-1)$ 也是一个质数。假设整数g满足：
- $g\not\equiv 0\mod p$
- $g\not\equiv\pm 1\mod p$
- $g^q\not\equiv 1\mod p$

证明g是模p的原根

$g^{p-1}\equiv 1\mod p$ 。如果存在一个更小的数x满足 $g^x\equiv 1\mod p$ ，有x|p-1。根据题目的条件，整除p-1的数只有q和2，且x不会是q。x也不能是2，因为 $g^2\equiv 1\Rightarrow g\times g\equiv 1\Rightarrow g\equiv\pm 1$ 。因此不存在一个这样的x；p-1就是g的阶，进而g是原根

### Exercise 1.36

1. 假设p是一个奇质数，有整数b满足 $p\nmid b$ 。证明b模p要么有两个平方根，要么没有平方根。换句话说，证明 $X^2\equiv b\mod p$ 在Z/pZ下要么有两个解，要么没有解（p=2会发生什么？p|b会发生什么？）

$X^2=b+kp$ 。假设有另外的X'和k'满足 $(X')^2=b+k'p,X^2-(X')^2=b+kp-(b+k'p)=(k-k')p$ ，推出 $p|X^2-(X')^2=(X+X')(X-X')$ 。说明要么p|X+X',要么p|X-X'。得到 $X\equiv X'\mod p$ 或 $X\equiv -X'\mod p$

p=2的话任何b的平方根都是自身，且只有一个。p|b的话 $b\equiv 0\mod p$ ，因此平方根也只有一个，是0

4. 假设p是一个奇质数，g为模p的原根。则任意数a都等于g的某个幂次模p，假设为 $a\equiv g^k\mod p$ 。证明仅在k为偶数时，a模p有平方根

$X^2\equiv g^k\mod p$ 。若k为偶数，可以将其写为 $(g^{\frac{k}{2}})^2$ ，因此 $g^{\frac{k}{2}}$ 就是要求的平方根。而如果k不是偶数就无法将其写成 $(g^y)^2$ 的形式，或者说无法解出2y=k

### Exercise 1.37

假设质数 $p\geq 3$ ，且 $X^2\equiv b\mod p$ 有解

1. 证明对任何指数 $e\geq 1$ ，方程 $X^2\equiv b\mod p^e$ 有解

提示：用归纳法（induction）。通过修改模 $p^e$ 的解给出模 $p^{e+1}$ 的解

（提示拉不动我，还是找chatgpt救吧）

根据条件，e=1时有解，即 $X^2=b+kp$ 对某个k有解

假设指数为k时方程成立：存在整数 $x_k^2\equiv b\mod p^k$ 。再假设存在t使得 $x_{k+1}=x_k+tp^k$ 使得 $x_{k+1}^2\equiv b\mod p^{k+1}$ 。展开 $x_{k+1}^2$ 得到 $t^2 p^{2k}+2tx_kp^k+x_k^2\equiv 2tx_kp^k+x_k^2\mod p^{k+1}$ （马后炮发现这一段是最重要的）

因为 $x_k^2\equiv b\mod p^k$ ，所以存在整数s满足 $x_k^2=sp^k+b$ 。代入上式，得到 $2tx_kp^k+sp^k+b\equiv b\mod p^{k+1}\Rightarrow 2tx_kp^k+sp^k\equiv 0\mod p^{k+1}$ 。在模p的意义下， $2tx_k+s\equiv 0\mod p$ 。需要 $2x_k$ 的逆元在模p下存在才能解出t

若 $p\nmid x_k$ ，则由于质数p大于等于3， $2x_k$ 在Z/pZ中可逆。套用上述公式算出 $x_{k+1}$ 即可

若 $p|x_k$ ，则 $x_k\equiv 0\mod p$ 。代入先前的方程，发现 $x_k^2\equiv 0\mod p^k$ ，因此b=0。易见 $x_{k+1}=0$ 是一个满足更高幂方程的解

### Exercise 1.49

Alice和Bob创造了一个对称密码。k为密钥，明文为d位的整数，或者说 $M=\{m\in Z:0\leq m < 10^d\}$

加密明文时，Alice计算 $\sqrt{k}$ 并保留d位小数，这个小数部分称为 $\alpha$ 。 $c\equiv m+\alpha\mod 10^d$

4. 如果得到一组明文/密文对，且 $10^d$ 相比于k来说很大，可以恢复k吗？