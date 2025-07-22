# [CRYPTOHACK](https://cryptohack.org)

不要再拖了，是时候该好好学学密码学了，不然writeup都看不懂……

理论上应该从最简单的开始，但一位愿意指导我的大佬仅在这个月有空，所以只能赶鸭子上架，从难的开始(･_･;

根据[FAQ](https://cryptohack.org/faq/#solutions)，仅能公开分享Starter和小于等于25分的题的解法。因此这里会记录一些做题的思考和提示（非完整解题思路和脚本）

## [Elliptic Curves](https://cryptohack.org/courses/elliptic/course_details)

我非得学明白你到底是个什么玩意（

### Background Reading

Weierstrass方程 $E:Y^2=X^3+aX+b$ 定义了一个代数曲线，仅当判别式（discriminant） $\Delta=-16(4a^3+27b^2)\not ={0}$ 时，该方程才定义了一个椭圆曲线

椭圆曲线有个特点：可以定义一个名为“点加法（point addition）”操作符，接收曲线上的两个点作为操作符然后输出曲线上的第三个点。取椭圆曲线上的点集（set of points），点加法是一个阿贝尔群运算（满足交换律）
> 由此也可以定义标量与点的乘法。 $Q=[2]P=P+P$ 。标量乘法是ECC里的陷门函数，计算 $Q=[n]P$ 很简单；但给定Q和P，找到满足 $Q=[n]P$ 的n很难

点加法具体的定义在我看来有点“奇特”。选定P和Q，画一条同时穿过两个点的直线，一直画到这条直线穿过曲线上的第三个点R。将R沿y轴反射，得到 $R'=R(x,-y)$ ，最后 $P+Q=R'$

假如要计算的是P+P呢？这回没法“两点确定一条直线”了，但可以通过计算曲线在该点处的切线来确定唯一的一条直线。后面的步骤就和上面一样了

如果确定的直线与曲线不存在第三/二个交点呢？这种情况下我们说直线与点O相交，该点位于每条垂直的线的无穷远处

![point_addition](https://cryptohack.org/static/img/ECClines.svg)

O点为群运算的单位元，P+O=P且P+(-P)=O（负元为点关于x轴的对称点，-P=(x,-y)）

椭圆曲线的定义：椭圆曲线E是满足Weierstrass方程的解的集合，外加一个无穷远点O，同时方程内的a和b必须满足上述判别式，保证曲线上不存在奇点（singularities，奇点处的切线不是唯一的，导致点加法的定义出问题）。曲线上的点加法具有如下性质：
1. P+O=O+P=P
2. P+(−P)=O
3. (P+Q)+R=P+(Q+R)
4. P+Q=Q+P

ECC里学习的是有限域 $F_p$ 上的椭圆曲线，意味着椭圆曲线不再是一个曲线（这里我的理解是，模了p后的点集合已经绘制不出曲线的形状了），而是一堆点的集合，每个点的x,y坐标都是 $F_p$ 里的整数

### Point Negation

在密码学的背景下，我们不再将椭圆曲线视为几何对象（geometric object），而是如下定义的点集合： $E(F_p)=$ { $(x,y)\in F_p,y^2=x^3+ax+b$ } $\cup O$

但上文对于加法的定义不变

有曲线 $E:Y^2=X^3+497X+1768\mod 9739$

要求找到满足 $Q+P(8045,6936)=O$ 的Q。点的负元等于取y坐标的负数，其实就是算 $-6936\mod 9739$ 。直接套模数的定义：-6936=9739\*(-1)+2803

### Point Addition

注意到目前我们对点加法的定义完全是基于几何层面的，甚至需要画图。事实上，存在一个直接根据点的x，y坐标计算结果的算法

此题直接根据伪代码，随便找个语言实现即可。注意伪代码里的a是Weierstrass方程里的a，除法要用模逆元实现

### Scalar Multiplication

同理，也存在直接计算标量乘法的算法。虽然材料中给出的伪代码不是最高效的算法，但是做题够用了

代码无比丑陋，但它确实能跑（
```py
from Crypto.Util.number import *
O=(0,0)
MOD=9739
A=497
def point_add(P,Q):
    if P==O:
        return Q
    if Q==O:
        return P
    x1,y1=P
    x2,y2=Q
    if x1==x2 and y1==-y2:
        return O
    if P!=Q:
        _lambda=((y2-y1)*inverse(x2-x1,MOD))%MOD
    else:
        _lambda=((3*pow(x1,2,MOD)+A)*inverse(2*y1,MOD))%MOD
    x3=(pow(_lambda,2,MOD)-x1-x2)%MOD
    return (x3,(_lambda*(x1-x3)-y1)%MOD)
def scalar_mul(P,n):
    Q=P
    R=O
    while n>0:
        if n%2==1:
            R=point_add(R,Q)
        Q=point_add(Q,Q)
        n//=2
    return R
```

### Curves and Logs

标量乘法好算但是不好逆（离散对数，ECDLP）。即使是效率最高的算法也需要 $q^{\frac{1}{2}}$ 的复杂度，其中点P生成的子群（点P生成的循环子群，通过点P不断加自己得到）的大小为q。非常好的陷门函数

Elliptic Curve Diffie-Hellman Key Exchange协议如下：
- 选定曲线E，质数p，生成器（generator）G，其中G生成的子群H=< G >的阶数为质数q
- A生成随机数 $n_A$ 并计算 $Q_A=[n_A]G$
- B生成随机数 $n_B$ 并计算 $Q_B=[n_B]G$
- A发给B $Q_A$ ，B发给A $Q_B$ 。因为ECDLP的困难性，窃听者无法从这些点中计算出 $n_{A/B}$
- A计算 $[n_A]Q_B$ ，B计算 $[n_B]Q_A$
- 因为标量乘法的结合性， $S=[n_A]Q_B=[n_B]Q_A$
- S为共享的秘密（shared secret）

### Efficient Exchange

注意到在约定好使用的曲线等参数后，传输点坐标时只需传输x坐标，因为另一方可以根据曲线的方程算出y坐标。所以该怎么计算模某个数下的平方根？

这里要补一下数论的概念（我每次看数论都是一如初见……）

若存在某个整数x使得 $x^2\equiv a\mod p$ ，则称a是模p的二次剩余；否则是模p的二次非剩余（不知道为什么我老是被绕晕，简单来说就是在模p的前提下一个数a有平方根就是模p的二次剩余）

这题给的p满足 $p\equiv 3\mod 4$ ，意味着p+1可以被4整除。在这种情况下，a的平方根为 $a^{\frac{p+1}{4}}\mod p$ （当然前提是a是模p的二次剩余）。证明需要用到[欧拉准则](https://zh.wikipedia.org/wiki/%E6%AC%A7%E6%8B%89%E5%87%86%E5%88%99)。已知 $a^{\frac{p-1}{2}}\equiv 1\mod p$ 和 $x\equiv a^{\frac{p+1}{4}}\mod p$ ，有 $x^2\equiv(a^{\frac{p+1}{4}})^2\equiv a^{\frac{p+1}{2}}\equiv a^{\frac{p-1}{2}}\*a=a\mod p$ 。x确实是a的平方根。通常情况下有两个解，另一个根为 $-x\mod p$ ，即p-x
```py
x=4726
y_square=(pow(x,3,MOD)+497*x+1768)%MOD
y=pow(y_square,(MOD+1)//4,MOD)
shared_secret = scalar_mul((x,y),6534)[0]
```
### Montgomery's Ladder

（从这里开始就不在Starter的范围内了）

错误的密码参数选择会导致上述的安全性全部失效。不过吧，即使选择的参数是安全的，错误的实现也会导致这点。侧信道攻击可以通过电路的工作量或是算法运行的时间泄漏出秘密。比如[LadderLeak](https://eprint.iacr.org/2020/615.pdf)，可以完全破坏协议的安全性。关键在于需要让椭圆曲线上的标量乘法永远在常数时间内运行（run in constant time）

Montgomery's Ladder算法可以满足上述要求。这题要求实现一个最基本的版本：Montgomery’s binary algorithm。这个算法的关键在于，无论k的第i个bit是0还是1，需要做的运算都是一个加法和一个倍乘；而最开始介绍的标量乘法则会根据bit的不同选择只执行加法或是额外执行一个倍乘。不过这个算法仍不是最安全的，算法执行的步骤数泄漏了k的bit length，而且if语句的分支会泄漏k的结构。可在[Montgomery curves and their arithmetic](https://eprint.iacr.org/2017/212.pdf)的第16页`A uniform Montgomery ladder`找到改进后的算法（里面还有下面提到的加法和倍乘的简洁实现）

这题的椭圆曲线遵循Montgomery form： $E:By^2=x^3+Ax^2+x$ 。虽然可以转化成Weierstrass form并使用之前实现的算法，但是为什么不直接实现一个Montgomery form上的算法呢？材料已经给出了仿射坐标（用(x,y)表示曲线上的点，还有射影坐标和雅可比坐标。仿射坐标是最好理解的，但是计算效率比后两者低）下加法和倍乘的伪代码

其他材料:
- 射影坐标（projective coordinates）相关的公式： https://eprint.iacr.org/2017/293.pdf
- [Montgomery curves and the Montgomery ladder](https://eprint.iacr.org/2017/293.pdf)

题目的只给了x，于是y要自己算。这题的p是 $p\equiv 1\mod 4$ ，不能用上面的方法计算平方根了。直接用通用的： https://gist.github.com/nakov/60d62bdf4067ea72b7832ce9f71ae079

最后用不同的y算出来两个点的x是一样的。因为Doubling formula中 $\alpha$ 的计算其实是曲线在点P处的切线斜率（隐函数求导），最后算出来的值只有符号不同，而符号不会影响后续 $\alpha^2$ 的值

### Smooth Criminal

题目使用的曲线的阶数并不是质数(阶数的分解结果中不包含大素数)。因此可以用Pohlig-Hellman算法将DLP分成若干个小问题，大大降低复杂度

因为生成器G生成了整个曲线，所以曲线的阶等于G的阶

假设G的阶数 $q=p_1^{e_1}p_2^{e_2}...p_k^{e_k}$ ，给定Q，目标是计算k使得Q=k\*G

首先对每个 $p_i^{e_i}$ 计算 $k\mod p_i^{e_i}$ 。计算对应的子群生成元 $G_i=\frac{q}{p_i^{e_i}}G$ , $Q_i=\frac{q}{p_i^{e_i}}Q$ 。此时 $G_i$ 的阶为 $p_i^{e_i}$ ，问题转化为在 < $G_i$ >中求解 $Q_i=k_iG_i$

得到所有 $k_i$ 后用crt即可组合出完整的k

见 https://connor-mccartney.github.io/cryptography/ecc/PrivateCurve-0xl4ughCTF2024

### Curveball

题目使用的fastecdsa库： https://github.com/AntonKueltz/fastecdsa

注意到没有限制private_key的大小，如果输入的d超过了generator的阶会发生什么？会得到点本身，等同于乘上1

### ProSign 3

题目使用的ecdsa库： https://github.com/tlsfuzzer/python-ecdsa

`randrange(1, n)`的n并不是一开始定义的`g.order()`，而是`int(now.strftime("%S"))`……

### Moving Problems

mov攻击： https://risencrypto.github.io/WeilMOV

mov攻击将椭圆曲线群上的离散对数问题转换成有限域乘法群中的离散对数问题（ecdlp转成dlp）。一些前置知识：

双线性映射（bilinear map）：
- 设U，V，W为向量空间，{ $u,u_1,u_2\in U$ }, { $v,v_1,v_2\in V$ }， $\alpha$ 是标量
- $f_1:V\rightarrow W$ 是线性映射，如果 
    - $f_1(v_1+v_2)=f_1(v_1)+f_1(v_2)$
    - $f_1(\alpha v)=\alpha f_1(v)$
- $f_2:U\times V\rightarrow W$ 是双线性映射，如果
    - $f_2(u_1+u_2,v)=f_2(u_1,v)+f_2(u_2,v)$
    - $f_2(u,v_1+v_2)=f_2(u,v_1)+f_2(u,v_2)$
    - $f_2(\alpha u,v)=\alpha f_2(u,v)=f_2(u,\alpha v)$
    - 即，如果v固定，该映射在u上是线性的；反之亦然

单位根（Roots of Unity）：
- t是n次单位根，如果 $t^n=1$
- 阶数为质数q的有限域中的任何元素a都是q-1次单位根（拉格朗日定理， $a^{q-1}\equiv 1\mod q$ ）

扩域（Extension Field）：
- 给定一个有限域 $F_q$ ，可以构造一个扩域 $F_{q^t}$ 。扩域仍然是一个域，有加法、乘法、逆元；域中的元素是在 $F_q$ 上的多项式（多项式的系数是 $F_q$ 中的元素），模一个不可约多项式来构造
- 所有 $a\in F_{q^t}$ 的阶要么是 $q^t-1$ ，要么是某个整除 $q^t-1$ 的数
- 于是对于 $F^{q^t}$ 中的所有非零元素，都有 $a^{q^t-1}=1$
- 因此扩域中的所有非零元素都是 $q^t-1$ 次单位根

嵌入度（Embedding Degree）：
- 假设E是质数域 $F_q$ 上的椭圆曲线；P是m阶的点且m是质数，与q互质
- 如果k是满足 $q^k\equiv 1\mod m$ 的最小正整数，则称k为曲线 $E(F_q)$ 关于m的嵌入度

挠点和挠群（Torsion Points and Torsion Groups）：
- E是质数域 $F_q$ 上的椭圆曲线。满足mP=O的点 $P\in E(F_q)$ 称为m挠点。 $E(F_q)$ 中的所有m挠点构成的子群称为 $F_q$ 的m挠子群。记为 $E(F_q)[m]=$ { $P\in E:mP=O$ }
- 因为 扩域 $F_{q^t}$ 大于基域 $F_q$ ，所以扩域上的m挠群很有可能大于基域上的m挠群。当t等于曲线关于m的嵌入度时得到的m挠群最大（比 $F_{q^k}$ 更大的扩域无法增加更多的m挠点）。因此 $E(F_{q^k})[m]$ 称为满m挠群（full mtorsion group），其中k是曲线关于m的嵌入度
- 满m挠群拥有多个子群，下文的Weil Pairing会用到其中两个
    - $G_1$ : 该子群中的全部点都在 $E(F_q)$ 中
    - $G_2$ : 该子群中的全部点都在 $E(F_{q^k})$ 中且都不在 $E(F_q)$ 中。有多个子群满足这点，随便选一个即可

韦伊配对（Weil Pairing）：
- 假设k是曲线关于m的嵌入度 $q^k\equiv 1\mod m$ ，这个式子可以变形成 $q^k-1=mx$ ，因此m整除 $q^k-1$
- 考虑扩域 $F_{q^k}$ 。该扩域的乘法群 $F^{*}_{q_k}$ (去掉了零元素)的阶为 $q^k-1$ 。因为m整除这个乘法群的阶，所以它有一个唯一的m阶子群 $G^T$ (循环群基本定理,Fundamental Theorem of Cyclic Groups)
- 当满足额外的条件 $m\nmid (q-1)$ 时，可以构造韦伊配对，或者说 $G_1\times G_2\rightarrow G_T$ 的映射 $e_m$ 。 $e_m$ 接收一对m挠点A和B作为输入， $A\in G_1$ 且 $B\in G_2$ ；输出 $e_m(A,B)$ 为一个m次单位根，即 $e_m(A,B)^m=1$
- 双线性：
    - $e_m(A_1+A_2,B)=e_m(A_1,B)\*e_m(A_2,B)$
    - $e_m(A,B_1+B_2)=e_m(A,B_1)\*e_m(A,B_2)$ （注意这里的双线性是乘法，而不是加法）
    - 假设 $G_1,G_2$ 分别为两个椭圆曲线群的生成器， $\alpha,\beta$ 为常量。有 $e_m(\alpha G_1,\beta G_2)=e_m(\beta G_1,\alpha G_2)=e_m(\alpha\beta G_1,G_2)=e_m(G_1,\alpha\beta G_2)=e_m(G_1,\alpha G_2)^{\beta}=e_m(G_1,G_2)^{\alpha\beta}$
- 单位元为 $e_m(A,A)=1,\forall A\in E[m]$
- 交替性（Alternation）： $e_m(A,B)=e_m(B,A)^{-1},\forall A,B\in E[m]$
- 非退化性（Non-Degeneracy）：
    - $e_m(A,O)=1,\forall A\in E[m]$
    - 如果 $e_m(A,B)=1,\forall B\in E[m]$ ，则A=O
- 更详细的数学背景见 https://crypto.stanford.edu/pbc/notes/elliptic/weil2.html 。但不建议非数学专业或没有强大数学背景的人阅读。“密码学家应该将其视为一个黑盒的神奇玩意”

好的终于到mov攻击了

考虑 $F_q$ 上的椭圆曲线E。给定满足Q=rP的均为质数m阶的P和Q，目标是找到r。ecdlp。因为P是m挠点且这个点在基域上的曲线中，于是 $P\in G_1$ (Q同理)

攻击步骤：
1. 计算扩域上的椭圆曲线的阶（ $n=\sharp E(F_{q^k})$ ）。因为 $E(F_q)$ 的m挠群是 $E(F_{q^k})$ 的子群，m整除n（拉格朗日定理）
2. 选择一个随机点 $T\in E(F_{q^k})$ ，满足 $T\not\in E(F_q)$
3. 计算 $S=(\frac{n}{m})T$ 。如果S=O，返回第二步；如果S不是O，则它是一个m阶的点。证明如下：
- $S=(\frac{n}{m})T$
- mS=nT
- 假设T的阶为t。根据拉格朗日定理，t整除 $E(F_{q^k})$ 的阶。因此n可以被写作n=dt。因此mS=dtT
- 因为tT=O，dtT=O
- 所以mS=O，S的阶数是m
4. $P,rP\in G_1,S\in G_2$ 。计算两个韦伊配对值：
- $u=e_m(P,S)$
- $v=e_m(rP,S)$
- $u,v\in F_{q^k}$
- 因为韦伊配对是双线性的且r是常量，有 $v=e_m(P,S)^r$ 。因为 $u=e_m(P,S)$ ,可得 $v=u^r$ 。这是乘法群 $F_{q^k}$ 上的dlp
5. 如果 $q^k$ 不大，则对于 $u=v^r$ ，可以借助index calculus找到r

### Exceptional Curves

虽然曲线的阶是质数，但是阶完全等于p了。这是[Anomalous Elliptic Curves](https://www.monnerat.info/publications/anomalous.pdf)，可以用smart attack

见 https://connor-mccartney.github.io/cryptography/ecc/Elliptic-GCC-CTF-2024

### Micro Transmissions

从`Smooth Criminal`中得知，如果想要防止攻击者用pohlig hellman求n，就要保证G的阶的分解结果中包含大素数。这样即使攻击者拿到了几个小素数因子上的ecdlp，crt也组不出完整的n

但如果n本身就很小呢？此时小素数因子上的ecdlp就已足够恢复n了

### Elliptic Nodes

两个曲线的点足以恢复a和b。然后就会发现这是个奇异曲线（sagemath定义曲线时会报错）

这篇[论文](https://people.cs.nycu.edu.tw/~rjchen/ECC2012S/Elliptic%20Curves%20Number%20Theory%20And%20Cryptography%202n.pdf)的2.10（73页）讲述了这种情况。奇异曲线就是有奇点（singular point），奇点是多项式 $x^3 + ax + b$ 在域k上的重数（multiplicity）大于1的根。有两种情况：
- 尖点（cusp）。曲线方程形如 $y^2=(x-\alpha)^3$ ，奇点位于 $(\alpha,0)$ 。除去这个奇点外，剩下的点构成的群与域 $F_p$ 上的加法群同构
- 节点（node）。曲线方程形如 $y^2=(x-\alpha)^2(x-\beta)$ ，奇点位于 $(\alpha,0)$ 。除去这个奇点外，剩下的点构成的群与域 $F_p$ 的扩域上的乘法群同构

至于怎么判断题目的曲线是哪种情况，解出多项式 $x^3 + ax + b$ 的根后找到重数（multiplicity）为2的根，利用函数偏移的技巧就能确认属于哪种情况：
```py
f = x^3 + a * x + b
f2 = f.subs(x=x+shift)
print(f2.factor())
```
见 https://github.com/elikaski/ECC_Attacks?tab=readme-ov-file#the-curve-is-singular

### Digestive

题目取消了hash，直接返回消息本身。我想着协议要求必须hash消息肯定是有深意的吧？可能是可以通过已知的签名伪造别的消息的签名之类的？但我没找到方法

结果这题的关键和密码一点关系也没有。调试了ecdsa库的源码（sign_number函数），发现其sign的消息是截断了的，意味着加长json而不修改json前面的内容不会修改number

最后是一点点python的特性。json重复键只会取最后一个键

### Double and Broken

想复杂了。前文说到double and add算法根据bit的不同执行的操作也有所不同。于是我根据之前做的类似能量分析题的经验，以为要画图看bit与操作之间的对应关系：
```py
import matplotlib.pyplot as plt
import numpy as np
data = eval(open("collected.txt").read())
arr = np.array(data)
column_means = np.mean(arr, axis=0)
plt.figure(figsize=(4, 4))
plt.plot(column_means, linestyle='-', linewidth=1, color='blue') 
plt.title('Data Visualization')
plt.xlabel('Index')
plt.ylabel('Value')
plt.grid(True)
plt.legend()
plt.show()
```
但是横竖看不出来东西。只能从已知的flag前缀入手，查看其二进制位和数据有没有什么关联

结果题目给的能量是double and add算法的for循环消耗的能量。其实很简单，耗能较多的就是1，因为执行了两个操作；否则就是0

也难怪plot不出来东西。for循环才执行了多少次啊（

### No Random, No Bias

看到sha1+拼接的操作后的第一反应是hash extension attack。我这个脑子疑似有点过拟合了。这题控制不了拼接的内容，明显不是

sha1完全是障眼法。关键在于sha1的hash size只有160 bit，而ecdsa使用的曲线是256 bit的。short nonce attack，这篇[文章](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care)的`Breaking ECDSA from bad nonces`章节有提到这篇论文： https://eprint.iacr.org/2019/023.pdf 。在4.5（论文第7页）可以看到一个式子：

$k_i-s_i^{-1}r_id-s_i^{-1}h_i\equiv 0\mod n$

$k_i-(s_i^{-1}r_id+s_i^{-1}h_i)=k_i-(s_i^{-1}(r_id+h_i))=k_i-(k_i(h_i+dr_i)^{-1}(r_id+h_i))\equiv 0\mod n$

这是一个论文前面提过的hidden number problem（4.1，第5页）

直接套现成的脚本 https://github.com/jvdsn/crypto-attacks/blob/master/attacks/hnp/lattice_attack.py

### Edwards Goes Degenerate

发现cryptohack的题目名称很多时候是个提示。于是搜索题目名，得到了这个： https://crypto.stackexchange.com/questions/103954/breaking-ed25519-discrete-logarithm-with-degenerate-curve-attack 。里面又提到了这个： https://crypto.stackexchange.com/questions/98499/ed25519-attacks

说当点(0,y)计算标量乘法时，根据Twisted Edwards Curves的仿射坐标加法公式，得到的结果是 $(0,y^k\mod p)$ 。意味着直接拿y坐标对着p做dlp就能解出私钥k了

### Real Curve Crypto

实数域上定义的椭圆曲线。[先前](https://crypto.stackexchange.com/questions/51198/is-ecc-over-real-numbers-possible)确实有人讨论过这个问题。据说可以用数值分析这个方向的方法（numerical approximation）做，但最终我也不知道怎么做……动用一下大佬之力

于是又到了喜闻乐见的“哇[wp](https://hackmd.io/@grhkm/By-_iF795)甩我脸上我都看不懂”时间。当我意识到文章前半部分只用了大佬20分钟的时间理解后，我明白这不是我该来的地方

核心结论如下（只能做个无脑的tldr，保留结论忽略过程）：

定义在复数域上的椭圆曲线 $E(C)\cong C/\Lambda$ ，其中 $\Lambda=Z\omega_1+Z\omega_2$ 。群同构为 $\phi: C/\Lambda\rightarrow E(C),z\mapsto(℘(z),℘'(z)),0\mapsto\infty$

题目的ecdlp等同于 $n℘^{-1}(g_x)\equiv ℘^{-1}(p_x)\mod\Lambda$ ，可用LLL求解

℘是Weierstrass ℘-function，定义为 $℘(z)=℘(z;\Lambda)=z^{-2}+\Sigma_{\omega\in\Lambda,\omega\not={0}}(\frac{1}{(z-\omega)^2}-\frac{1}{\omega^2}),z\not\in\Lambda$

由此可以推导出一个微分方程： $℘'(z)^2=4℘(z)^3-g_2℘(z)-g_3$ 。其中 $g_2$ 和 $g_3$ 为某些常数项，具体的定义可以忽略。不难看出，这个东西很像椭圆曲线。于是就有了上述的映射

作者已在wp的最后放出了求解脚本，不过好像少了算 $\omega_2$ 的部分。根据wp内容， $\omega_2=\frac{\pi}{M(\sqrt{e_3-e_1},\sqrt{e_3-e_2})}$ ，其中 $e_1,e_2,e_3$ 可以通过分解曲线方程 $x^3 - x$ 得到，满足 $e_1$ < $e_2$ < $e_3$

拿到flag后，建议看看其他人的solutions。`neobeo`的解法似乎很像最开始提到的数值分析方法

### A Twisted Mind

在做其他题的时候见过“twisted”这个词，于是意识到题目名再次是个提示： https://crypto.stackexchange.com/questions/19877/understanding-twist-security-with-respect-to-short-weierstrass-curves 。这个链接已经包含了一个示例，跟着做就可以了。不过后续我发现示例里求某个阶的点那一步不是必须的，这步只是为了方便用sagemath内置的discrete_log。如果自行实现pohlig hellman算法的话就不用管。见 https://7rocky.github.io/en/ctf/other/ecsc-2023/twist-and-shout

这题仍然属于invalid curve attack，因为题目没有检查输入的x点在不在定义的曲线上。区别在于题目使用的算法同时依赖了a和b参数，因此一般的依赖于修改参数b的invalid curve attack就不能用了。但是曲线的quadratic twist无需修改a和b参数，只需将曲线放到扩域 $F_{p^2}$ 中。测试一下，发现当某个x坐标处于 $E^2$ 但不处于E中时，题目的scalarmult算的是 $E^2$ 中的结果

E和 $E^2$ 的阶的分解结果除了最后一个因子，剩下的都挺小的。于是在E中选一个点， $E^2$ 中选一个点，只求两者相对于几个小因子的ecdlp；最后crt组出完整的privKey。需要两个点是因为无论单独在哪个曲线上求ecdlp的bit数都不够大（我这里还脑抽了一下，全部在 $E^2$ 中选点，妄想着找到个阶与已知点互质的点进而搞crt……但凡学点群论就知道这有多荒谬了）

### Checkpoint

注意到服务器再次没有验证点是否在曲线上，而且使用的点加算法不依赖参数b。这不就是我上道题说的“一般的invalid curve attack”吗？

https://crypto.stackexchange.com/questions/71065/invalid-curve-attack-finding-low-order-points 里提到了一篇[论文](http://tomlr.free.fr/Math%E9matiques/Math%20Complete/Cryptography/Guide%20to%20Elliptic%20Curve%20Cryptography%20-%20D.%20Hankerson,%20A.%20Menezes,%20S.%20Vanstone.pdf)。链接里提到的那一段在pdf的203页。理是这么个理，但是怎么生成低阶数的点？

翻到了先前记录的wp： https://affine.group/writeup/2024-06-Codegate-Babylogin 。wp的情况和这题太像了，都是不看参数b的invalid curve attack，就连符号的问题都是一样的：由于服务器生成key时只看x坐标，导致生成key的数有两种可能，s模点的阶数和-s模点的阶数。这里我选择了文章提到的method 3， https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2023/10/0073-invalid_curve.pdf 的第9页。这个方法的优点是简单易懂，弊端是需要的query数量比其他方法多。幸好这题不限制query数量，于是就没缺点了

另外服务器接收点时接受的是hex格式……我竟然被这玩意卡了至少半个小时……

### An Evil Twisted Mind

注意到模数不是质数。一些合数模数上的椭圆曲线资料：
- https://crypto.stackexchange.com/questions/72613/elliptic-curve-discrete-log-in-a-composite-ring
- https://zhuanlan.zhihu.com/p/643176962 （Keymoted）

假如n=pq，那么模n的椭圆曲线等同于相同a，b参数的曲线模p和模q然后合在一起。如果计算点加法A+B的话，等同于把点分别映射到p和q对应的曲线上（x和y坐标模p和q），即将A分成 $A_p$ 和 $A_q$ ，B分成 $B_p$ 和 $B_q$ ，再加在一起： $(A_p+B_p,A_q+B_q)$ 。两个曲线运算时互不干扰。假如任何一个运算等于无限远点，那么A+B的结果不存在于模n的曲线上。所以有将其称作“pseudocurve”的，因为它的运算不封闭，不是群

算标量乘法kA也类似。先计算模p上的 $kA_p$ ，再计算模q上的 $kA_q$ ，然后crt将两个x,y坐标对合在一起。计算ecdlp同理，在模p上算出满足A=xB的x，然后再算模q上的，然后crt组出完整的模n下的x

但是吧，题目没有任何地方提示n可能形如pq，也不像keymoted那道题一样给出分解n的提示。这怎么搞？

摇人。佬说可以用cado-nfs分解：cado在可接受的时间内能分解大约300 bit的数（即这道题）；500 bit需要几天；1024 bit不用想了，还是挺安全的

尝试用`A Twisted Mind`中构造twist的方法，但是发现分解 $p^2$ 上的曲线的阶很慢。后面发现需要用sagemath内置的`quadratic_twist`方法（在之前的[链接](https://crypto.stackexchange.com/questions/19877/understanding-twist-security-with-respect-to-short-weierstrass-curves)中已经知道了 $p^2$ 上的曲线与这个方法返回的曲线其实是同构的），这个方法得到的曲线的阶比较光滑，而且好分解

后面的思路就和上一道题很像了。只是这次要找的点需要同时满足不在 $F_p$ 和 $F_q$ 的曲线上，但在两者的quadratic twist上

看`7rocky`的解法时我有些不明白他为什么这么构造：
```py
dp, dq = Fp(1), Fq(1)

while dp.is_square() or dq.is_square():
    dp += 1
    dq += 1

dEp = Ep.quadratic_twist(dp) #quadratic_twist的参数要求不是域中的平方数
dEq = Eq.quadratic_twist(dq)

assert Ep.order() + dEp.order() == 2 * p + 2 #为什么？
assert Eq.order() + dEq.order() == 2 * q + 2

factors_p = factor(dEp.order())
factors_q = factor(dEq.order())

for i in range(0, 10000, dp):
    try:
        Ep.lift_x(Fp(i))
    except:
        Pp = dEp.lift_x(Fp(i * dp * 4)) #为什么要乘上dp再乘4？
        try:
            Eq.lift_x(Fq(i))
        except:
            Pq = dEq.lift_x(Fq(i * dq * 4))
            break
```
`HappyHacker22`用了 $p^2$ 上的曲线（阶可能是cado-nfs分解的）。如果这么做的话需要手动设置点的阶数，不然sagemath又会分解一遍阶

最后的最后，事实上这题不需要用cado-nfs分解n。`IcingMoon`指出，题目给的order大小大概是模数的平方根，很有可能是 $E_p$ 的阶。所以对于 $E_p$ 中的任意一点，拿阶数与P相乘会得到无限远点。而Montgomery/Brier–Joye ladder中无限远点的z坐标为0。于是模n的曲线上的结果的z坐标与n的gcd可能为p（不确定怎么得到这点的，可能也和crt有关？）

### An Exceptional Twisted Mind

https://affine.group/writeup/2021-01-Zer0pts#pure-division

因为 $Z/p^2Z\subset Z_p\subset Q_p$ ，所以可以像处理Anomalous curve（smart attack）那样将E用change_ring换到 $Q_p$ 来解ecdlp

## [Lattices](https://cryptohack.org/challenges/post-quantum)

### Gram Schmidt

实现算法。但是我发现我不是很明白材料给的伪代码，于是找了原书[An Introduction to Mathematical Cryptography](https://isidore.co/CalibreLibrary/Hoffstein,%20Jeffrey/An%20Introduction%20to%20Mathematical%20Cryptography%20(2nd%20ed.)%20(7710)/An%20Introduction%20to%20Mathematical%20Cryptograp%20-%20Hoffstein,%20Jeffrey.pdf)里的描述（pdf第400页），清晰多了

### Find the Lattice

首先先看看这个密码系统为什么能行

decrypt中的`a=f*e`等同于`fhr+fm`,代入h的公式得 $f\*f^{-1}\*g\*r+f\*m=g\*r+f\*m\mod q$ 。然后`(a*inverse(f, g)) % g`等于 $f^{-1}\*g\*r+f^{-1}\*f\*m=f^{-1}\*g\*r+m$ 。整体模g后就剩下m了

然后就是找线性表达式了。decrypt里面的算式基本不用看，因为大部分值都是未知的。encrypt里可以得到类似`hr-kq-e=-m`的算式。不过我不确定这有没有搞头。题目描述说可以用二维lattice reduction得到答案，但这怎么看都要三维吧？秉承着“我要跟着hint走”的理念，得找找别的

gen_key中的h满足 $fh-g\equiv 0\mod q$ ，换句话说有fh-kq=g。诶这个看着就很二维了。把式子扩张成向量的写法：`f*(h,1)+(-k)*(q,1)=(g,f-k)`，试一下发现确实能得到g，进而得到f，进而decrypt出m

后续翻solutions发现，上述做法能成功的原因是g最大被限制在q/2,即q的一半；f最大也是q的一半，k差不多也是q的一半。因此`(g,f-k)`是格里的最短向量

另外，`7Rocky`的解法用到了`hr-kq-e=-m`。竟然真的有搞头？

### Backpack Cryptography

脚本小子冲冲冲： https://github.com/hyunsikjeong/LLL/blob/master/low-density-attack/LowDensityAttack.sage

### LWE Intro

Learning With Errors (LWE) 问题：给定一个线性函数f(A)，参数为环上的值；在获取函数的噪声样本后确定f(A) （原文是learning a linear function，hmmm啥是学习线性函数？）。样本形如(A,⟨A,S⟩+e)，其中S是定义了线性函数的秘密元素（secret element），e是分布于已知范围内的小误差项，A是环中的已知元素。⟨A,S⟩表示矩阵乘法，矩阵A乘上向量S

基于LWE的密码系统有很多种，不过通常有以下共同的特点：
- 在两个不同的模数下进行模运算：明文模数（plaintext modulus）和密文模数（ciphertext modulus）
- 密钥是模n下的向量空间里的元素
- 通过将编码的噪声信息（noisy message）与较大的点积相加来加密消息

噪声信息是消息与误差项或噪声项的和（具有特殊构造）

点积是密钥与向量空间中的随机元素的点积；密文会提供这个随机元素。如 (A,⟨A,S⟩+encoded(m,e))

如果密钥已知，则可以自行减去点积的结果，剩下encoded(m,e)。上文提到的特殊构造允许直接将噪声与消息分离，于是得到m

至于特殊构造是什么，通常有两种做法。将消息放在LWE样本的高位，噪声放在低位；或者反过来

题目的答案是`Gaussian elimination`。在给的[资料](https://cims.nyu.edu/~regev/papers/lwesurvey.pdf)的第2页有

### LWE High Bits Message

不确定decrypt中说`not modulo q`具体是什么意思
```py
q = 0x10001
p = 257
delta=round(q/p)
S=vector(ZZ,[...])
A=vector(ZZ,[...])
b = 44007
x=(b-A*S)%q
print(round(x/delta))
```
### LWE Low Bits Message

```py
#https://crypto.stackexchange.com/questions/102852/fhe-modular-reduction-in-specific-range
def centered_mod(x,q):
    return ((x+(q//2-1))%q)-(q//2-1)
p = 257
q = 0x10001
S=vector(ZZ,[...])
A=vector(ZZ,[...])
b = 11507
x=b-A*S
print(centered_mod(x,q)%p)
```
python的`%`给出的数位于[0,p-1]，但这题要求的是“centered modular reduction”，位于 $(-q/2,q/2]$ ，所以需要改动一下

另外，c++的`%`是centered modular reduction

### From Private to Public Key LWE

利用LWE的加法同态（additively homomorphic）特性可以将其转换为公钥密码系统。给出m的密文(A,b)后，任何人都可以将其转为 $m+m_2$ 的密文。对于消息在低位的系统，(A, $b+m_2$ )为修改后的密文；消息在高位的系统则是(A, $b+\Delta m_2$ )

类似地，将两个LWE密文加起来也可以得到一个有效的密文，为两个密文对应的明文之和的密文。私钥的拥有者可以发布多组“零的加密”作为公钥，而加密者需要从这些公钥中随机选出一个子集并将其加在一起。和的结果仍然是零的有效密文。然后加密者可以将自己的消息加进去，得到m的有效密文。这些步骤要求发布者精心选择噪声样本，保证多个误差项的和仍然在解密时需要的阈值之内

为了保证以上加密系统的安全性，必须保证第三方难以分辨出哪些公钥样本被选入子集。因此公钥的样本数量需要显著大于LWE的维度， $n^2log(q)$ bits

https://openquantumsafe.org/liboqs/algorithms/kem/kyber.html

### Noise Free

没有noise的话整个密码系统就是个线性方程组。拿到64个A后组成矩阵搞 $A^{-1}B=S$ 即可

记得在GF(q)里运算

### Too Many Errors

误差项e根据seed决定，因此只要多次调用reset，e的值就是固定的。然而a也是固定的。幸好a有几率发生“突变”，即原先根据seed生成的a中的一个分量有可能变成别的。借此可以获取多个线性无关的向量。只需爆破e的所有可能值恢复正确的b，后面就和上一题一样了

然而这好像不是预期解。上述方法能用完全是基于e范围很小的前提（跨度太大就不好爆破了）。预期解可能为solutions区`r4sti`的解法，对e的跨度没有要求

### Nativity

这题其实就是上文说的LWE public key system，更详细的讲解见 https://65610.csail.mit.edu/2024/lec/l07-pke.pdf

……吗？

翻到材料的第4页会发现系统识别明文bit依赖于判断 $|c^T(−s|1)|\leq\frac{q}{4}$ （`−s|1`是拼接）。然而这题在生成的时候只生成偶数项的噪声：`2*sample((m,), normal)`，后续通过判断解密出的内容是否是偶数来确认加密时使用的明文bit是0还是1

这明显很怪。然而我仍然没反应出来该怎么攻击……只想着lattice了。据说lattice是非预期解，但是512乘上64还是太为难我的电脑了。关键在于将整个系统看作是模2下的。此时整个“LWE”就变成了完全没有误差的线性方程组，因为添加的噪声`2*sample((m,), normal)`在模2下等同于啥也没干。找s等同于找kernel（solve_right函数）

### Bounded Noise

在上道题的pdf同属的课程下找到了 https://65610.csail.mit.edu/2024/lec/l20-lweattack.pdf ，介绍了Arora and Ge攻击。如果误差的范围很小的话，比如像这题一样在{0,1}内，可以构造类似 $(A^Ts-b)(A^Ts-b-1)=0$ 的方程组。虽然这样做会出现 $s_is_j$ 项，但是可以做个替换，比如让 $s_is_j=z$ ，整个系统就是线性的了

该攻击需要满足两个条件：
- 误差范围较小。范围变大之后时间复杂度将呈超越多项式时间增长（superpolynomial time，我猜原因是误差范围多起来后缠在一起的未知变量就多了，而且以指数倍增长）
- 有足够的样本（方程）

一些资料：
- https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lwe/arora_ge.py
- https://eprint.iacr.org/2020/666.pdf

也可以用LLL，尝试找到所有的误差项，然后当作正常线性方程组解

### Missing Modulus

chatgpt帮我搜到了这个： https://crypto.stackexchange.com/questions/108356/as-a-high-level-intuition-why-is-lwe-without-modular-reduction-easy-to-solve 。里面提到了一篇论文： https://eprint.iacr.org/2018/822.pdf 。第9页说可以用Least Squares Method解。numpy里有这个函数： https://numpy.org/doc/stable/reference/generated/numpy.linalg.lstsq.html 。再加上最小二乘法的[定义](https://zh.wikipedia.org/wiki/%E6%9C%80%E5%B0%8F%E4%BA%8C%E4%B9%98%E6%B3%95)，看起来这玩意就是专门解带误差的线性系统的。这不就是这道题吗，直接套用就出了

这个方法取样本时得多取一点，和维度数一样的样本（512）不够（不过我又看了solutions，似乎是因为512样本的lstsq在real上求解出s后我没round到最近的整数。看其他人的解法里拿到A方阵后直接求逆再round就好了。直接求逆需要的样本数比较小，但是时间较长）

以及，可以用LLL找s

### Noise Cheap

搜了一下，以为是primal lattice attack。跟着一个[视频](https://www.youtube.com/watch?v=iW8dVkYhCuM)复现了里面的攻击，但那里面的方法适用于AS+e的情况，而这题是AS+pe。想着自己改一下格的构造，但那里面用到了reduced echelon form且没说为什么要用，导致我不会改……

我有点钻牛角尖了。我下意识地认为这题必须构造一个只包含误差项的格，因此虽然看到了最明显的线性方程，但这种构造方式会把S也扩进去，于是我认为这样构造出来的格就不够短了（事实上原因是我没有没有处理pe，见下方）

佬的格构造：

![lattice](https://cdn.discordapp.com/attachments/1388708228388618260/1397024451400306759/image.png?ex=688037e8&is=687ee668&hm=5f6cecd79567d08073a5648e3c9cbbfdc4b4e7c8fb47446427f0ac44468cd832&)

加了点weight后顺利解出（如果不考虑实现时细枝末节的错误的话……）。我错过的地方是忘记把方程的左边除以p（乘上 $p^{-1}\mod q$ ）了……

看了`r4sti`的构造后发现左边不除p也可以，就是加weight时复杂了些

## [Isogenies](https://cryptohack.org/challenges/isogenies)

### Introduction to Isogenies

椭圆曲线之间的同源（Isogenies）本质上是两样东西。首先，这是椭圆曲线间的有理映射（rational maps，有理函数定义的映射），而且是满态射（surjective morphism，好像就是满射？）。同时，映射保留从定义域（domain）到陪域（codomain）的群结构，意味着它们同时是群同态（group homomorphism）。将从定义域E映射到陪域E'的同源记为 $\phi:E\rightarrow E'$

接下来会关注可分离的同源（separable isogenies），这类同源的映射的度（degree）正好等于核的大小（核是定义域中映射到陪域的无限远点的点集）。虽然同源的数学背景很复杂，远远超出了密码学的应用范围，但一般来说会关注两件事。其一是给定点的子群H，目标是计算核为H的同源（因此度为#H）。其二是从定义域中取出任意点，计算该点处的同源并得到它在陪域对应的点

同源的密码性来自于不同椭圆曲线之间的同源路径（long paths of isogenies）。如果我们固定某个质数l，那么l同源图是一个顶点为椭圆曲线（的同构类），边为l度的同源（有理映射中出现的多项式的最高度数为l）的图。一般来说，当我们考虑超奇异椭圆曲线（supersingular elliptic curves）的同源图时，最终会得到一个及其混乱的图(SIDH上确实如此，不过CSIDH上限制了一组特殊的同源，因此图会有更多的结构)

当l很小时，计算l同源不难。可以通过计算许多l同源来遍历图，最终落到某个顶点处。基于同源的密码将这个由多个同源组成的路径作为私钥，起始节点和终点节点为公钥。协议的过程是，在曲线之间行走（secret walks），交换具体的曲线（有时还有其他数据），然后重复行走过程，最后落到一个共享的秘密顶点。这个顶点可用于创建对称密钥。类似ECDH中用椭圆曲线上的共享秘密点创建密钥

题目的答案是65537，因为一个separable isogeny的度就是其kernel的大小

### The j-invariant

类似模运算——许多运算只在模n下相等；在基于同源的密码学中，许多运算只有在同构时才相等。对于协议的两个参与者来说，仅仅比较曲线方程是不够的，还需要检查两条曲线是否同构

一种判断两条曲线是否同构的方法是比较两者的不变量（invariant）。对于椭圆曲线，我们选择j不变量（j-invariant），记为j(E)
> 如果两条曲线同构，它们具有相同的j不变量;但具有相同的j不变量的两条曲线可能不在基域上同构，而是在某个扩域上同构。一个例子是两条通过二次扭曲（quadratic twist）关联的曲线。它们会有相同的j不变量，但仅在二次扩域中上同构

```py
E=EllipticCurve(GF(163),[145,49])
print(E.j_invariant())
```