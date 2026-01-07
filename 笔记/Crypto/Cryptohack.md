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
- 选定曲线E，质数p，生成元（generator）G，其中G生成的子群H=< G >的阶数为质数q
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

因为生成元G生成了整个曲线，所以曲线的阶等于G的阶

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
    - 假设 $G_1,G_2$ 分别为两个椭圆曲线群的生成元， $\alpha,\beta$ 为常量。有 $e_m(\alpha G_1,\beta G_2)=e_m(\beta G_1,\alpha G_2)=e_m(\alpha\beta G_1,G_2)=e_m(G_1,\alpha\beta G_2)=e_m(G_1,\alpha G_2)^{\beta}=e_m(G_1,G_2)^{\alpha\beta}$
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

我有点钻牛角尖了。我下意识地认为这题必须构造一个只包含误差项的格，因此虽然看到了最明显的线性方程，但这种构造方式会把S也扩进去，于是我认为这样构造出来的格就不够短了（事实上原因是我没有处理pe，见下方）

佬的格构造：

![lattice](https://cdn.discordapp.com/attachments/1388708228388618260/1397024451400306759/image.png?ex=688037e8&is=687ee668&hm=5f6cecd79567d08073a5648e3c9cbbfdc4b4e7c8fb47446427f0ac44468cd832&)

加了点weight后顺利解出（如果不考虑实现时细枝末节的错误的话……）。我错过的地方是忘记把方程的左边除以p（乘上 $p^{-1}\mod q$ ）了……

看了`r4sti`的构造后发现左边不除p也可以，就是加weight时复杂了些

## [Isogenies](https://cryptohack.org/challenges/isogenies)

### Introduction to Isogenies

椭圆曲线之间的同源（Isogenies）本质上是两样东西。首先，这是椭圆曲线间的有理映射（rational maps，有理函数定义的映射），而且是满态射（surjective morphism，好像就是满射？）。同时，映射保留从定义域（domain）到陪域（codomain）的群结构，意味着它们同时是群同态（group homomorphism）。将从定义域E映射到陪域E'的同源记为 $\phi:E\rightarrow E'$

接下来会关注可分离的同源（separable isogenies），这类同源的映射的度（degree）正好等于其核的大小（kernel，核是定义域中映射到陪域的无限远点的点集）。虽然同源的数学背景很复杂，远远超出了密码学的应用范围，但一般来说会关注两件事。其一是给定点的子群H，目标是计算核为H的同源（因此度为#H）。其二是从定义域中取出任意点，计算该点处的同源并得到它在陪域对应的点

同源的密码性来自于不同椭圆曲线之间的长同源路径（long paths of isogenies）。如果我们固定某个质数l，那么l同源图是一个顶点为椭圆曲线（的同构类），边为l度的同源（有理映射中出现的多项式的最高度数为l）的图。一般来说，当我们考虑超奇异椭圆曲线（supersingular elliptic curves）的同源图时，最终会得到一个极其混乱的图(SIDH上确实如此，不过CSIDH上限制了一组特殊的同源，因此图会有更多的结构)

当l很小时，计算l同源不难。可以通过计算许多l同源来遍历图，最终落到某个顶点处。基于同源的密码将这个由多个同源组成的路径作为私钥，起始节点和终点节点为公钥。协议的过程是，在曲线之间行走（secret walks），交换具体的曲线（有时还有其他数据），然后重复行走过程，最后落到一个共享的秘密顶点。这个顶点可用于创建对称密钥。类似ECDH中用椭圆曲线上的共享秘密点创建密钥

题目的答案是65537，因为一个separable isogeny的度就是其kernel的大小

### The j-invariant

类似模运算——许多运算只在模n下相等；在基于同源的密码学中，许多运算只有在同构时才相等。对于协议的两个参与者来说，仅仅比较曲线方程是不够的，还需要检查两条曲线是否同构

一种判断两条曲线是否同构的方法是比较两者的不变量（invariant）。对于椭圆曲线，我们选择j不变量（j-invariant），记为j(E)
> 如果两条曲线同构，它们具有相同的j不变量;但具有相同的j不变量的两条曲线可能不在基域上同构，而是在某个扩域上同构。一个例子是两条通过二次扭曲（quadratic twist）关联的曲线。它们会有相同的j不变量，但仅在二次扩域上同构

```py
E=EllipticCurve(GF(163),[145,49])
print(E.j_invariant())
```

### Where's the Supersingular Curve

绝大多数时候我们关心的是计算超奇异椭圆曲线之间的同源。从密码学角度来说，这是因为超奇异椭圆曲线的l同源图是l+1正则图（regular graph，无向图G中若存在自然数k，使得每个顶点的度（与该顶点相连的边的数量）都等于k，则称G为k正则图）且是具有最优扩展性质（optimal expansion properties）的拉马努金图（Ramanujan graph）。这意味着在图中随机游走容易“迷路”。基于得知路径的起点和终点难以恢复路径本身这点建立了同源问题

数学上，“超奇异”这个名称源于这些椭圆曲线的自同态环（endomorphism ring，从E到自身的群同态，即自同态，组成的环结构）非常大（super-sized）。它们不是奇异曲线（singular curves），注意所有椭圆曲线都是非奇异的。它们的“奇异”来源于它们的特殊（稀有）性，而不是几何意义上的奇点
```py
p = 2**127 - 1
F = GF(p)
A_coefficients=[...]
for A in A_coefficients:
    E = EllipticCurve(F, [0, A, 0, 1, 0])
    if E.is_supersingular():
        print(A)
```

### Image Point Arithmetic

前面说过，同源不仅是曲线之间的有理映射，还保留了曲线间的群结构。意味着即使某个同源 $\phi:E\rightarrow E'$ 是未知的，给定 $\phi(P)$ 和 $\phi(Q)$ ，仍然可以确定 $\phi(P+Q)$ 的结果

```py
gx,gy=(48622,27709)
px,py=(9460,13819)
p=63079
eq1=(pow(gy,2,p)-pow(gx,3,p))%p
eq2=(pow(py,2,p)-pow(px,3,p))%p
a=((eq1-eq2)*inverse_mod(gx-px,p))%p
b=(eq1-a*gx)%p
E=EllipticCurve(GF(p),[a,b])
P=E(gx,gy)
Q=E(px,py)
print((P+Q).x())
```

### Montgomery Curves

曲线之间的同构是一度的同源。一个经常计算的同构是不同曲线模型之间的映射。比如这题的Weierstrass到Montgomery

```py
E=EllipticCurve(GF(1912812599),[312589632,654443578])
print(E.montgomery_model())
```
建议看看其他人的解法，直接用sagemath太作弊了（

### DLOG on the Surface

通常用由单个点生成的核计算同源（isogeny from a kernel generated by a single point。假设在椭圆曲线E上有一个有限子群 $G\subset E$ ，只要知道这个子群就可以构造出核为G的同源 $\phi$ 。若这个子群正好是循环子群，即G=< P >由一个点P生成，则称为单点生成的核）。因此n度的同源对应一个n阶点

对于在 $F_{p^2}$ 上的超奇异曲线，其点所构成的阿贝尔群同构于 $Z/(p+1)\times Z/(p+1)$ （两个相同结构循环群的直和，从两个群里分别取出一个元素放在一起构成有序对(a,b)。运算为 $(a,b)+(a',b')=(a+a'\mod n),(b+b'\mod n)$ ）

挠子群（torsion subgroup）E[n]有两个生成元P和Q，均为n阶点。通常一个核的生成元形如[a]P+[b]Q,对于一组固定的基（生成元P，Q）来说。这里指E[n]是一个秩为2的有限阿贝尔群，因此可以找到两点P和Q，使得任何n挠点都可以表示为 $aP+bQ,a,b\in Z/n$ 。因为上文讨论的是核为一组n挠点构成的循环子群的同源，因此一定能找到某个R生成整个内核。又因为 $R\in E[n]$ ，R一定可以被写为基(P,Q)的线性组合aP+bQ

在ECDH中，求解ecdlp十分困难。然而对于基于同源的密码学来说，通常要求曲线的阶p+1是光滑的，因此ecdlp比较简单。不过算得更多的是关于基点的二维离散对数（假如 $P'\in E[n]$ ，已知P'可表示为[x]P+[y]Q,“关于基点的二维离散对数”指的就是找到x和y）

没啥思路，但有幸找到了一位大佬的记录： https://hackmd.io/@giangnd/BymiyNVAC 。发现佬用了weil_pairing解。嗯？我好像在mov attack里见过？首先先看看佬提供的两份资料：
- https://github.com/defeo/MathematicsOfIBC/blob/popayan-temp/poly.pdf （17页）
- https://www.sagemath.org/files/thesis/hansen-thesis-2009.pdf （48页）

均介绍了weil_pairing的性质。这个我在上面已经抄过了，所以没啥问题。但是为啥超奇异椭圆曲线能直接套weil_pairing解？问了chatgpt，说是因为超奇异曲线的嵌入度基本都很小，因此天然满足“pairing-friendly”性质，即构造pairing时简单又高效

最后是一点简单的运算
```
e(R,Q)
e(aP+bQ,Q)
e(aP,Q)*e(bQ,Q) #双线性
e(P,Q)^a*e(Q,Q)^b #双线性和单位元
e(P,Q)^a
a=e(P,Q)^a.log(e(P,Q))

e(R,P)
e(aP+bQ,P)
e(aP,P)*e(bQ,P)
e(P,P)^a*e(Q,P)^b
e(Q,P)^b
e(P,Q)^-b #交替性
-b=(e(P,Q)^-b).log(e(P,Q))
```
```py
p = 2**127 - 1
F.<i> = GF(p^2, modulus=[1,0,1])
E = EllipticCurve(F, [1,0])
P=
Q=
R=
S=
n=P.order()
assert n==Q.order()
base=P.weil_pairing(Q,n)
a=R.weil_pairing(Q,n).log(base)%n
b=-R.weil_pairing(P,n).log(base)%n
c=S.weil_pairing(Q,n).log(base)%n
d=-S.weil_pairing(P,n).log(base)%n
from Crypto.Cipher import AES
from hashlib import sha256
def decrypt_flag(a, b, c, d,iv,ct):
    data_abcd = str(a) + str(b) + str(c) + str(d)
    key = sha256(data_abcd.encode()).digest()[:128]
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print(cipher.decrypt(bytes.fromhex(ct)))
decrypt_flag(a,b,c,d,iv,ct)
```
日常去看其他人的解法

`Blupper`的解法完全没有用到weil_pairing。虽说不会解R=aP+bQ中的a和b，但如果式子是R=aP，配合材料里说的“ecdlp比较简单”，就会解了。把R=aP+bQ变成R=aP意味着模掉Q，即任何Q的倍数都等于0。Q的任意倍数可以联想到Q生成的循环群。所以如果构造一个以Q生成的循环群为核的同源，然后在同源映射后的结构中求ecdlp，就能完美满足上述需求。sagemath神力让这件事变得很简单： https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_field.html#sage.schemes.elliptic_curves.ell_field.EllipticCurve_field.isogeny

`Warri`的解法更“神奇”了。注意到曲线的trace of frobenius模p等于0，即这是个超奇异曲线，因此上面的点的阶数为p+1= $2^{127}$ （如果域K是q阶有限域，则K上的椭圆曲线是超奇异的当且仅当trace of the q-power Frobenius endomorphism模q等于零）。与题目材料说的“群同构于(Z/(p+1) + Z/(p+1))”一致。题目等同于说求 $R = (a\mod 2^{127})P + (b \mod 2^{127})Q$ (这里估计也是为什么上述脚本求出来的a要模n)

因为P,Q,R的阶均为 $2^{128}$ ，所以通过计算 $X\in$ {P,Q,R}， $2^{128-k}X$ 可以将点X提升（lift）到阶为 $2^k$ 的子群中。于是得到hP, hQ, hR。群同构保留了椭圆曲线的加法性质，因此子群中有 $hR = (a \mod 2^k)hP + (b \mod 2^k)hQ$ 。假如能够知道 $(a \mod 2^{k-1}, b \mod 2^{k-1})$ ，只需爆破四种情况就能确认 $(a \mod 2^k, b \mod 2^k)$

（这里补一点chatgpt的说法。原始大群和小子群之间的映射其实是取阶数“降维”，它在系数空间上对应于“取低k位数值”的操作。因为这个关系是严格的同构（即群运算保持、无信息丢失），才能用子群中的点运算来恢复出系数。所以，即便阶小于原群，也没破坏这些线性组合关系，从而能逐步完整还原出a和b）

题目已经固定了a和b的lsb为1。因此可以重复以上步骤直到恢复完整的a和b

从`gilcu3`的解法中发现sagemath早已准备了一个函数： https://doc.sagemath.org/html/en/reference/groups/sage/groups/additive_abelian/additive_abelian_wrapper.html#sage.groups.additive_abelian.additive_abelian_wrapper.AdditiveAbelianGroupWrapper.discrete_log ，完全符合这题的需求……

### Two Isogenies

做上一题时学到了sagemath里自带的isogeny用法，所以直接秒了（

如果用题目给的定义`F=GF(p**2, names="i", modulus=[1,0,1])`，需要额外加一步`i = F.gen()`才能定义出`K = E(i, 0)`。直接用`F.<i> = GF(p^2, modulus=[1,0,1])`可以省略那步

可以看看`r4sti`的预期解，使用了提供的[资料](https://ocw.mit.edu/courses/18-783-elliptic-curves-spring-2021/680a7686aabd24b22a15eeb96e733838_MIT18_783S21_notes5.pdf)：`Theorem 5.13 (Vélu)`

如果用sagemath自带的函数的话，`Three Isogenies`的解法和这题一样；用资料的话得看`Theorem 5.15 (Vélu)`

### Composite Isogenies

上述算法的时间复杂度是n（n为同源的度数），因为需要计算核的所有n个倍点

如果同源的度数为合数 $n=p_0^{e_0}p_1^{e_1}...p_k^{e_k}$ ，可以通过结合 $e_0$ 个 $p_0$ 度的同源、 $e_1$ 个 $p_1$ 度的同源……以此类推，最后得到目标的n度同源

假设有一个同源 $\phi:E\rightarrow E'$ ，已知用该同源运算一个核里的点会得到单位点（通俗理解，就是“消去”核点的阶数）。假如将核生成器K的阶缩为 $p_0$ ，则可以计算一个度为 $p_0$ 的同源 $\phi_0$ ，运算后得到 $K'=\phi_0(K)$ ，K'的阶数为 $p_0^{e_0-1}p_1^{e_1}...p_k^{e_k}$ 。然后对K'和 $\phi_0$ 的陪域实施以上操作，得到K''和 $\phi_1$ ……一直重复，直到像的阶变为0。最后把这一堆 $\phi_i$ 合起来就是要算的n度同源

可以自己实现上述逻辑，但sagemath里仍然提供好了现成工具：`E.isogeny(K,algorithm='factored')`

### SIDH Key Exchange

SIDH协议的公共参数：
- 起始曲线 $E_0$
- 两组挠点基底（torsion basis）：复习一下，指一对挠点 $P,Q\in E[n]$ ，其中P和Q的阶均为n，且 < P > + < Q > =E[n]，即生成整个n挠子群
    - $E[2^{eA}]=(P_2,Q_2)$
    - $E[3^{eB}]=(P_3,Q_3)$
    - SIDH中的p通常形如 $2^{e_A}3^{e_B}-1$ ，即上一题处理的p

生成公钥时，A计算由点 $K_A=P_2+[s_A]Q_2$ 生成的 $2^{eA}$ 阶同源 $\phi_A:E_0\rightarrow E_A$ ，并计算其像 $\phi_A(P_3),\phi_A(Q_3)$ 。A发送给B $E_A,\phi_A(P_3),\phi_A(Q_3)$ ， $s_A$ 为自己的私钥

B要做的事情类似。计算由点 $K_B=P_3+[s_B]Q_3$ 生成的 $3^{eA}$ 阶同源 $\phi_B:E_0\rightarrow E_B$ ，并计算其像 $\phi_B(P_2),\phi_B(Q_2)$ 。B发送给A $E_B,\phi_B(P_2),\phi_B(Q_2)$ ， $s_B$ 为自己的私钥

共享秘密来自于两者计算的第二个同源。A计算核为 $K_{SA}=\phi_B(P_2)+[s_A]\phi_B(Q_2)$ 的同源 $\phi_{SA}:E_B\rightarrow E_{SA}$ 。B则是计算由核为 $K_{SB}=\phi_A(P_3)+[s_B]\phi_A(Q_3)$ 的同源 $\phi_{SB}:E_A\rightarrow E_{SB}$ 。共享秘密是两个同源的陪域的j不变量： $j(E_{SA})=j(E_{SB})$

老老实实完成协议后，去看`user202729`的解法就会发现：因为这题我们已经有了双方的私钥，所以一行代码就能直接计算最终的同源

## [ZKPs](https://cryptohack.org/challenges/zkp)

### ZKP Introduction

零知识证明（zero-knowledge proof，ZKP）允许一方（证明者）向另一方（验证者）证明某个陈述是真的，同时不泄漏任何除了“陈述是真的”之外的信息。核心思想在于，虽然通过披露知识来证明你拥有某些知识很简单，但真正的挑战在于如何在不实际披露知识本身或任何相关细节的情况下证明你拥有该知识

有效的零知识证明算法应拥有以下三个性质：完整性（Completeness）、健全性（Soundness）和零知识性（Zero-Knowledge）

基本上，有意义的零知识证明需要证明者和验证者之间进行某种形式的交互。通常是验证者问证明者一个或多个随机的问题。问题的随机性配合证明者正确的答案能够使验证者相信证明者的知识。如果没有交互的话，验证者可以将证明给第三方，错误地暗示他们也有秘密知识

答案是1985，最上面写了"The foundation for ZKPs was laid in 1985 by Goldwasser..."。我以为是1989， https://epubs.siam.org/doi/10.1137/0218012 记录的日期是1989

### Proofs of Knowledge

这题是一个证明离散对数相关知识的协议。证明者（P）想要向验证者（V）证明自己知道一个w，满足 $g^w\equiv y\mod p$ 。其中g生成了 $F^{\*}_p$ 群（为生成元）

更一般地说，对于DLOG关系 $R_{dlog}$ ，有声明（statement）(p,q,g,y)定义了g生成的q阶 $F^{\*}_p$ 的子群，其中p和q是素数，y是子群中的一个元素。w是y相对于g的离散对数，记为 $((p,q,g,y),w)\in R_{dlog}$

Schnorr提出的协议如下：
- P在 $Z_q$ 中随机选择一个r，然后计算 $a=g^r\mod p$ 。发送给V
- V在 $Z_C$ 中随机选择一个e，发送给P
- P计算 $z=r+ew\mod q$ ，发送给V（ $Z_C$ 表示挑战随机数e所在的整数集合， $Z_C\subseteq Z_q$ ）
- 假如 $g^z=ay^e\mod p$ ，V接收该证明

上述协议是一个Sigma协议，通常表示为Σ协议（Σ-Protocol）。这种协议需要满足额外的三个性质：
- 完整性：如果P和V双方在公共输入x和私有输入w， $(x,w)\in R$ 上实现协议，则V返回⊤（accept）
- 特殊健全性（Special Soundness）：如果P可以说服V，则说明P知道w
- Special-Honest-Verifier-Zero-Knowledge（SHVZK）：V无法从P那里得到任何w的信息

这题先看完整性，剩下两个后面再看

```py
from pwn import *
import random
import json
conn=remote("socket.cryptohack.org",13425)
p = 
q = 
w = 
g = 
conn.recvline()
r=random.randint(1,q)
conn.sendline(json.dumps({"a":pow(g,r,p)}))
e=json.loads(conn.recvline(keepends=False))['e']
conn.sendline(json.dumps({"z":(r+e*w)%q}))
print(json.loads(conn.recvline(keepends=False))['flag'])
```

### Special Soundness

一个协议想要成为Σ协议必须满足的第二个条件是特殊健全性。称P和V之间发送的信息(a,e,z)为一组记录（transcript）

特殊健全性大概如下：给定两组证明相同关系的被接收的记录(a,e,z)和(a,e',z')且 $e\not=e'$ ，可以计算满足 $g^w\equiv y\mod p$ 的w
> 计算出来的w不一定和P使用的是一个w。虽然在这里的案例中w是唯一的，因此两者肯定是一样的；但存在其他类型的关系存在多个有效的w。计算任意有效的w足以满足特殊健全性

假设P发给V一个a，然后收到一个随机挑战e。P需要计算一个z来让V接受记录。假如P可以完成这件事，要么P只能对某个特殊的e完成一组记录（ $\frac{1}{2^t}$ 的概率，在当前设置的安全参数下可以忽略不计）；要么P能够对更多e完成更多组记录

然而，如果某人可以完成一组以上的记录，这等同于说这个人可以在本地完成至少两组被接受的记录，等同于他可以计算w
> 如果P可以计算某个z使得V承诺某个a后接受至少两组的记录，那么可以说要么P知道w，或者知道计算w的信息

```py
from pwn import *
import json
conn=remote("socket.cryptohack.org",13426)
q = 
conn.recvline()
conn.recvline()
conn.sendline(json.dumps({"e":2}))
z=json.loads(conn.recvline(keepends=False))['z']
conn.recvline()
conn.sendline(json.dumps({"e":1}))
z2=json.loads(conn.recvline(keepends=False))['z2']
flag=(z-z2)%q
print(int.to_bytes(int(flag), (flag.bit_length()+7)//8, 'big'))
```

### Honest Verifier Zero Knowledge

最后是(Special-)Honest-Verifier-Zero-Knowledge

Honest Verifier：P与诚实的验证者进行交互，即验证者严格遵循协议。具体则是保证e是均匀随机的t位比特串（bitstring），且与协议中的其他值无关

Zero Knowledge：验证者无法得知任何有关w的信息。需要证明存在一个高效的模拟器（simulator）S，输入S(x,e)可以输出记录(a,e,z)，与P和V之间真正交互产生的记录不可区分。在这题的背景下指 $S((p,q,g,y),e)\rightarrow(a,e,z)$ ，其中(a,e,z)是被接受的记录，证明某个满足 $y\equiv g^w\mod p$ 的w
> “不可区分”非常重要。正式证明中需要证明模拟器生成的记录中每条消息的分布（在计算/统计上）与诚实证明者/验证者在真实协议中生成的消息不可区分

> Special:在SHVZK中模拟器接收(参数,e),输出(a,e,z)；而HVZK中允许模拟器自行选择e。存在通用的转换使得HVZK协议转成SHVZK协议，所以差异并不重要

注意模拟器永远不会接收w作为输入。且它必须是高效的，因此在离散对数问题困难的今天它无法高效地算出w

关键在于模拟器在得知e后可以自行选择a值，于是可以均匀随机地选择 $z\in F^*_q$ ，然后计算a使得(a,e,z)满足V的检查

1. 如果存在一个模拟器，仅从公开的数据就能生成一组合格的记录，那么说明验证者能够获取一组合格的记录的行为对计算w没有任何优势。毕竟验证者在本地运行模拟器就能拿到任意多组的记录
2. 实际协议中验证者在得知a后再生成e。但一个诚实的验证者应均匀随机的选择e，在看到a之后选择e无法影响协议本身
3. 因为第二条，即使验证者先看见a，再看见e，最后是z；相比于直接在最后看完整的记录，也得不到任何计算w的优势。又根据第一条，即使看见完整的记录也得不到任何有关w的信息

这表明，对于一个诚实的验证者来说，如果存在这样的模拟器，那么通过与P完成协议，验证者除了知道P知道w这一事实之外，不会得知任何它无法在本地有效计算的额外信息

### Non-Interactive

可以将任何Σ协议转换成非交互零知识证明（non-interactive zero-knowledge proof，NIZK）

从SHVZK中注意到验证者只需提供均匀随机的t位比特串。因此验证者不一定要自行采样，只需要在证明者给出a后根据a进行随机采样即可。哈希函数正好满足这点

Fiat and Shamir发现，可以将随机值e换成证明者提供的a的哈希输出，不影响原协议的安全性。虽然这样导致证明者可以在本地爆破a来尝试获取想要的e；但从特殊健全性和SHVZK中可知，给定一个a值，不知道w的证明者最多可以回答上一个e。证明者通过作弊来伪造证明的几率完全可以忽略不计
> 给哈希函数的输入非常重要。通常是全部的公共参数和第一条消息（a）。但在更复杂的协议（和CTF）中，经常出现因不完整的输入被放入哈希函数中导致的漏洞，导致证明者可以通过修改第一条消息/公共参数来伪造证明

### Too Honest

发送一个巨大的e使得`self.r + self.e*flag`中的`self.e*flag`盖过r（全部都在高位），然后直接除以e即可得到flag

### OR Proof

OR-proof:给定两个Σ协议 $\Sigma_1,\Sigma_2$ ,存在通用的转换生成新Σ协议 $\Sigma_3$ ，为前两个Σ协议的“或”（OR）
> 证明者P输入 $x_0,x_1,w$ ，其中w满足 $(x_0,w)\in R$ 或 $(x_1,w)\in R$ 。 $\Sigma_{OR}$ 协议允许P证明他知道任意一种情况的答案，同时不透露他具体知道哪一种情况

协议如下：
- 对于公共参数 $(x_0,x_1)$ ，假设P知道 $x_b$ 对应的答案
1. 对于协议1-b，P随机采样 $e_{1-b}$ ，对 $\Sigma_{1-b}$ 运行模拟器，得到一组被接受的记录 $(a_{1-b},e_{1-b},z_{1-b})$
2. 对于协议b，P直接计算 $a_b$
3. P发送 $(a_0,a_1)$ 给V
4. V发送随机挑战s给P
5. P计算 $e_b=s\bigoplus e_{1-b}$
6. P用 $(a_b,e_b,w_b)$ 计算 $z_b$ ，得到被接受的记录 $(a_b,e_b,z_b)$
7. P发送 $t_0=(a_0,e_0,z_0),t_1=(a_1,e_1,z_1)$ 给V
8. 如果 $e_0\bigoplus e_1=s$ ，V接受两组记录 $t_0,t_1$ （相对于其公共参数）
> SHVZK说明如果我们可以在选择a前先选择e，就能伪造一组无法与真正的记录辨别开的假记录。在或协议中，证明者同时给出了 $\Sigma_0$ 和 $\Sigma_1$ 的正确记录，但两者的e值的异或结果必须等于验证者给出的挑战。于是证明者只能自由地选择一个e值。如果证明者没有协议1-b的答案，他可以自由地选择 $e_{1-b}$ 然后用模拟器跑出合格的记录；然后用异或的性质算出被固定的另一个 $e_b$ ，用协议b的w诚实地算出合格的记录

### Hamiltonicity 1

目前看的Schnorrs Σ协议只需一轮就能保证安全性，但其他的Σ协议没有这么方便

这题是一个使用一位挑战（one bit challenge）的Σ协议示例。证明者有50%的几率猜对一轮挑战。需要重复挑战t次，直到健全性误差（soundness error）在安全性中可以忽略不计

这类协议通常让证明者承诺某些信息，然后根据其承诺的内容回答两个问题中的一个。不知道答案（witness。其实上面一直在用这个词，但我不知道怎么翻才不突兀……）的证明者无法同时回答两个问题

现在要讨论的Σ协议的内容是证明某个图拥有哈密顿回路（Hamiltonian cycle）。哈密顿回路指的是访问图中每个节点正好一次且终点等于起点的路径
> 判断一个图是否存在哈密顿回路属于NP完全（NP-Complete）问题。抛开复杂理论不谈，任何NP问题都可以嵌入到哈密顿回路问题中。这意味着如果有一个基于哈密顿回路的Σ协议，则可以将这个Σ协议推广至任意NP中的关系

对于证明者P和验证者V，公共参数为N个节点的图G，秘密参数为G中的哈密顿回路w。协议如下：
1. P将G编码为 $N\times N$ 的矩阵。其中索引(i,j)处如果为1，则表明G有一条从节点i到节点j的路径；0则是没有
2. P对G中的内容作出理论上隐藏信息的承诺，称为G'
3. P采样随机排列（permutation）perm，对G'中的每行和每列应用排列
4. P发送a=G'给V
5. V采用随机挑战比特e，发送给P
6. 如果e=1
- P对w应用perm来计算G'中的环路，记为cycle'
- P计算openings——打开cycle'承诺所需的随机值（randomness）。这块可能是第二步的逆操作？
- z=(cycle',openings)
7. 如果e=0
- P计算openings——打开G'中的条目所需的随机值
- z=(perm,openings)
8. P发送z给V
9. 如果e=1
- V验证cycle'是G'中的哈密顿回路
- V用openings验证回路中的每条路径都是对1的承诺（V uses openings to verify that all edges in the cycle are commitments to 1）
- 如果上述都符合，返回 $\top$ ，否则返回 $\bot$
10. 如果e=0
- V对G用perm得到G''
- V使用openings打开G'中的条目
- 如果G'=G''，返回 $\top$ ，否则返回 $\bot$

关于这个协议为什么是Σ协议的非正式论述：
1. 三步形式：该协议形为(a,e,z)，其中e为随机的1位字符串
2. 正确性：如果P知道w且遵循协议，一个诚实的V一定会接受
3. 特殊健全性：给定两组被接受的记录(a,0,z)和(a,1,z')。z'给出了G'中的哈密顿回路w，而z给出了将G转成G'的排列。因此可以通过逆排列得到w'，即G中的哈密顿回路
4. SHVZK：最基本的模拟器如下。给出 $(G,[e_0,e_1,...,e_t])$
- for i in range(t)
    - 采样随机比特e'
    - 如果e'=0，对G进行随机排列并给出承诺，设为a
    - 如果e'=1，对随机图 $G_2$ 作出承诺，其中 $G_2$ 是一个已知其哈密顿回路的图
    - 如果e=e'，计算z（要么开启G，要么开启 $G_2$ 中的已知回路），(a,e,z)是满足条件的记录
    - 如果 $e\not=e'$ ，返回第一步（所以为什么不直接根据参数生成而是要自己随机采样一遍看是否和参数一致？）

好的，明明这个协议比Schnorrs协议复杂那么多，为什么只介绍这么点啊？甚至我还没看懂……openings和承诺究竟是啥？看了这题的例子(`example.py`)，hmmm好像明白了？

“理论上隐藏信息的承诺”指遍历图G中的每个值，放入pedersen_commit函数（又是个和离散对数有关的玩意，理解起来不复杂）后就能得到承诺comm和openings (v,r) （v是原图表G中的条目的值，协议中不会传给验证者）。将G中的每个条目替换成对应的comm后再应用排列就得到了G'

若e=1，对w应用先前的排列perm，得到排列后的哈密顿回路w'，即同样是排列后的G'中的哈密顿回路。随后遍历w'，得到w'对应的openings中的r值，组成新的openings，和perm一起发给V

若e=0，对图G的openings应用perm得到排列后的openings，和perm一起发给V

于是“V用openings验证回路中的每条路径都是对1的承诺”指pedersen_commit函数的逆操作“pedersen_open”返回1，即验证成功

通过爆破参数使`hash_committed_graph`一直返回0即可。不过看了`r4sti`的解法，全是1也是可以的，只要用example里提供的图即可（检查回路的挑战不检查使用的图等于题目用的图）

### Pairing-Based Cryptography

基于配对的密码学是密码学的一个分支，构造时使用双线性配对（bilinear pairings）或耦合（couplings）。“配对”是一种非退化双线性映射（non-degenerate bilinear map）

利用这些工具可以开发诸如决策性Diffie-Hellman假设（Decisional Diffie-Hellman (DDH) assumption）这类不止依赖单个满足加密性质的群的加密方案（cryptographic schemes that are not feasible with just a single group satisfying cryptographic properties）

DDH问题大概是，给定有限循环群G，生成元g,DH密钥交换的 $g^a,g^b$ 和另一个元素x，判断x是 $g^{ab}$ 还是一个随机的群元素。如果不存在区分 $g^{ab}$ 和随机元素的算法，则群G满足DDH假设。在这里和pairing的关系是，假设有 $p,q,r\in Z$ ，以及（加法）阿贝尔群里的G，P，G，R，满足P=[p]G,Q=[q]G,R=[r]G；配对函数可以通过检查是否pairing(P,Q)=R来验证是否pq=r

配对指一个双线性的函数 $e:G_1\times G_2\rightarrow G_T$ ，意味着它满足：
- 对于任意整数(a,b)和任意群元素(g,h)，有方程 $e([a]g,[b]h)=e(g,h)^{ab}$
- 一定是非退化的（degenerate），即e(g,h)=0当且仅当g=0或h=0。此处0指群中的单位元
- 对于密码学应用来说，配对函数e需要在多项式时间内计算出来

配对基本分为两类：对称（symmetric），指两个起始群（source groups）是一样的 $G_1=G_2$ ；而它们不一样时为非对称（asymmetric）

再细分的话可以分成强非对称配对和弱非对称配对。强非对称配对需要保证 $G_1$ 和 $G_2$ 之间难以建立同态，否则是弱非对称配对。所以总共是三种

一个ZKP中的例子是Boneh–Lynn–Shacham (BLS)数字签名协议。该方案采用双线性配对进行验证，签名以椭圆曲线群的元素表示

1. Key Generation
- 选择一个元素x，范围0 < x < r(r为生成元的阶)。x为私钥
- 公钥为[x]g，将椭圆曲线的生成元g乘上x
2. 签名
- 签名m时计算m的哈希h=H(m)，签名结果S=[x]h
3. 验证
- 对公钥[x]g验证签名S时，需要检查签名和生成元g的双线性配对e(S,g)是否等于m的哈希和公钥的配对e(h,[x]g)
- 若验证成功则说明签名的确是由私钥生成的

可以看一下`r4sti`的解法，不用第三方库直接在sagemath中实现

### Couples

题目的实现并非BLS，多了个可以控制的参数z。在最后进行比较的`pairing(xzH, G1)`和`pairing(received_H, xzG)`中，唯一可以利用的性质为其非退化性，让xzH等于0后一切就好办了

因此这题可以说是数论题：要使poly的返回值为0，等同于让`pow(x,power+7,p)`等于`pow(x,3,p)`。虽然有`0 < new_z < p`的限制，但是可以用费马小定理 $x^{p}=x\mod p$ 绕过

### Let's Prove It

第二次死在了size上！

分析题目时就感觉很多地方很奇怪。允许控制random类的seed，getPrime也完全依赖random类，isPrime又用了特殊的randfunc，同样和random类有关。但以上内容均只能用来控制Schnorrs协议的p，甚至不能说是“控制”，因为没有好办法从输出的一个值反推要求的seed。然而还是很可疑啊？

后续通过diff `Let's Prove It Again`的代码发现c的生成莫名其妙来了个平方。但我完全没往这方面想，卡在了random上：说不定有办法使其生成一个减去1为光滑数的p呢？这不就能直接dlog出flag了吗？可惜我确实想不出任何除了爆破的方法。而且nonce每个实例都会变，没法预计算

那咋办，问问佬吧。佬说这是LLL

……

仔细看了一下，p是1024位，但v和c都只有512位；flag不足400位。不是哥们，这不hnp吗？我又没看各个参数的大小……

在我确认这题是否是hnp时，佬又扔出了重磅炸弹：可以通过`long_to_bytes(abs((m1['r'] - m2['r']) // (c1 - c2)))`直接恢复。啊？我的模逆元呢？

结果又是参数大小的锅。（结合`maple3142`的方法） $r\equiv v - cf\mod p-1$ ，v 512位，cf不到p的1024位，所以r在Z中是一个绝对值小于p-1的负数。 $-x\equiv m-x\mod m$ 。因此拿到模p-1的r后直接减去p-1就拿到了Z中的r。此时如果按照`maple3142`的方法继续做下去，拿到r后模去c就有了模c下的v。又因为v和c都是512位，通过不断加c的方式恢复真正的v不需要太久。最后在Z下解出f

但如果走佬提到的`klmn`的方法，拿两个proof m-x和m-x'并相减，得到 -v+cf+v'-c'f，或者说v'-v+(c-c')f。v'-v相比于后面来说很小，所以直接整除`(c-c')`就能拿到f

### Let's Prove It Again

参数大小的问题仍然存在，加一个爆破正确的c的逻辑即可

另外，这好像已经不是zkp了……理论上zkp不允许在双方均可计算的c中加随机值

### Mister Saplin's Preview

注意request_checker是在另一个进程执行的。所以只要随便输一个很大的数字，使其卡在for循环中，来不及更新`balance_validated`到false即可

所以这和zkp有啥关系？

### Mister Saplins The Prover

get_node可以传入负索引，获取第2层的第一个node，即第一层前两个叶节点合并的结果

注意到flag长度为47，而这是一个表示64字节的merkle tree。意味着secret长度只有17。前16个字节形成前两个叶节点，最后一个字节和已知的flag前缀组成第三个叶节点

关键在于flag叶节点在多次连接中保持一致。利用多次连接可以拿到第一层后面的5个固定的叶节点，然后就能在最后一次连接中获取前两个叶节点（的合并结果）并爆破剩下的一个字节

### Fischlin Transform

Fischlin Transform不需要rewinding lemma保证安全性（这个rewinding lemma指先前见过的，提取器extractor在证明者P提交一个a并获取一个e后将其“倒带”到刚刚发送a的时间，获取第二个不一样的e，进而提取出w，证明P知道w），而是Random Oracle的读取权限
- 仅给出P的RO调用和证明的记录，提取器可以提取出一个满足关系的w，概率与P给出合格证明的概率相同

与Fiat-Shamir类似，[Fischlin transformation](https://crypto.ethz.ch/publications/files/Fischl05b.pdf)可以将任意Σ协议转换成NIZK。思路是强制证明者对给定的a向RO发出查询，并提供合格的记录；然后利用特殊健全性从记录中提取出w

https://eprint.iacr.org/2024/526.pdf 没有那么正式，方便了解算法

这题在 $\Sigma_{OR}$ 上应用Fischlins Transform。 $\Sigma_{OR}$ 应具有Witness-Indistinguishability (WI)性质：仅通过与证明者交互，验证者无法区分证明者到底用了哪个witness（通俗来说，走了哪个分支）。等价的说法是，无法区分使用不同witness的证明者给出的证明

我竟然一个资料不看独立做出来了这题，哇最不脑雾的一集（

proof中的e值说明了for循环执行的次数，间接说明了题目选择的b值对应的有效proof最少需要e次才能拿到。倘若我们用1-b对应的顺序重新排列参数并在e次循环前得到了有效的proof的话，就能100%确定题目选择的是b而不是1-b

可以假设题目选择了0，则我们也选择泄漏w0，随后算出r。e_sim是e1。如果用b=0的参数顺序跑for循环并在e次循环前得到了一个proof的话，说明远程选的肯定不是0，答案是1。不过要是没有结果的话也不能确认远程选的一定是0，毕竟另一边的proof不一定就比选定的一边先出

看了别人的解法后发现这篇[论文](https://eprint.iacr.org/2022/393.pdf)的34页给出了攻击算法。所以Fischlin Transform不能用于构造 $\Sigma_{OR}$ 协议，因其构造出来的OR协议无法满足WI

### Hamiltonicity 2

与`Hamiltonicity 1`的区别在于需要一次给出全部的proof并计算`challenge_bits`，意味着没法利用爆破控制`challenge_bits`

好的我自然是想不出来的。于是把`7Rocky`佬的思路放在这

不可能在不存在哈密顿回路的图中证明存在哈密顿回路，因此一定要引入一个存在哈密顿回路的图。将前者称为 $G_1$ ,后者称为 $G_2$ 。问题在于如何保证challenge bit 1对应 $G_2$ ，0对应 $G_1$ 。明显不可能，因为决定proof后才知道具体的`challenge_bits`

于是要把思路逆转过来：先拿到`challenge_bits`再构造proof。假如 $G_1$ 和 $G_2$ 的`hash_committed_graph`值一样，都是X；计算`challenge_bits`时等同于拿一个占位符X代替实际的图，后续根据`challenge_bits`的值决定把X换成 $G_1$ 还是 $G_2$

需要在 $G_2$ 的commitment中做手脚，因为 $G_1$ 要经过`open_graph`；而 $G_2$ 只检查回路，只open回路相关的node，其余node的值不重要，可以随意改变

另一个关键的点在于可以简化`pedersen_commit`的逻辑，使其固定返回`(1,0)`或`(h1,0)`，方便构造 $G_2$ 的假commitment

### Ticket Maestro

其实是osint（

没有头绪，但注意到供题人是 https://www.zksecurity.xyz 。发现这是一个和zkp安全相关的组织。主页下面有他们的github： https://github.com/zksecurity 。顺藤摸瓜找到[zkbugs](https://github.com/zksecurity/zkbugs)库，里面记录了和zkp相关的漏洞。用github自带的搜索功能搜索`groth16`，找到这个文件： https://github.com/zksecurity/zkbugs/tree/main/tools/circomspect 和`groth16 malleability attack`

虽然不知道为什么它们提供的链接点进去是空的，但有了这个关键词我们就能自己搜了。得到这篇文章： https://medium.com/@cryptofairy/exploring-vulnerabilities-the-zksnark-malleability-attack-on-the-groth16-protocol-8c80d13751c5 。groth16的proof是A、B和C三个椭圆曲线上的点，满足这个公式：

![verification](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*pCzxjoqaiD7EVOqjQbmlgA.png)

很明显-A、-B和C仍然是一个有效的proof。然而只延伸出一个有效的proof还不够，因为proof和proof'的价值只有2，等同于请求一个proof的价格。需要用别的伪造方法才能盈利

那篇文章好就好在给了另一种构造方式，见 https://www.beosin.com/resources/beosin%E2%80%99s-research--transaction-malleability-attack-of-groth 。虽然更复杂，但可以构造出几乎无限个有效的proof。取两个随机数 $r_1,r_2$ ，构造：

$A' = r_1^{-1}A,B'=r_1B + r_1r_2\delta,C' = C + r_2A$

其中 $\delta$ 来自服务器使用的VerifyingKey

结果这题最大的难点在于怎么写rust：
- 如何序列化和反序列化proof和ticket？
- 为啥题目里的反序列化逻辑不能直接抄？
- 什么叫函数拿走了变量的所有权导致我不能再用了？
- 原来`Cargo.toml`不是摆设啊？
- 文章末尾给的rust代码怎么没法直接运行
- 怎么与远程交互？
- 笨蛋AI你给的代码怎么报这么多错？

最后也是找到了不是解决办法的办法：
- 题目原逻辑的`hex::decode(ticket.proof)?;`中的`?`只能用在返回`Result<>`的函数中。要么用`hex::decode(ticket.proof).expect('x')`,要么像原代码一样包一层函数
- 看这个函数签名：`redeem(&mut self, ticket: Ticket)`，表示redeem函数会拿走ticket的所有权（ownership），调用后原来的ticket就不能再使用了。可以换成`redeem(&mut self, ticket: &Ticket)`，或者调用时传入`ticket.clone()`
- `Cargo.toml`记录了项目的dependencies和package相关信息
- 我选择直接把那段代码丢给AI改。虽然改出来之后还是不能用的，但运行`cargo run`时rust编译器会指出错误的地方（缺了什么引用，语法哪里有问题等），且提供编译器推断的正确代码。人工根据那些提示改掉错误即可。如果遇见自己不会改的就把错误和代码一起扔给AI，它会出手
    - 当然很大概率它出手后仍然不能跑……但这时报的可能就是其他的错误了，重复以上步骤直到全部代码能跑即可（？）
- AI记忆力不好，在改出没有报错的代码后，一定要把改完的代码粘贴给它，并在告诉它在这份代码的基础上加新功能。deepseek在最后直接把我的（并非我的）poc整合成远程交互代码，速度快且没有任何报错

看了其他人的solutions后发现还有另一种构造方式： https://slowmist.medium.com/zkp-series-principles-and-implementation-of-extensibility-attacks-on-groth16-proofs-aedcd703323a 。 $\forall x\in F$ , $A'=Ax,B'=Bx^{-1}$

## [Hash Functions](https://cryptohack.org/challenges/hashes)

### Jack's Birthday Hash

看到题目的第一眼以为是[Birthday problem](https://en.wikipedia.org/wiki/Birthday_problem)，结果套完公式发现不是。生日问题要求的是“任意两个重复”，这题要求“和指定的secret重复“

11 bit一共有 $2^{11}=2048$ 种可能，那么与secret重复的概率就是 $\frac{1}{2048}$ ；反过来与secret不重复的概率就是 $1-\frac{1}{2048}$ 。假设需要n个输入使某个hash有0.5的概率与secret重复，写成方程就是 $1-(1-\frac{1}{2048})^n=0.5$ (每个输入都不重复是相关事件，因此相乘)。解方程可得到 $n=\frac{ln(0.5)}{ln(1-\frac{1}{2048})}\approx 1420$

### Jack's Birthday Confusion

这回可以放心套公式了，直接写脚本手动爆破（
```py
num=76
res=(1/2048)**num
for i in range(num):
    res*=2048-i
print(1-res)
```

### Hash Stuffing

pad函数不会给大小正好是BLOCK_SIZE的倍数的明文添加padding
```py
from pwn import *
import json
p=remote("socket.cryptohack.org","13405")
BLOCK_SIZE = 32
def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)
m1=b'a'*31
msg={"m1":m1.hex(),'m2':pad(m1).hex()}
p.sendlineafter(": ",json.dumps(msg))
p.interactive()
```

### PriMeD5

大 力 出 奇 迹

以前看wp时就见过[fastcoll](https://github.com/brimstone/fastcoll)这个工具，但是记错它的用途了……从[collisions](https://github.com/corkami/collisions)可以看到，目前“生成一个文件匹配已知hash”是不可能的，最符合本题要求的已知攻击是“生成两个相同hash的文件”

这不等于说“纯碰运气”吗？这要多久啊？跑去社区看了一眼，有人提到存在非预期解，脚本只需要1秒左右的运行时间

最后我没想到那个非预期解，反而是根据"一个随机选择的数N有 $\frac{1}{ln(N)}$ 的几率是质数"这个结论发现概率不是特别低，选择直接头铁硬算。没想到很快就找到答案了（然而并没有描述里提到的5分钟那么快）

写完后跑去看了非预期解。这明显比预期解聪明多了，同样是爆破但是效率高了不少

### Twin Keys

更 大 的 力 出 更 大 的 奇 迹

下方的异或是障眼法。只要循环次数是二的倍数且h1和h2相等，最后的结果就相等

还是`collisions`这个项目，往下翻会发现[UniColl(hashclash)](https://github.com/cr-marcstevens/hashclash#create-you-own-identical-prefix-collision)这个项目：指定一个前缀，生成文件A和另一个前缀相差几个字符的文件B，两者md5值相同

照着项目里的搭建方式搭好源码就能直接用。注意前缀的长度必须是4的倍数，因此需要额外加两个padding字符，比如：`echo -n "CryptoHack Secure Safeaa" > prefix.txt`

我运行了接近一个小时才拿到结果；然而社区里其他人分享说，基本十分钟左右就能得到答案了。我的电脑太拉了（

注意如果软件运行时输出卡在这一步：
```
Starting...
20: Q5m5tunnel
20: Q4m5tunnel
...
```
即不断重复上述的输出（tunnel的名字可能有些不同），建议停止软件并更换使用的padding字符（这玩意额外坑了我两个小时）

### No Difference

“我把puzzle揣兜里，结果它自己开了”

题目贴心地写出了permute函数的性质，那么肯定要用到这些性质对吧？

但是题目中的异或仅对单个字节使用，看起来函数的异或性质没有傻瓜的利用方法；同时我们只能随意控制state的后4个字节，所以函数【自己是自己的逆函数】这点也没有无脑的利用方式

很容易注意到SBOX中存在多个重复的值，所以可以精心构造输入，使permute返回的结果经过substitute后返回一样的值。但是我是笨蛋，根本不会分析permute函数的本质，进而除了爆破，想不出到底该怎么“精心”

于是我选择测试特殊值。每轮permute+substitute前我都会将state的后4个字节置0。重复这个步骤仅仅三次后我就发现state卡在了两个值之间循环。可能是最简单的175分了……

那么是时候看看其他佬的解法了

`Se_P3t`的解法指出permute函数的两条性质说明了这是个线性函数。如果把函数的输入和输出看作是八个字节的二进制位组成的8\*8的矩阵，permute函数的作用是对该矩阵做转置

用sagemath自带的`SBox.difference_distribution_table()`可以查看题目的S盒的差分分布表(DDT)。假设S盒有n位输入和m位输出，DDT的大小为 $2^n\times 2^m$ 。每行的索引表示所有可能的输入查分（ $\Delta X$ ），每列的索引表示所有可能的输出差分（ $\Delta Y$ ），每个单元格的值表示对于某个固定的输入差分 ΔX，在所有可能的输入 X（从 0 到 $2^n - 1$ ）中，有多少对 (X, X⊕ΔX) 经过S盒后，其输出差分为 ΔY。比如，如果(223,0)=256，这意味着`all(SBOX[x] ^ SBOX[x^223] == 0 for x in range(256))==True`，即对于所有输入组X和X'，如果两者相差223，则它们经过S盒的输出都是一样的

然后我看了半天都看不明白two block collision里的“second block difference” `[0x28, 0, 0x28, 0x28]`是怎么来的。上一步的differential matrix如果我没看错的话，根据脚本的输出`00010000 --> 00101000`，意味着如果输入相差0b00010000，结果便相差0b00101000（differential matrix的lsb和msb是反过来的）。那问题来了，为什么second block difference的第二项是0？明明differential matrix的每一项都是0x28啊？

（我想我又犯了看不明白转置和符号的老毛病，越看越糊涂。不管了）

hellman的做法为直接爆破。hash函数中不可控制的部分只有state的前四个字节，所以求碰撞的复杂度只有 $2^16$ 。甚至可以直接像`ciphr`的做法一样硬碰撞

### MD0

hash函数的结果是out，然而这个out对于更长的msg来说是其“中间状态”。我们可以完全控制blk，那么对于一段完整的msg，只要找到其某一段前缀msg'对应的中间状态，便可以模拟剩下的msg的hash计算过程

### MDFlag

看到题目的第一眼：简单！

发现length extension攻击需要加padding：不对！

在[hash_extender](https://github.com/iagox86/hash_extender)的介绍中可以发现使用length extension攻击大致如下：
- 知道`secret||data`的hash（data可以是空）
- 可以在消息末尾添加其他的data：`secret||data||extension`
    - extension的前缀必须是特定的padding
- 得到`secret||data||extension`的hash

在没有padding的情况下，很容易就能发现，如果发送和FLAG一样长的输入，获取其hash后便可通过比对extension的结果以及服务器的输出逐个字符爆破flag。然而padding的存在阻止了这点。问了deepseek，padding的规则如下：

填充操作会**在原消息末尾添加一个比特位“1”，然后添加若干个比特位“0”，最后添加一个64位的消息长度值**。具体步骤如下：

| 步骤 | 操作 | 说明与示例 |
| :--- | :--- | :--- |
| **1. 添加比特“1”** | 在消息末尾追加一个二进制位 `1`。 | 这通常在实现中通过字节操作完成，即在消息后追加一个字节 `0x80`（二进制 `10000000`）。 |
| **2. 添加比特“0”** | 在上一步之后，填充足够多的二进制位 `0`，直到**整个消息（原消息+填充位）的长度**满足：`长度 % 512 = 448`。 | “0”的个数是`(447 - (当前长度 % 512)) mod 512`个比特。如果消息长度已经对512取模等于448，则仍然需要填充一个完整的512比特块（即448比特“0”）。 |
| **3. 添加原始长度** | 在填充的“0”之后，**追加一个64位（8字节）的整数**，表示**原始消息的比特长度**。 | 该长度值按**小端字节序**存储。如果原始消息长度超过 $2^{64}$ 比特，则只取低64位 |

padding的长度最短也要10个字节（第一步的0x80+第二步只追加一个`\x00`+第三步固定8个字节），意味着在我们可以逐字符爆破之前，得先搞明白10个字节的flag

……好像并非不可能？flag的格式`crypto{`为7个字节，如果可以用上末尾的`}`就是8个字节；剩下两个字节爆破即可。448个bit是56字节，flag长度为46字节；也许存在一个长度x，使得padding正好落在flag已知的字符处？

（这看起来是一个数学问题，但是我没搞明白怎么列式。最后靠写脚本爆破得到的x）

### Mixed Up

如果让`mixed_and`全由某个数（比如0）组成，就能使`very_mixed`同样只由某个字符构成。利用这点可以逐个爆破每个字符的每个bit

### Invariant

运气并不是实力的一部分，如果一个人只有运气的话（

我一看到这类具有神秘结构的题就头疼，于是跑去问大佬。佬说试试输入完全一样的字符，看看会发生什么。我便写了一个脚本，用于爆破全部256个字节。最后发现有两个输出十分特别，随便组合它们后莫名其妙就成功了……

但是为了让这个过程不那么莫名其妙，让我们看看`aloof`的解析

加密过程分为四个部分：
- AK:用异或添加round key（`__subkeys`）
    - 查看`__subkeys`的构造可以发现这一步只会影响data的lsb
- SR：和AES中的shift rows步骤一致
- SB：使用sbox替换每个字节
    - sbox的替换存在一个极短的循环`(6,7)`，即6变成7，7变成6
- MC：用异或来mix columns
    - 列出式子可以发现如果整个column只包含两个不同元素，则此步骤不会修改state
    - 这点可以用chatgpt找到（但更关键的步骤是SB的分析，它没找到）

前文提到的两个特殊值即为6和7。正好这两玩意只相差1，所以AK不会破坏已有的结构，其他的步骤也不会

### Merkle Trees

ZKP里的`Mister Saplin's Preview`要求先把Merkle Trees做了

默克尔树（Merkle tree，也称哈希树）常用于区块链和数字货币中，保证数据完整性和验证过程的效率。类似普通的树结构，但其叶子为数据块的哈希值

树的最底部为叶子，为各种数据（比如加密货币中的交易内容）的哈希值。往树的上面走，每两个子节点组成一对，共同形成下一层的节点的哈希值。以上步骤一直重复到树的顶点，称为默克尔根（Merkle root）

![merkle_tree](https://cryptohack.org/static/img/Hash_Tree.png)

如果想要验证某段数据是否在集合中，不需要查看整个数据集；只需要从某个特定的节点开始，检查这个节点到默克尔根的路径上的哈希值

```py
from hashlib import sha256
from Crypto.Util.number import *
def hash256(data):
    return sha256(data).digest()
def merge_nodes(a, b):
    return hash256(a+b)
content=open("output.txt").read().splitlines()
flag=''
for i in content:
    a,b,c,d,root=eval(i)
    left = merge_nodes(bytes.fromhex(a), bytes.fromhex(b))
    right = merge_nodes(bytes.fromhex(c), bytes.fromhex(d))
    if merge_nodes(left, right)!=bytes.fromhex(root):
        flag+='0'
    else:
        flag+='1'
print(long_to_bytes(int(flag,2)))
```
### WOTS Up

`WOTS Up???`的hash的第一个字节值等于BYTE_MAX，导致priv_key全部泄漏……

### WOTS Up 2

priv_key包含32个不同的项，但可以从已知消息的data_hash_bytes算出每个字节对应的hash_iters，进而确认每个sig_item是`priv_key[i]` hash多少次后得到的。有了这些数据就能精确算出当前sig_item距离目标sig_item的迭代次数

## [RSA](https://cryptohack.org/challenges/rsa)

### Fast Primes

p和q的结构均为 $kM+(65537^{a}\mod M)$ 。不难看出如果把N模M，得到的结果为 $65537^{a'}\mod M$ ，其中 $a'=a_1+a_2$ 。而且由于M是多个小素数的乘积（光滑数），用Pohlig-Hellman很快就能求出a'

（这里可以直接用saagemath的`Zmod(M)(N).log(65537)`求，不需要自己实现Pohlig-Hellman）

……然后就没有然后了。想要确定p或者q需要同时确定对应的k和对应的a，拿到a'只等于划定了一个范围，到最后还是要爆破？可是这样的复杂度太高了

最后我在factordb找到了神秘好心人上传的分解结果。可以看看如何解决上述问题了

这题是[ROCA](https://bitsdeep.com/posts/analysis-of-the-roca-vulnerability) （Return of Coppersmith’s Attack），专门针对按照题目中的方式生成的RSA公钥。链接已经介绍得很清楚了（虽然我没完全看懂），这里记录几个关键点
- 质数形如 $kM+(65537^{a}\mod M)$ 等于说有“M的位数”的信息泄漏。此题的质数有256bit，理论上entropy应为256bit。但M有219bit，说明k的entropy只有256-219=37bit；加上a的上限为62bit，总entropy只有37+62=99bit。entropy较小对应已知的信息多，是Coppersmith类型攻击的特征
- 利用Coppersmith可以在 $a_1$ (下文用 $a_1$ 表示某个质数结构对应的 $a_i$ ，a'表示两个可能的 $a_0,a_1$ 的和)已知的情况下求解上述多项式在模p下的根k，进而分解N。此处确实需要爆破 $a_1$ 的值，但存在优化使得复杂度没那么高
- 不需要在 $[0,a']$ 之间搜索 $a_1$ ，可以将搜索区域优化成 $[\frac{a'}{2},\frac{a'+|G|}{2}]$ (|G|为65537生成的子群的阶)。因为 $a_1=a_2=\frac{a'}{2}$ 是“两者相加等于a'“最小的可能， $a_1=a_2=\frac{a'+|G|}{2}$ 是最大的可能（此处猜测是因为结合|G|的大小和 $a_i$ 的大小，模运算最多取消掉一个|G|）
- Coppersmith攻击内部使用格，算法中存在一个参数m，与生成的格的维度有关。格的维度越大算法的速度越慢，但维度太小也会导致LLL无法解出答案
- |G|的大小与M有关
- Coppersmith攻击在已知的信息位数大于 $\frac{log_2(N)}{4}$ 时能成功，然而题目的M的位数远远大于这个值
- 结合以上三点可以得出如下的优化策略：
    - 在LLL算法能成功的前提下使m越小越好
    - 将M替换成M'，保证Coppersmith攻击能成功的前提下缩减爆破范围。这个M'将是M的因子，因为这样不会破坏原始多项式的结构

### RSA Backdoor Viability

是论文题：
- https://eprint.iacr.org/2017/403
- https://crocs.fi.muni.cz/public/papers/Secrypt2019

实现见[cm_factorization](https://github.com/crocs-muni/cm_factorization)

solutions里aloof给了解析，但是我看不懂（

### Bespoke Padding

padding是完全线性的，符合Franklin-Reiter related-message attack的特征

（差点以为是coppersmith）

### Null or Never

这下确实是coppersmith了（

难点在于构造多项式。我也不知道花了多少小时在这玩意上，总是差临门一脚。最无奈的地方在于deepseek给了我一个“false positive”的构造方式，单独运行起来很像是对的，但实际在sagemath里跑的结果是错的。我百思不得其解，甚至换了很多套coppersmith的实现，全部都不行。最后的最后才发现是构造错了（结果正确的构造方式也是deepseek给的。“我们两个真是太厉害啦”）

用的是这个脚本： https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/coppersmith.sage ，虽然显示“可能找不到根”但最后仍然找到了

（sagemath自带的small_roots也可以）

### Let's Decrypt

看了半天才发现不仅仅可以控制e，还能控制n……

目标是让`pow(SIGNATURE, e)-kn=target`。为了方便，直接让e=k=1，这样就有n=SIGNATURE-target

### Blinding Light

RSA签名的malleability attack

### Vote for Pedro

我是开立方根也要找论文的神人

这题看起来很眼熟，以为是Bleichenbacher padding attack。但翻了以前的记录后发现这个攻击生成的签名形如`XX||Hash(m)||garbage`，不可控制的garbage位于末尾，不是这题想要的

我也不知道为什么我就笃定这题是Bleichenbacher攻击，总之踏上了google搜索的不归路。找到了这篇论文： https://www.jstage.jst.go.jp/article/imt/3/4/3_4_780/_pdf/-char/en ，里面提到了`Oiwa, et al.’s Variant`，可以让garbage出现在Hash(m)之前的结构中。啊这不就是我想要的吗？

然而我搜了半天也搜不到那篇论文的免费版，倒是搜到了一篇总结各种Bleichenbacher攻击变种的论文： https://download.hrz.tu-darmstadt.de/pub/FB20/Dekanat/Publikationen/CDC/sigflaw.pdf ，里面的`Exploiting the Algorithm Parameters Field`也符合这题的要求

我讨厌读论文，幸好在chatgpt的帮助下，我注意到这题根本没有这么复杂。只用算法`5.2b`的步骤就好了

那么`5.2b`的内容是什么呢？是模 $2^k$ 下开立方根。题目的代码相当于只看签名的后缀，等于 $((sig^e)\mod N)\mod 2^k$ 。只要 $sig^e$ 够小，模N根本没有作用

### Let's Decrypt Again

做这道题的过程实在是太曲折了……概括下来是：我好像有思路->对的对的->嗯……->不对不对！->对……对吗？->哦对的对的->对个鬼啊->诶好像真是对的->怎么实现啊？->为什么总是不对？->为什么突然对了？

看到这题的第一眼我就觉得是离散对数，随即去翻我的笔记里有关pohlig-hellman的内容。虽然笔记里记录的实现是模p的，但我把p换成n，阶从p-1换成phi(n)就可以了吧？

脚本报错，于是我去找chatgpt调试脚本。给它描述完题目和我的思路后，chatgpt竟然说我的思路完全是错的，因为离散对数“不是这么算的”。它推荐我先找 $e_i$ 然后求各个 $pow(SIG,e_i)-msg_i$ 之间的gcd。这不可能吧？告诉chatgpt我的想法后它的想法立刻转变，又说我是对的了……总之是拿到了能跑的脚本

但是脚本能跑不代表它能出期望的结果。我仔细想了一下，猛然发现一个大问题：万一阶不是phi(n)呢？pohlig-hellman算法要求的阶到底是什么？我完全没搞明白……

幸好我有数学书，最近在看的`An Introduction to Mathematical Cryptography`里就有pohlig-hellman算法的内容。书上说这个阶是底数在群G中的阶(multiplicative order)。转来转去又回到了起点，只要phi(n)是光滑数，由于群中元素的阶必须整除phi(n)，元素的阶必定也是光滑数

但是不知道为什么，套别人的脚本仍然得不出答案，一直卡在discrete_log的地方。最终勉强拼出了这样一个玩意：
```py
def pohlig_hellman(g,h,n,order):
    fac=factor(order)
    exponents=[]
    moduli=[]
    Rn=IntegerModRing(n)
    g=Rn(g) #不加这一步会导致下面计算指数和discrete_log时报错“指数太大”
    h=Rn(h)
    for pi,ei in fac:
        gi=g^(order//(pi**ei))
        hi=h^(order//(pi**ei))
        try:
            exponents.append(discrete_log(hi,gi,order)) #不加order这个参数出不来
            moduli.append(pi**ei)
        except ValueError:
            continue
    return crt(exponents, moduli)
```
然而还不够。实战发现大部分计算不成功，因为很多子离散对数不存在，导致crt无法恢复出完整的指数。到这里我真没招了，只是一遍一遍机械地运行脚本，期待它能成功。但是跑了几十次后我有点怀疑自己了，这是不是错误的实现方式啊？成功率出奇的低，偶尔能算出第一个消息的对数，但从来没有算出过第二个和第三个

就在我准备放弃时它突然成功了。我没换参数但它就是非常巧合地连续三次成功了

看了其他人的解法，我的实现确实有问题……这篇[论文](https://eprint.iacr.org/2011/343.pdf)的`2.2.2`详细描述过这个攻击（Duplicate Signature Key Selection (DSKS) attack）。关键不仅在于N需要是两个光滑质数的乘积，还需要保证底数和结果是 $F_p,F_q$ 的generator。参考`ciphr`的做法：“set the length of our primes p',q' longer than the bitlength of the original N”。而且直接这样就好：
```py
x = discrete_log(Zmod(p)(digest), Zmod(p)(SIG0))
y = discrete_log(Zmod(q)(digest), Zmod(q)(SIG0))
e = int(crt(x, y, p-1, q-1))
```
用 $p^e$ 做N也可以