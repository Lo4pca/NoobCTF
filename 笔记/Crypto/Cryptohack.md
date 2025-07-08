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

Montgomery's Ladder算法可以满足上述要求。这题要求实现一个最基本的版本：Montgomery’s binary algorithm。这个算法的关键在于，无论k的第i个bit是0还是1，需要做的运算都是一个加法和一个倍乘；而最开始介绍的标量乘法则会根据bit的不同选择执行加法或是倍乘。不过这个算法仍不是最安全的，算法执行的步骤数泄漏了k的bit length，而且if语句的分支会泄漏k的结构。可在[Montgomery curves and their arithmetic](https://eprint.iacr.org/2017/212.pdf)的第16页`A uniform Montgomery ladder`找到改进后的算法（里面还有下面提到的加法和倍乘的简洁实现）

这题的椭圆曲线遵循Montgomery form： $E:By^2=x^3+Ax^2+x$ 。虽然可以转化成Weierstrass form并使用之前实现的算法，但是为什么不直接实现一个Montgomery form上的算法呢？材料已经给出了仿射坐标（用(x,y)表示曲线上的点，还有射影坐标和雅可比坐标。仿射坐标是最好理解的，但是计算效率比后两者低）下加法和倍乘的伪代码

其他材料:
- 射影坐标（projective coordinates）相关的公式： https://eprint.iacr.org/2017/293.pdf
- [Montgomery curves and the Montgomery ladder](https://eprint.iacr.org/2017/293.pdf)

题目的只给了x，于是y要自己算。这题的p是 $p\equiv 1\mod 4$ ，不能用上面的方法计算平方根了。直接用通用的： https://gist.github.com/nakov/60d62bdf4067ea72b7832ce9f71ae079

最后用不同的y算出来两个点的x是一样的。因为Doubling formula中 $\alpha$ 的计算其实是曲线在点P处的切线斜率（隐函数求导），最后算出来的值只有符号不同，而符号不会影响后续 $\alpha^2$ 的值

### Smooth Criminal

题目使用的generator G的阶数并不是质数。因此可以用Pohlig-Hellman算法将DLP分成若干个小问题，大大降低复杂度

假设G的阶数 $q=p_1^{e_1}p_2^{e_2}...p_k^{e_k}$ ，目标是计算k使得Q=k\*G

首先对每个 $p_i^{e_i}$ 计算 $k\mod p_i^{e_i}$ 。计算对应的子群生成元 $G_i=\frac{q}{p_i^{e_i}}G$ , $Q_i=\frac{q}{p_i^{e_i}}Q$ 。此时 $G_i$ 的阶为 $p_i^{e_i}$ ，问题转化为在 < $G_i$ >中求解 $Q_i=k_iG_i$

得到所有 $k_i$ 后用crt即可组合出完整的k

见 https://connor-mccartney.github.io/cryptography/ecc/PrivateCurve-0xl4ughCTF2024