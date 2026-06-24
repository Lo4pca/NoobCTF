# [Ideals, Varieties, and Algorithms](https://dokumen.pub/ideals-varieties-and-algorithms-an-introduction-to-computational-algebraic-geometry-and-commutative-algebra-9780387356501-9780387356518-0387356509.html)

上一次学代数几何时没坚持下来，这次找了一本入门难度的教材，希望能坚持到最后

## Geometry, Algebra, and Algorithms

### Polynomials and Affine Space

2. 设 F₂ 为练习 1 中的域

b. 在 F₂[x, y, z] 中找一个非零多项式，它在 $F^3_2$ 的每一点处取值均为零。尝试找一个涉及全部三个变量的多项式

$x^2y+y^2x+x^2z+z^2x$

验证用的sagemath脚本：
```py
F = GF(2)
points = [(x, y, z) for x in F for y in F for z in F]
R.<x, y, z> = PolynomialRing(F, 3)
f = x^2*y+y^2*x+x^2*z+z^2*x
for point in points:
    value = f.subs({x: point[0], y: point[1], z: point[2]})
    if value != 0:
        print(f"在点 {point} 处不为零：f = {value}")
        break
```

c. 在 F₂[x₁, …, xₙ] 中找一个非零多项式，它在 $F^n_2$ 的每一点处取值均为零。你能找到一个涉及全部 x₁, …, xₙ 变量的多项式吗？

已知 $F_2[x]$ 中 $x^2+x$ 在每一点的取值都为0。增加变量时直接乘上新变量即可： $g\in F_2[x_1,...,x_n]=x_nf$ 。其中f在 $F_2[x_1,...,x_{n-1}]$ 消失

直接加也是可以的。 $g\in F_2[x_1,...,x_n]=f+h$ ，其中f在 $F_2[x_1,...,x_{n-1}]$ 消失 ，h在 $F_2[x_n]$ 中消失

任意组合上述操作也可以得到在 $F_2[x_1,...,x_n]$ 中消失的多项式

3. （需抽象代数知识）设 p 为素数。整数模 p 的环是一个具有 p 个元素的域，记作 $F_p$

b. 用拉格朗日定理证明：对所有 $a ∈ F_p$ - {0}，有 $a^{p−1} = 1$

记 $F_p$ -{0}为 $F_p^{*}$ 。由拉格朗日定理，任意a生成的子群的阶一定整除 $|F_p^{*}|$ ，即整除p-1。设子群阶为d，则存在k使得dk=p-1, $a^{p-1}=(a^d)^k=1$

d. 在 $F_p[x]$ 中找一个非零多项式，它在 $F_p$ 的每一点处取值均为零

$x^p-x$

### Affine Varieties

7. 极坐标中最优美的例子之一是四叶玫瑰线(four-leaved rose)。该曲线由极坐标方程 r = sin(2θ) 定义。我们将证明这条曲线是一个仿射簇(affine variety)

a. 利用 r² = x² + y²，x = r cos(θ) 和 y = r sin(θ)，证明四叶玫瑰线包含在仿射簇 V((x² + y²)³ − 4x²y²) 中。提示：利用 sin(2θ) 的恒等式

题目要求证明曲线上任意一个坐标(x,y)满足(x² + y²)³ − 4x²y²=0

sin(2θ)的恒等式为sin(2θ)=2sin(θ)cos(θ),所以r=2sin(θ)cos(θ)。两边同时乘上 $r^2$ 来凑出r cos(θ)和r sin(θ)： $r\cdot r^2=r^2\cdot 2\sin(θ)\cos(θ)=2r\sin(θ)r\cos(θ)=2xy$

r² = x² + y²,所以 $r^3=(x^2+y^2)^{\frac{3}{2}}$ ,得到等式 $(x^2+y^2)^{\frac{3}{2}}=2xy$ 。两边同时平方， $(x^2+y^2)^3=4x^2y^2$ ,即(x² + y²)³ − 4x²y²=0

b. 现在仔细论证 V((x² + y²)³ − 4x²y²) 包含在四叶玫瑰线中。这比看起来要复杂，因为在 r = sin(2θ) 中 r 可以为负

现在要反过来，证明对所有满足(x² + y²)³ − 4x²y²=0的(x,y)，均可找到r和θ使得r = sin(2θ)。至于为什么要“找”，因为虽然给定一组(x,y)，它们与原点的距离r和与x轴的夹角θ就固定了，但sin(2θ)可能为负数，自然不可能等于非负数的距离r；所以需要利用单个点的极坐标表示不唯一来找到一组满足r = sin(2θ)的极坐标

分类讨论。若sin(2θ)大于0，则套用a的方式即可证明确实有r=sin(2θ)；若sin(2θ)小于0，则采用另一组极坐标 $(r_1,\theta_1)=(-r_0,θ_0+π)$ 。已知 $-r_0=\sin(2θ_0)$ ，有 $\sin(2\theta_1)=\sin(2(θ_0+π))=\sin(2\theta_0)=-r_0=r_1$

（ds解答这题时突然发疯，导致我没弄明白这题，只能抄ds的思路，结果就是这样乱七八糟的）