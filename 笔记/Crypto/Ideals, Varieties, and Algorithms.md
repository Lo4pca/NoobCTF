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

c. 证明：对所有 $a ∈ F_p$ ，有 $a^p = a$ 。提示：分别处理 a = 0 和 a ≠ 0 的情形

d. 在 $F_p[x]$ 中找一个非零多项式，它在 $F_p$ 的每一点处取值均为零。提示：利用 (c) 部分