# ez_det

不会线性代数
```py
#没有chatgpt我啥也不是
from sympy import Matrix, lcm
from math import gcd
from functools import reduce
from Crypto.Util.number import long_to_bytes
C=
# 转成 sympy 矩阵（所有运算在有理数域精确处理）
Cmat = Matrix(C)      # 5x5
D = Cmat[:, 1:5]      # 取第 2..5 列 -> 5x4 矩阵
DT = D.T              # 4x5

# 求 DT 的零空间（返回有理数基向量）
nullspace = DT.nullspace()
if not nullspace:
    raise ValueError("找不到非零左零空间（不应发生）")

v = nullspace[0]   # 这是一个列向量（rational entries），空间维度应为 1
# 把有理数向量缩放到整向量：乘以所有分母的 lcm
denoms = [r.q for r in v]   # sympy Rational 的分母属性是 .q
L = lcm(denoms)
v_int = [int((L * r)) for r in v]  # 现在是整向量（可能有公因子）
# 取最小整数基：把公因子除掉
g = abs(reduce(gcd, v_int))
v_prim = [x // g for x in v_int]

# 计算 flag_long = v_prim · (第一列 of C)
first_col = list(Cmat[:,0])
flag_long = sum(int(a)*int(b) for a,b in zip(v_prim, first_col))
print(long_to_bytes(flag_long))
```
关键在于M的构造。M的最后一行除了第一个分量是flag，其余都是0。假设有一个向量 $y=(0,0,0,0,1)$ ， $M_j$ 为M的第j列向量， $(M_j)_i$ 表示M的第j列向量的第i个分量。对于j=1..4，有 $y^TM_j=(M_j)_5=0$ 。所以y在`M[:,1:5]`的左零空间里（左零空间定义： $m\times n$ 的矩阵D， $LeftNull(D)=$ { $y\in R^m|y^TD=0_{1\times n}$ }）

现在假设有一个向量x满足 $x^TC[:,1:5]=0$ ，即 $x\in LeftNull(C[:,1:5])$ 。它与上述y的关系是：

$$x^TC[:,1:5]=x^T(AM[:,1:5])=(x^TA)M[:,1:5]=0$$

因此 $x\in LeftNull(C[:,1:5])\Leftrightarrow A^Tx\in LeftNull(M[:,1:5])$ 。既然 $A^Tx$ 和y都在`M[:,1:5]`的左零空间，可以说存在x使得 $A^Tx=y$ （ $dim(LeftNull(D))=m-rank(D)=5-4=1$ ，因此两个向量只能相等）

所以脚本中用`DT.nullspace()`取 $C[:,1:5]$ 对应的左零空间，即x。得到x后与`C[:,0]`点乘即可得到 $x^TC[:,0]=x^T(AM[:,0])=(x^TA)M[:,0]=y^TM[:,0]=flag$

脚本里求出的nullspace为分数。为了防止浮点数精度问题导致点乘出的flag结果不对，选择将分数转为整数后再运算

另外，题目生成的A为[幺模矩阵](https://baike.baidu.com/item/%E5%B9%BA%E6%A8%A1%E7%9F%A9%E9%98%B5/9349415)（unimodular），保证所有整数向量通过A或者 $A^{-1}$ 运算后仍然是整数向量（至于为什么`DT.nullspace()`返回分数，可能是因为它们的比例不同。sympy默认返回最小整数比或最简分数， $(2,0,0,0,1)^T$ 在sympy里可能返回 $(1,0,0,0,\frac{1}{2})^T$ ）