# [prime-sponsorship](https://starglow.net/blog/ctf/prime-sponsorship)

这篇wp没给脚本，于是尝试跟着复现

首先引入要使用的记号
- $R_{q,p}=F_q[x]/(x^p-x-1)$
- $\mod (q,x^p-x-1)$ 指 $R_{q,p}$ 中的多项式

题目使用了两个多项式环，其中q固定为1511，p $\in$ {211,223}

公钥生成：

随机生成两个多项式f和g，两者的系数都在-1，0，1内，次数小于 $p_1=211$ 。同时 $g\mod 3$ 在 $R_{3,211}$ 和 $R_{3,223}$ 中均可逆。题目分别根据两个p给出了两个公钥， $h_p=g(3f)^{-1}\mod (q,x^p-x-1)$

加密：

明文为二进制向量 $r\in$ {0,1} $^{211}$ 。加密结果为 $c=Round_3(h_{211}r)$ 其中 $Round_3$ 将输入的多项式的每个系数移到最近的3的倍数

解密：

计算e=(3f)c，然后将其系数提升到 $(-\frac{q}{2},\frac{q}{2})$ ，输出 $g^{-1}e\mod 3$

根据公钥的生成方式，可知 $3fc=3fh_{211}r=gr$ 。因此后续乘上 $g^{-1}$ 即可得到r

会发现明明只用了一个公钥 $h_{211}$ ，却给出了两个公钥，而且两者使用的g和f都是一样的。记 $\phi_{211}=x^{211}-x-1$ 和 $\phi_{223}=x^{223}-x-1$ ，根据crt，如果有 $\frac{g}{3f}\mod \phi_{211}$ 和 $\frac{g}{3f}\mod \phi_{223}$ ，可以恢复 $\frac{g}{3f}\mod F_q[x]/(\phi_{211}\phi_{223})$ 。最后这个式子是个有理重构问题（[Rational reconstruction](https://en.wikipedia.org/wiki/Rational_reconstruction_(mathematics))）。因为f和g的次数均小于211且 $\phi_{211}\phi_{223}$ 的次数高达434，有理重构问题有解。现在尝试将这个问题转成线性代数问题

多项式之间的乘法可以用矩阵来表示，即wp中的`convolution-by-h`矩阵。实现可以直接找chatgpt要（

总之把给的两个公钥多项式转成矩阵后，有了以下两个方程：
- $3C_{211}f-g=0\mod (q,\phi_{211})$
- $3C_{223}f-g=0\mod (q,\phi_{223})$

如果把两者相减就能消掉g，进而求f了。当然现在减不了，需要将 $C_{223}$ 限制在前211项，记为 $C_{223}^{cut}$ 。得到Df=0, $D=3(C_{211}-C_{223}^{cut})\mod 1511$ 。求D的核即可得到f

有了f之后g就很简单了, $g=3fh_{211}$ 。wp里说在大多项式环下求逆消耗很大，因此选择求 $g\mod 3$ 的卷积矩阵，对 $F_3$ 下的单位向量解出x，即 $g^{-1}\mod 3$ 。但我没能实现这一步，我发现直接拿inverse已经非常快了……

最后抄题目的decrypt函数即可

```py
#谢谢你chatgpt
def convolution_matrix_general(h_poly, Rq, p):
    Fq = Rq.base_ring()
    conv_matrix = Matrix(Fq, p, p)
    for j in range(p):
        basis_vec = [Fq(0)]*p
        basis_vec[j] = Fq(1)
        f_basis = Rq(basis_vec)
        product = h_poly * f_basis
        conv_matrix.set_column(j, vector(Fq, product.list()))
    return conv_matrix
#不知道为什么求出来的f和g符号都是反的，需要手动逆回来
def invert_sign(vec):
    res=[]
    for i in vec:
        if int(i)==1510:
            res.append(1)
        else:
            res.append(-int(i))
    return res
p1 = 211
p2 = 223
q = 1511
Fq = GF(q)
F3 = GF(3)
Rq = PolynomialRing(Fq, 'x').quotient(x^p1 - x - 1)
R3 = PolynomialRing(F3, 'x').quotient(x^p1 - x - 1)
Rq_2 = PolynomialRing(Fq, 'x').quotient(x^p2 - x - 1)
Rx.<x> = PolynomialRing(ZZ, 'x')
pk1 = 
pk2 = 
ct = 
h1=Rq(pk1)
h2=Rq_2(pk2)
C_h1=convolution_matrix_general(h1,Rq,p1)
C_h2=convolution_matrix_general(h2,Rq_2,p2)
C_h2_restricted=C_h2[:,0:p1][0:p1,:]
f=Rx(list((C_h1-C_h2_restricted).right_kernel().basis()[0]))
g=list(3*f*h1)
g_inv = R3(invert_sign(g)).inverse()
e = Rq(3) * Rq(invert_sign(list(f))) * Rq(ct)
e = [ c.lift_centered() for c in e ]
res=list(g_inv * R3(e))
flag=''
for i in res:
    flag+=str(i)
flag=int(flag,2)
print(int.to_bytes(flag, (flag.bit_length()+7)//8, 'big').decode())
```
这个解法比[官方解法](https://github.com/UMD-CSEC/UMDCTF-Public-Challenges/blob/main/UMDCTF2025/crypto/prime-sponsorship)快了非常多

最关键的问题在于，为啥两个不在同一个模多项式环下的线性方程可以相减？事实上，我不知道（

chatgpt说相减的并不是两个不同环下的多项式，而是映射到的矩阵线性变换。而两者的基域是一样的，都是 $F_{1511}$ ;且f本身也只有211维，因此 $C_{223}$ 被截断的分量根本不参与运算，自然也不会影响结果。无论将f映射到 $R_{q,211}$ 还是 $R_{q,223}$ ，它的前211项在这两个环中都具有完全相同的表示