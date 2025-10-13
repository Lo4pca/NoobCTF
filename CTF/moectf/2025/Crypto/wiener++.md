# wiener++

这题可以直接套 https://hasegawaazusa.github.io/wiener-attack.html 末尾的脚本解出。这里写一点关于格的构造的补充

原文(37)式 $e_i\approx Nd_i\approx N^{\alpha}k_i\approx d_i\approx N^{\alpha}g\approx s\approx 1-p-q\approx N^{0.5}$ 的逻辑可能是这样的：

$e_id_i=k_i\phi(N)+1$ ， $\phi(N)\approx N$ ，所以 $e_id_i\approx k_iN\Rightarrow k_i\approx\frac{e_id_i}{N}$ 。题目的条件是d < $N^{\alpha}$ ，实测发现 $e_i$ 的数量级约等于N，所以 $k_i\approx\frac{NN^{\alpha}}{N}=N^{\alpha}$ 。最开始的 $e_id_i\approx k_iN$ 也可以写成 $e_id_i\approx N$ ，因为题目生成时会保证 $N^{\alpha}$ 不会太大。 $e_i$ 和N同数量级，所以完全可以把 $e_i$ 与N倒过来，得到 $Nd_i\approx e_i$

$Nd_i\approx N^{\alpha}k_i$ 这块我不太明白，这是把 $k_i\approx N$ 了吗？可是我推出 $k_i\approx N^{\alpha}$ 。要么我推错了，要么这里是一个条件非常宽松的量级近似

$N^{\alpha}k_i\approx d_i$ 类似，相当于把 $k_i$ 的量级忽略了

然后突然冒出来一个g。这里我参考了 https://ctf-wiki.org/crypto/asymmetric/rsa/d_attacks/rsa_extending_wiener ，g似乎满足 $lcm(p-1,q-1)=\frac{\phi(N)}{g}$ ，所以g的量级几乎可以说是1，因此可以“强行”写 $d_i\approx N^{\alpha}g$

s=1-p-q，数量级大概是N的一半。 $N^{\alpha}$ 和 $N^{0.5}$ 差不了太多，所以 $N^{\alpha}g\approx s\approx 1-p-q\approx N^{0.5}$

（我很难理解上述逻辑，但能和chatgpt恢复的逻辑就这么多了。感觉非常抽象， $e_i\approx Nd_i\approx d_i$ 都行啊？）

接下来看Minkowoski′s first theorem $\lambda_1(L)\leq\sqrt{n}det(L)^{\frac{1}{n}}$ 。这里 $\lambda_1(L)$ 指格中的最短向量，n为格的维数（列向量的数量），det(L)是格的行列式，可以用格中的每个列向量的长度相乘来估算；而每个列向量的长度又可以通过向量中的最大分量估算。所以文中给出的格的det(L)大概是 $N^0NN^{0.5}N^2=N^{3.5},\sqrt{n}det(L)^{\frac{1}{n}}=2N^{\frac{3.5}{4}}\approx N$ 。而期望的最短向量B的长度为其最大分量 $(k_2s+1)^2\approx N^{2\alpha+1}$ (展开的主导部分为 $k_2^2s^2=(N^{\alpha})^2(N^{0.5})^2=N^{2\alpha+1}$ )，因此目标向量B不在LLL的规约结果里

所以需要额外构造一个矩阵D，用于缩放格矩阵，使格中的列向量大小与目标向量B相等。B中的每个分量的量级大概是 $(N^{2\alpha},N^{0.5+2\alpha},N^{\alpha},N^{2\alpha+1})$ ，于是我们构造 $D=diag(N,N^{0.5},N^{1+\alpha},1)$ ，使得B中的每个分量的量级与最大的量级对齐，变为 $(N^{1+2\alpha},N^{0.5+0.5+2\alpha},N^{1+\alpha+\alpha},N^{2\alpha+1})$ ，即全部分量的量级都是 $N^{2\alpha+1}$ 。此时由于B的各个分量都是同一量级，且B其实就是L中的基向量，所以可以说 $det(L)\approx det(B)$ （如果像之前那样差异很大的话就要一个一个算），此时 $||BD||$ < $2N^{1+2\alpha}$ ，满足定理