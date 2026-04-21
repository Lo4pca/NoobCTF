# Garbled Circuit

准备读这篇文章： https://blog.tanglee.top/2025/04/03/Revisiting-Garbled-Circuit.html ，结果发现内容很多，我不跟着写的话看到后面就忘了前面了（

文章中给出了更入门的题目与garbled circuit的介绍： https://jsur.in/posts/2021-02-08-dicectf-2021-garbled 。先把这个看了

说alice和bob想要知道一个函数f(x,y)的值。alice提供x，bob提供y，但两者均不想让对方知道自己提供的值。`Yao's Garbled Circuits`协议便可以满足这点。协议的步骤如下：
- 假设alice和bob想要计算的函数为一个布尔电路。其中有两个输入门，分别对应alice和bob的输入
- alice混淆电路（生成随机的标签，并加密电路门的真值表）
- alice将混淆后的 输入标签和电路 发送给bob
- bob利用oblivious transfer (OT)选出自己的标签
- bob使用输入标签解密真值表，即获取电路门输出

需要一个更详细的例子。假设alice和bob的输入为x和y，想要计算两个输入的AND结果。alice将生成一些随机的标签，作为某个对称密码的密钥加密真值表。AND门的原始真值表如下：

|x, $w_1$ |y, $w_2$ |f(x,y), $w_3$ |
|:-:|:-:|:-:|
|0|0|0|
|0|1|0|
|1|0|0|
|1|1|1|

混淆后用 $k_1^0$ , $k_1^1$ 代表alice的输入, $k_2^0$ , $k_2^1$ 代表bob的输入， $k_3^0$ 和 $k_3^1$ 代表输出。alice需要记住这些标签对应的值。标签为了阅读方便，命名带了些规律；但实践中攻击者无法通过标签判断标签背后对应的输入

混淆后的真值表如下：

| $w_1$ | $w_2$ | $w_3$ |
|:-:|:-:|:-:|
| $k_1^0$ | $k_2^0$ | $E_{k_1^0}(E_{k_2^0}(k_3^0))$ |
| $k_1^0$ | $k_2^1$ | $E_{k_1^0}(E_{k_2^1}(k_3^0))$ |
| $k_1^1$ | $k_2^0$ | $E_{k_1^1}(E_{k_2^0}(k_3^0))$ |
| $k_1^1$ | $k_2^1$ | $E_{k_1^1}(E_{k_2^1}(k_3^1))$ |

其中 $E_k(m)$ 表示以k为密钥，使用对称密码加密m的结果

alice将自己的输入标签A与上述混淆后的真值表的 $w_3$ 栏打乱顺序后发给bob。接下来，bob用OT从alice手中选出自己的输入对应的标签B。有了这两个标签后，bob依次尝试解密四个密文，看手中的标签到底对应哪个输出标签

所以bob怎么知道自己是否成功解密了一个密文？一般有两种方法解决：
- alice加密输出标签时顺便在末尾加点padding。假如bob成功解密了一个密文，他便能通过末尾的padding明白自己拿到了输出标签
- 额外再用相同的密钥对加密某个明文并发送给bob。明文的值不重要，比如全是0字节。假如bob解密出一堆0，他便能知道对应的解密结果是正确的

最后我们顺利解决了开头的问题：
- bob不知道alice的输入，因为他只能知道alice的输入对应的标签，而他无法从标签倒推alice的输入
- alice不知道bob的输入，因为OT协议保证了发送方不知道接收方选择了什么内容
- 最后两者知道的只有两个输入对应的输出标签，由alice判断这个标签具体对应什么值

这个例子的缺陷非常明显。计算AND门，bob选择对应1的标签后，如果结果是对应的1的标签，bob就能知道alice输入的是1，因为AND只有一种情况可以得到1。这就不是garbled circuit协议的锅了，是AND门自己的问题。此处的"信息泄露"是AND门的特质。平时一般需要拿多个门组合在一起

附加的题目（garbled，DiceCTF 2021）设置和上述过程相同。漏洞在于题目使用了第二种方法验证密文是否解密成功，而单个标签（key）的空间只有 $2^{24}$ 。攻击者可以用meet in the middle技巧爆破出正确的key。回到开头准备读的文章，关于这道题目（以及garbled circuit）的具体实现见`A Demo of Garbled Circuit`部分。不感兴趣的话可以直接从`Elementary Optimizations`开始

该协议的一个问题是效率太低了。加密真值表需要整整 $2^k$ 个密文，接收者平均需要解密 $2^{k-1}$ 个密文才能找到正确的明文。以下是一些用于优化的技巧：

1. Point-and-Permute
- 在每个标签后追加一个随机的“color bit”，使得一对标签（对应上一篇文章里的 $k_i^0,k_i^1$ ，这篇文章里的符号是 $W_i^0,W_i^1$ 。W代表wire，表示输入或输出）拥有相反的color bit，即 $LSB(W_i^0)=b,LSB(W_i^1)=1-b$ 。然后根据所有输入标签的color bit排列密文（比如，第一个密文对应两个color bit均为0的输入标签）。注意color bit的值和输入标签实际代表的值没有任何关系（一个标签的color bit是0不代表它的实际值就是0）。最后，接收者只需根据手上的输入标签的color bit便可找到对应的密文
2. Row Reduction
- 在point-and-permute的基础上，可以定义一个一次性加密（One-Time Encryption） $E_{k_1,k_2}(m)=H(g,k_1||k_2)\bigoplus m$ ，用于混淆电路。其中H是random oracle（g是某个标识符，保证即使 $k_1$ 和 $k_2$ 重复，不同门的输出也不一样）。假设当前混淆 $G(W_a,W_b)=W_c$ ，选择输出 $W_c^0$ (原文还提到了 $W_k^1$ ，但后续并未提及。怀疑可能是笔误)，使得第一个密文为0。换句话说（上标表示color bit），满足 $E_{W_a^0,W_b^0}(W_c^0)=H(g,W_a^0||W_b^0)\bigoplus W_c^0=0$ 。不难看出这种情况下 $W_c^0$ 对应的标签等于 $H(g,W_a^0||W_b^0)$ 。于是后续只需要传三个密文，因为第一个密文固定为0
3. Free-XOR
- 生成一个全局秘密值 $\Delta\in 0,1^{\lambda}$ (所有长度为 $\lambda$ 比特的二进制字符串的集合，元素数量 $2^{\lambda}$ )，然后生成输入标签，使得 $W_i^0\bigoplus W_i^1=\Delta$ 。或者说， $W_i^x=W_i^0\bigoplus(x\Delta)$ （如果x=0， $x\Delta=0^{\lambda}$ ;如果x=1， $x\Delta=\Delta$ ）。于是对于一个xor门 $G(W_a,W_b)=W_c$ ，有 $W_a^x\bigoplus W_b^x=(W_a^0\bigoplus W_b^0)\bigoplus(x\bigoplus y)\Delta$ 。此时如果让对应0的输出标签 $W_c^0=W_a^0\bigoplus W_b^0$ （对应1的输出标签则是多异或一个 $\Delta$ ）,会发现已经不需要任何密文了，因为接收者可以根据输入标签直接算出对应的输出标签
- 这个技巧可以与以上两个技巧一起用。使 $LSB(\Delta)=1$ ，就能保证每一对生成的输入标签的color bit，即lsb，不同

然后跳到`Free-XOR Offset Leak`（作者在文章的开头说只读`elementary-optimizations`和`free-xor-offset-leak-attack`就足以理解wp了）

free xor中需要用OT传输的两个信息为 $W_i^0$ 和 $W_i^1$ 。如果攻击者以某种方式同时获取了两个标签，便能得到全局偏移值 $\Delta$ 。[nil-circ](https://github.com/defund/ctf/tree/master/dicectf-quals-2025/nil-circ)中使用的是基于ECDH的Chou-Orlandi OT协议。具体过程如下：

1. 背景
- 发送者拥有两条秘密 $m_0,m_1$
- G为curve-25519的公共generator，q为G的阶
- 下述所有运算均在curve-25519上考虑
- H为random oracle
2. 过程
- 发送者随机选择 $y\in Z_q$ (原文的 $y\in_R Z_q$ 的R就是随机选择，random的意思)，将Y=y\*G发送给接收者
- 接收者随机选择 $r\in Z_q$ ，然后根据自己的secret bit b（接收者想要知道那条秘密）生成R。若b=0,R=r\*G;若b=1，R=Y-r\*G 。接着计算 $k_b=H(i,r\*Y)$ ，其中i是计数器，用于计数多次OT的索引
- 接收者计算两条一次性密钥， $k_0=H(i,yR)$ 和 $k_1=H(i,yY-yR)$ 。然后加密两条秘密 $c_0=m_0\bigoplus k_0$ , $c_1=m_1\bigoplus k_1$ 。将 $(c_0,c_1)$ 发送给接收者
3. 数学原理

注意到当b=0时， $H(i,yR)=H(i,y\*r\*G)=k_b$ ; b=1时， $H(i,yY-yR)=H(i,y\*y\*G-y\*(Y-r\*G))=H(i,y\*y\*G-y\*y\*G+y\*r\*G)=H(i,y\*r\*G)=k_b$ 。所以不论b是什么，接收者的 $k_b$ 与发送者的一条信息的密钥相同，进而可以获取秘密

问题是，并没有手段保证接收者就按照这套标准给发送者发送R。在free xor的背景下，攻击者可以尝试构造 $k_0=k_1\Rightarrow yR=yY-yR\Rightarrow R=\frac{1}{2}Y$ ,就能计算 $\Delta=c_0\bigoplus c_1=m_0\bigoplus m_1=W_i^0\bigoplus W_i^1$

无论如何混淆真值表，真值表毕竟还是真值表，其功能不会改变。因此对于一些不平衡的真值表，可以仅通过标签判断其对应的值。比如前面提到的AND门。四组不同的输入只会产生两个不同的标签，明显出现三次的标签代表0，只出现一次的标签代表1。假设输入标签分别为 $W_a^x,W_a^y,W_b^u,W_b^v$ ，且 $W_a^x$ 和 $W_b^u$ 输出了 $W_c^1$ ，则我们可以推断 $W_a^x=W_a^1,W_b^u=1$ 。接着，由于电路的结构是公开的，我们就能得知所有与 $W_0$ 和 $W_1$ 相关的wire的方程。收集足够多的方程后便能解出所有标签的值