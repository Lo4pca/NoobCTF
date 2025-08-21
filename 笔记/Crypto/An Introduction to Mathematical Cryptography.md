# An Introduction to Mathematical Cryptography

cryptohack服务器里有很多人推荐这本书，让我看看！

## An Introduction to Cryptography

第一章的内容比较基础，懒得做笔记了，直接从基础的题目做起（然而不一定做得出来……）

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