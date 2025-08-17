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