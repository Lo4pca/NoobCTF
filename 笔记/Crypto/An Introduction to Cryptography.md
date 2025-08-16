# An Introduction to Cryptography

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

a和b均为整数，b大于0。a，b，q和r均满足`Division With Remainder`的定义 $a=bq+r,0\leq r$ < b

1. 证明集合{ $a-bq:q\in Z$ } 中至少有一个非负整数

如果a > b，当q是正整数时存在满足条件的r

如果a=b，q只能等于1，r=0

如果a < b，q必须为0，如果大于0的话a-bq会是负数，不满足r的定义；小于0的话r一定会大于等于b，也不满足定义。此时r只能等于a，满足定义

无论是哪种情况，均至少存在一个符合定义的r

（有点不对劲了，我开始不知道我在写啥了……明明很简单的道理，为啥表达不出来？）

（我好像知道为啥了。我怎么在证q的取值范围啊（）