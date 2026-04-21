# [Baby Bundle](https://github.com/idekctf/idekctf-2024/tree/main/crypto/baby-bundle)

这段时间都没有好好看数学，已经对数学ptsd了，各种wp里的长篇大论看着就头痛（不记得在哪里看到的这句话：“数学论文分两种，一种是看了第一页就不想看的，另一种是看了第一行就不想看的”）。今天想好好看一篇，结果一脚踩进了坑里——这是英文吗？怎么一个字没看懂？遂专门写一篇文章控告数学……（其实是对wp里我看不懂的句子进行批注。知识点来自chatgpt，所以可能有错的）

- Let $X=\mathbb P^1_F$ . What is the function field $K(X)$ of $X$?

$\mathbb P^1_F$ 指域F上的射影线(projective line over a field),是射影空间（projective space） $\mathbb P^n_F$ 的特例（n=1）。射影空间 $\mathbb P^n_F$ 又指n+1维空间 $F^{n+1}$ 里所有经过原点的线的集合。换句话说，是 $F^{n+1}$ 里所有非零向量的等价类 $(x_0​,x_1​,…,x_n​)$ 的集合。两个向量间的等价关系定义为： $(x_0​:x_1​:…:x_n​)∼(\lambda x_0​:\lambda x_1​:…:\lambda x_n​),\lambda\in F,\lambda\not ={0}$ ,即只要向量B是向量A的非零标量倍，两者就是相等的（诶，配合下面维基百科给出的图，这里的等价类代表的是不是“平行”？两条线若相交于无穷远点就将两者看成是相等的，因此那个标量代表把一条线平移？）。每个等价类称为一个齐次坐标（homogeneous coordinate）。插一嘴，查了[维基百科](https://en.wikipedia.org/wiki/Projective_space)，里面的定义好像有点不太一样，似乎没有明确提到第一个定义里的“相交于原点”？它只说是“set of the vector lines”。呃，先记定义吧，又是一个“xxx的集合”

回到射影线。chatgpt说其实是仿射线（affine line）加个无穷远点，仿射线就更简单了，只是代表平时看到的最简单的线而已。你这么说我可就要明白了啊（

- The function field of an integral curve is the field of rational functions, where a rational function f is a regular map (read: "function defined by polynomials") that's defined over some dense open set.

积分曲线（integral curve）是一个给定微分方程 $\frac{dy}{dx}=f(x,y)$ 的解曲线。换句话说，它是通过微分方程描述的一族曲线，满足每一点的切线斜率等于f(x,y)。有理函数（rational function）指有限项多项式或有限项多项式的比值。稠密开集（dense open set）的稠密部分见 https://encyclopediaofmath.org/wiki/Dense_set ，[这里](https://baijiahao.baidu.com/s?id=1771452625502003597)有更通俗易懂的解释：“指在一个度量空间中，任意给定一个点，都能找到该稠密集中的点无限接近它。换句话说，稠密集几乎填满了整个度量空间”。“开”指集合不包含其边界点（比如画个圆，包含圆里的空间但不包含画圆的线）

说了这么多，所以K(X)到底是啥？缩句后发现是“有理函数域”，句子的其他部分仅仅是其他补充内容。真的就这？

- What is the structure sheaf $\mathscr O_X$ of $X$?

这个问题wp里说跟解题没有关系。本来想跳过的，但是下一题也提到了structure sheaf。稍微看了chatgpt关于[sheaf](https://math.stackexchange.com/questions/2642231/what-is-an-intuitive-geometrical-explanation-of-a-sheaf)的解释，看起来这是个满足某些性质的管理数据的工具？更正式的定义根本看不明白，特别是链接里的内容。也没找到具体使用案例……感觉也是个跟群、环和域一样抽象的东西。已经不想再给解释写一篇了，脑子里留个印象就行（开摆！）

真看不懂……chatgpt给出的每个解释里涉及的名词我也不懂，去搜这些名词的结果只能是套娃……看来我得看看代数几何是啥玩意。大家都说这玩意数学系的人都不敢轻易动，不过我只是去看看定义，没说要解题，不会有逝的吧？