# [Ideal forms of Coppersmith’s theorem and Guruswami-Sudan list decoding](https://cseweb.ucsd.edu/~nadiah/papers/ideal-coppersmith/ideal-coppersmith-ics-slides.pdf)

记录初看时看到的问题，然后再看几遍看看能不能自己得到答案

1. 第五页`Theorem (Coppersmith/Howgrave-Graham)`中提到的一个条件是 $gcd(B,N)\geq N^{\beta}$ , $\beta$ 是啥？
3. 第六页的proof outline思路是啥？
- 有点不懂它这里proof的是什么。是第六页开头的那个定理吗？可是这个定理里没有B啊？所以我觉得是第五页的那个，然后第六页的定理是第五页定理的另一个形式，把前两个条件结合起来了。因为假如 $f(x_0)\equiv 0\mod B$ ，说明 $f(x_0)$ 是B的倍数，kB。如果 $gcd(B,N)\geq N^{\beta}$ ，gcd(kB,N)只有可能比这个数更大。那么证明的关键点应该是到底能不能在log N时间内找到根 $x_0$ 。应该mod B情况下是不行的，不然还要这个定理干啥；那就尝试构造一个多项式Q(x)与原本的 $f(x_0)$ 同根，这玩意不加任何mod且尽量使其系数较小，就能通过分解的方式获取Q(x)的根
2. 如何理解第七页第一、二条
- 对于第一条，我从第一句开始就不懂了。Ensure any root of f mod B is a root of Q mod $B^k$ ,为什么不能直接ensure是Q mod B？只能说我不太懂变量，它并没有规定k不能等于1……但是为什么说要保证这点的话 Q will be linear combination of $f(x)^iN^{k−i}$ ?这里没说i的上限，但我估计大于等于0。小于0的话没意义，线性组合本来就能减，加个负的完全等于减个正的。然后一个多项式乘上自己不会改变根的值应该挺明显的。最简单的形式，两个x-k相乘，不改变根值还是k的事实。拓展到多高次都是一样，反正两个东西相乘有一个是0其他的全部就是0了。至于乘上N，完全不重要，改的只是系数。现在唯一的难题就是这个k了。假设k=1，那i只能等于1。几个f(x)在这里疯狂线性运算，明显不会改变根的值。假如k=2……不对我算了一下，根还是那个根，和 $B^k$ 一点关系都没有。我突然觉得应该把关注点放到mod身上，比如x=4对于x+7不是根，但是模上个11就是了。然后然后我又发现，有没有可能它说 $Q\mod B^k$ 的根等同于f mod B，不代表它说 $Q \mod B^{k-i}$ 的根不等于f mod B？同时无法保证 $Q\mod B^{k+i}$ 的根等同于f mod B。我实验过了，在k不同的情况下， $f(x)^iN^{k−i}$ 的线性组合无法保证根等同于f mod B
- 第二点我仔细看了一下，其实很简单。要是 $|Q(x_0)|$ 的值小于 $B^k$ ，自然那个模 $B^k$ 就没用了，直接等于在Z上找到了根
3. 第八页的`F[z]-module`是啥
4. 第十一页的 $g(x_i)=y_i \leftrightarrow g(x)≡y_i \mod(x−x_i)$ 是怎么成立的？
- 理解一个东西的最好方式是写出它到底干了些什么。设 $g(x_i)=a_1x_i^n+a_2x_i^{n-1}+...+a^n$ ，那么插入一个新值x（假设它大于 $x_i$ ，模负数我有点晕，但我知道结论一样），两者的差值就是 $a_1(x^n-x_i^n)+a_2(x^n-x_i^n)+...+a_{n-1}(x-x_i)$ 。这整个值模 $x-x_i$ 是0，分开看的话就是每个 $(x^n-x_i^n)$ 是0。那么需要证明 $(x^n-x_i^n)\equiv 0\mod x-x_i$ 。好这个证明我一窍不通，不过我隐隐约约感觉是对的。 $x^n$ 表示这里有 $x^{n-1}$ 个x， $x_i^n$ 同理。因为x大于 $x_i$ ，假如把 $x^{n-1}$ 个x和 $x_i^{n-1}$ 个 $x_i$ 配对的话，只能配出 $x_i^{n-1}$ 个组。每组之间的差值是 $x-x_i$ ，明显可以被 $x-x_i$ 整除，所以所有配对成功的组模 $x-x_i$ 一定是0。还剩下 $x^{n-1}-x_i^{n-1}$ 个x没有配对。 $x^{n-1}-x_i^{n-1}$ 又可以用相同的方式继续往下缩减，最后一定缩得到指数是1的情况。所以可以整除。虽然感觉哪里好像不对……
5. 第十一页的Reed-Solomon list decoding是啥？
6. 第十三页的Algebraic-geometric codes是啥？
- https://en.wikipedia.org/wiki/Algebraic_geometry_code ，是 Reed-Solomon codes的普遍形式

一些收获
1. 第一次见这么清晰的Z（整数）和F[z]（多项式）的类比
2. Reed-Solomon list decoding和Guruswami-Sudan定理