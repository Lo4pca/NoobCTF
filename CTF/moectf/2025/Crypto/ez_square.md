# ez_square

AI做难的数学题很快，但不一定好；那么做简单的数学题就能又快又好了（

$(p+q)^2\equiv p^2+2pq+q^2\equiv p^2+q^2\mod n$

拿到的hint实际上是Z中的 $(p+q)^2$ 减去kn得到的。如果多测试几次的话，会发现k=4（没有跑出过不等于4的情况）。因此hint等于Z中的 $p^2-2pq+q^2$ 。这等于Z中的 $(p-q)^2$ 。于是直接开方hint就能拿到p-q的值了

设s=p+q,t=p-q，有 $s^2-t^2=4n$ ，那么 $s=\sqrt{4n+t^2}$ 。p+q也有了后拿p和q就很简单了
```py
from Crypto.Util.number import *
from gmpy2 import iroot
n = 
c = 
hint = 
p_plus_q=iroot(hint+4*n,2)[0]
p_minus_q=iroot(hint,2)[0]
p=(p_plus_q+p_minus_q)//2
q=n//p
print(long_to_bytes(pow(c,inverse(65537, (p-1)*(q-1)), n)))
```