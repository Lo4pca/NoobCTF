# [Count Good Numbers](https://leetcode.com/problems/count-good-numbers)

这道题不难，就连我也能随随便便找到公式。但是我突然发现c++里没有内置的modpow，去网上找的实现无法得到`pow(x,0)=1`。暂时逃到了python怀里（
```py
class Solution:
    def countGoodNumbers(self, n: int) -> int:
        mod=int(1e9+7)
        return (pow(5,n//2+(n%2==1),mod)*pow(4,n//2,mod))%mod
```
积累一下c++的modpow写法：
```c++
//https://leetcode.com/problems/count-good-numbers/editorial
class Solution {
private:
    static constexpr int mod = 1000000007;
public:
    int countGoodNumbers(long long n) {
        auto quickmul = [](int x, long long y) -> int {
            int ret = 1, mul = x;
            while (y > 0) {
                if (y % 2 == 1) {
                    ret = (long long)ret * mul % mod;
                }
                mul = (long long)mul * mul % mod;
                y /= 2;
            }
            return ret;
        };
        return (long long)quickmul(5, (n + 1) / 2) * quickmul(4, n / 2) % mod;
    }
};
```