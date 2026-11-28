# Maximum Number of Items From Sale I

写提示的和写editorial的似乎不是同一个人（
```c++
class Solution {
public:
    int maximumSaleItems(vector<vector<int>>& items, int budget) {
        int M=0;
        for(const auto& item:items){
            M=max(M,item[0]);
        }
        vector<int> freq(M + 1, 0);
        for (const auto& item:items) freq[item[0]]++;
        vector<int> cnt(M + 1, 0);
        for (int f = 1; f <= M; ++f)
            for (int mult = f; mult <= M; mult += f)
                cnt[f] += freq[mult];
        int n=items.size();
        vector<int> dp(budget + 1);
        dp[0] = 0;
        for (int i = 0; i < n; ++i) {
            int w=items[i][1];
            int f=items[i][0];
            for (int j = budget; j >= w; --j){ //倒着遍历的是0/1
                dp[j] = max(dp[j], dp[j - w]+cnt[f]); //因为倒着遍历的话第i轮更新的dp[j]只会用上第i-1轮的dp[j-w]
            }
        }
        for (int i = 0; i < n; ++i) {
            int w=items[i][1];
            int f=items[i][0];
            for (int j = w; j <= budget; ++j){ //正着遍历的是Unbounded
                dp[j] = max(dp[j], dp[j - w] + 1); //而正着遍历时第i轮更新的dp[j]可能用到本轮新更新的dp[j-w]
            }
        }
        return dp[budget];
    }
};
```
跟着提示的步伐走，先叫ds写出hint1的预处理。接下来hint4提到了“knapsack-style DP”，一搜才知道这玩意是有常见类型的：
- 0/1 knapsack：每种物品最多只能用一次
- Unbounded knapsack：每种物品可以用无限多次
- Bounded knapsack：每种物品最多用规定的次数次（0/1就是这种，估计是太常见了所以额外分了一类）

这题在Unbounded knapsack的基础上要求我们区分某个物品是否是第一次使用，但标准模板并不会记录是否使用过某个物品。或许可以搞个二维状态列表`dp[i][j]`，表示“dp[i]是否使用了物品j“，但这把好不容易拉下来的空间复杂度又搞上去了

我看了眼editorial，发现根本没有hint所说的“区分物品是否是第一次购买“。一头雾水的同时看了眼评论区，反倒是`Minduo`的留言给了我启发。可以来两次dp，一次0/1一次Unbounded，第一次只计算首次购买给出的bonus（注意不要额外+1），第二次才是典型的Unbounded

然后就会意识到第二个dp纯粹是多此一举。假如没有首次购买的bonus，这题完全就是greedy，直接全买最便宜的物品就行