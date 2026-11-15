# [Minimum Positive Sum Subarray](https://leetcode.com/problems/minimum-positive-sum-subarray)

这索引给我算得有点死了
```c++
class Solution {
public:
    int minimumSumSubarray(vector<int>& nums, int l, int r) {
        int n=nums.size();
        vector<int> prefix_sum(n+1);
        for(int i=0;i<n;i++){
            prefix_sum[i+1]=nums[i]+prefix_sum[i];
        }
        multiset<int> ms;
        int ans=INT_MAX;
        for(int i=1;i<=n;i++){
            if(i-r-1>=0) ms.erase(ms.find(prefix_sum[i-r-1]));
            if(i-l>=0) ms.insert(prefix_sum[i-l]);
            auto it = ms.lower_bound(prefix_sum[i]);
            if (it != ms.begin()) {
                --it;
                ans=min(ans,prefix_sum[i]-*it);
            }
        }
        return ans==INT_MAX?-1:ans;
    }
};
```
不想走爆破，和ds讨论有没有更好的办法。说好ds不直接给我答案的，结果确实没给代码，只是重点思路都透完了。倒无伤大雅，我本来也不指望能想出来

利用prefix_sum可以快速计算某段subarray的和。给定子数组右端点 R（元素索引），需要在 [R-r+1, R-l+1] 内找到最大的、严格小于 prefix_sum[R+1] 的 prefix_sum[L]，则 prefix_sum[R+1] - prefix_sum[L] 是候选答案。似乎不难，但是索引问题直接给我干爆炸了。上面的推理已经是经过ds修改的了，本来我写的prefix_sum是"prefix_sum[i]"表示包括i在内的prefix的和，即prefix_sum[0]=nums[0]。但这会有个问题，假如索引0本身就在候选subarray里，就没有办法算出来[0...R]的和，因为这个公式计算subarray [L...R]的和时用的是prefix_sum[R]-prefix_sum[L-1]，所以当L=0时就出问题了

解决办法是不包括i，即"prefix_sum[i]表示i之前的subarray的和"。所以当索引是i时，实际右端点是i-1。从这里往左延伸出长度l的subarray的话，第1个元素的索引是i-1-l+1=i-l；同理长度为r的subarray的第1个元素的索引是i-r，所以第一个不在这个subarray的元素的索引是i-r-1