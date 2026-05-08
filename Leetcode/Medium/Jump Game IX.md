# Jump Game IX

我需要分享这段神人代码

从discussion区`Connor Colombe`的评论可以总结出以下要点：
1. 从后往前遍历数组
2. ans[i+1]一定大于等于ans[i]
3. 假如ans[i]在i的左边，直接用prefix_maximum就能得到答案
4. 假如ans[i]在i的右边，需要找到从i能跳到的最右边的索引
    - 利用prefix_maximum找到从i往左跳能跳到的最大值，之后找到数组中小于这个最大值且最靠右的索引j
    - 因为`1`，此时可以直接用ans[j]的值作为ans[i]的答案

明显难点在于第四点。不过这个问题想必已有很多人研究过，我就叫ds直接给我一个实现。它给了我个FenwickMax。不知道这是啥玩意，总之用着再说：
```c++
class FenwickMax {
    vector<int> tree;
    int n;
public:
    FenwickMax(int sz) : n(sz), tree(sz + 1, -1) {}
    void update(int idx, int val) {
        while (idx <= n) {
            if (val > tree[idx]) tree[idx] = val;
            idx += idx & -idx;
        }
    }
    int query(int idx) {
        int res = -1;
        while (idx > 0) {
            if (tree[idx] > res) res = tree[idx];
            idx -= idx & -idx;
        }
        return res;
    }
};
class Solution {
public:
    vector<int> maxValue(vector<int>& nums) {
        int n=nums.size();
        vector<pair<int,int>> prefix_max(n);
        prefix_max[0]={0,nums[0]};
        for(int i=1;i<n;i++){
            if (nums[i] > prefix_max[i-1].second)
                prefix_max[i] = {i, nums[i]};
            else
                prefix_max[i] = prefix_max[i-1];
        }
        vector<int> ans(n);
        vector<int> sorted = nums;
        sort(sorted.begin(), sorted.end());
        sorted.erase(unique(sorted.begin(), sorted.end()), sorted.end());
        int m = sorted.size();
        FenwickMax bit(m);
        vector<int> largest(n, -1);
        for (int i = n - 1; i >= 0; --i) {
            int rk = lower_bound(sorted.begin(), sorted.end(), nums[i]) - sorted.begin() + 1;
            if (rk > 1) {
                largest[i] = bit.query(rk - 1);
            }
            bit.update(rk, i);
        }
        for(int i=n-1;i>=0;i--){
            int idx=largest[prefix_max[i].first];
            if(idx!=-1) ans[i]=max(prefix_max[i].second,ans[idx]);
            else ans[i]=prefix_max[i].second;
        }
        return ans;
    }
};
```
editorial的解法比较巧妙，但最巧妙的还得是采样区。原理和editorial的Approach 1类似，但大幅优化了interval之间的转换