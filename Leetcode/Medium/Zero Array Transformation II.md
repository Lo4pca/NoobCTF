# [Zero Array Transformation II](https://leetcode.com/problems/zero-array-transformation-ii)

我看不懂，我真看不懂
```c++
// https://leetcode.com/problems/zero-array-transformation-ii/solutions/6053366/c-line-sweep-without-binary-search-o-n-m-time
class Solution {
public:
    int minZeroArray(vector<int>& nums, vector<vector<int>>& queries) {
        int n = nums.size(), sum = 0, k = 0;
        vector<int> cnt(n + 1, 0);
        for (int i = 0; i < n; i++) {
            while (sum + cnt[i] < nums[i]) {
                if (k == queries.size()) return -1;
                int l = queries[k][0];
                int r = queries[k][1];
                int val = queries[k][2];
                k++;
                if (r < i) continue;
                cnt[max(l, i)] += val;
                cnt[r + 1] -= val;
            }
            sum += cnt[i];
        }
        return k;
    }
};
```
但是马后炮说几嘴还是会的（

首先while的条件是`sum + cnt[i] < nums[i]`，明显只有在`cnt[max(l, i)] += val`的`max(l, i)`中取到i才有可能跳出while。这里的cnt是Difference Array，在给某个范围增加某个数字时效率很高，见 https://www.geeksforgeeks.org/difference-array-range-update-query-o1

sum用于记录当前query累计的减少量，或者说当前位置（i）所有重叠在一起的range的减少总量

外层的for循环用于遍历每个元素，`sum + cnt[i] < nums[i]`用于检查当前元素是否可以通过已处理的query转换为0。`r < i`意味着当前query已经过去了，故不用再处理了，因为前面的query已经将i之前的元素变为0了。`cnt[max(l, i)] += val;`和`cnt[r + 1] -= val;`是正常的Difference Array range update，不过`max(l, i)`比较巧妙，假如l > i，这个query就在为未来的元素作准备（结合`sum += cnt[i];`考虑）；假如l < i，只需要从i开始考虑，原因和之前一样，小于i的元素已经处理完成了