# [Count Good Triplets in an Array](https://leetcode.com/problems/count-good-triplets-in-an-array)

editorial的解法没看懂，但是solutions区的反而能看懂一点
```c++
//https://leetcode.com/problems/count-good-triplets-in-an-array/solutions/1787085/bit
class Solution {
public:
    constexpr int static n = 100000;
    int bt[n + 1] = {};
    int prefix_sum(int i) {
        int sum = 0;
        for (i = i + 1; i > 0; i -= i & (-i))
            sum += bt[i];
        return sum;
    }
    void add(int i, int val) {
        for (i = i + 1; i <= n; i += i & (-i))
            bt[i] += val;
    }
    long long goodTriplets(vector<int>& nums1, vector<int>& nums2) {
        long long res = 0, sz = nums1.size();
        vector<int> ids(sz);
        for (int i = 0; i < sz; ++i)
            ids[nums2[i]] = i;
        for (int i = 0; i < sz - 1; ++i) {
            int mid = ids[nums1[i]], sm = prefix_sum(mid), gr = sz - 1 - mid - (i - sm);
            res += (long long)sm * gr;
            add(mid, 1);
        }
        return res;
    }
};
```
prefix_sum和add是binary indexed tree（FenwickTree）的实现，这里不看原理直接拿轮子也行（

跟着solution的思路：替换第一个数组里的元素为这个元素在第二个数组里的索引，即ids。表面上它是nums2的元素-索引映射，但由于两个nums都是同组元素的排列，ids便遵循“以nums1[i]作为索引，对应的元素是nums2中相同元素的索引“。现在我们要保证：
- nums1中的元素按顺序出现，即题目描述中的`pos1x < pos1y < pos1z`。这点自然如此，因为我们就是按顺序遍历nums1的
- 同样的元素在nums2中的索引满足`pos2x < pos2y < pos2z`。用`ids[nums1[i]]`取出`nums1[i]`元素在nums2中的索引mid，然后用prefix_sum取出mid之前的元素数量。因为后续依赖`add(mid, 1)`填充bit，这里无需担心取出了满足`pos2x < pos2y`但不满足`pos1x < pos1y`的数量

最后套用公式计算满足以上两个条件的z元素数量（这里solution里有图，虽然我还是不理解）

并非能看懂一点，完全不懂