# Maximum Total Subarray Value II

提示基本给出了完整的答案。虽然我没见过SparseTable，但是AI时代下找一个数据结构的实现可太简单了
```c++
class SparseTable {
private:
    vector<vector<int>> st_min;
    vector<vector<int>> st_max;
    vector<int> log;
public:
    SparseTable(const vector<int>& arr) {
        int n = arr.size();
        log.resize(n + 1);
        log[1] = 0;
        for (int i = 2; i <= n; ++i)
            log[i] = log[i / 2] + 1;
        int K = log[n] + 1;
        st_min.assign(K, vector<int>(n));
        st_max.assign(K, vector<int>(n));
        for (int i = 0; i < n; ++i){
            st_min[0][i] = arr[i];
            st_max[0][i] = arr[i];
        }
        for (int k = 1; k < K; ++k) {
            for (int i = 0; i + (1 << k) <= n; ++i) {
                st_min[k][i] = min(st_min[k-1][i], st_min[k-1][i + (1 << (k-1))]);
                st_max[k][i] = max(st_max[k-1][i], st_max[k-1][i + (1 << (k-1))]);
            }
        }
    }
    int queryMin(int L, int R) {
        int k = log[R - L + 1];
        return min(st_min[k][L], st_min[k][R - (1 << k) + 1]);
    }
    int queryMax(int L,int R){
        int k = log[R - L + 1];
        return max(st_max[k][L], st_max[k][R - (1 << k) + 1]);
    }
};
class Solution {
public:
    long long maxTotalValue(vector<int>& nums, int k) {
        int n=nums.size();
        SparseTable st(nums);
        auto comp = [&st](const pair<int,int>& a, const pair<int,int>& b) {
    return (st.queryMax(a.first, a.second) - st.queryMin(a.first, a.second)) <
           (st.queryMax(b.first, b.second) - st.queryMin(b.first, b.second));
};
        priority_queue<pair<int,int>, vector<pair<int,int>>, decltype(comp)> pq(comp);
        for(int i=0;i<n;i++){
            pq.push({i,n-1});
        }
        long long ans=0;
        while(k--){
            auto [l,r]=pq.top();
            pq.pop();
            ans+=st.queryMax(l, r) - st.queryMin(l, r);
            if(r>l) pq.push({l,r-1});
        }
        return ans;
    }
};
```
关键点在于，一段subarray `nums[l..r]`的最大值与最小值的差在r减小时只会减小，即"monotonically decreasing"。所以我们可以固定r=n-1，用max heap记录所有可能的l值；然后在记录heap给出的最大的k个元素时，每pop一个元素`[l,r]`就插入`[l..r-1]`，单调性保证了新插入的元素一定小于等于原本的元素

剩下的一个问题是，怎么快速获取一段subarray的最大值和最小值？答案是SparseTable：
- `st[k][i]`表示从索引i开始，长度为`2^k`的区间的查询结果
- 构建table时利用的递推关系：对于 k > 0，可以把长度为 $2^k$ 的区间分成两个长度为 $2^{k-1}$ 的子区间:`st[k][i] = combine(st[k-1][i], st[k-1][i + 2^(k-1)])`
- 查询：对于任意区间 [L, R]，找到最大的 k 使得 $2^k ≤ R - L + 1$ ，即 k = floor(log2(R - L + 1))，然后用两个长度为 $2^k$ 的区间即可覆盖整个查询区间：`query(L, R) = combine(st[k][L], st[k][R - 2^k + 1])`
    - 两个区间可能有重叠，因此要求combine函数是任何满足幂等性质的操作（对同一个元素重复应用多次操作，结果与只应用一次相同，即`f(f(x)) = f(x)`），比如max，min等