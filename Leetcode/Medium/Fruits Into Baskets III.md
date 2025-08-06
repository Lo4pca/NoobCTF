# [Fruits Into Baskets III](https://leetcode.com/problems/fruits-into-baskets-iii)

segment tree==hard

```c++
//editorial
//关于segment tree的介绍见 https://oi-wiki.org/ds/seg
class Solution {
public:
    int segTree[400007];
    vector<int> baskets;
    void build(int p, int l, int r) { //l和r分别为当前区间的起始和结束索引，p为节点编号
        if (l == r) { //base case为单元素区间
            segTree[p] = baskets[l];
            return;
        }
        int mid = (l + r) >> 1; //将当前区间从中间分段
        build(p << 1, l, mid); //子节点编号为父节点乘2
        build(p << 1 | 1, mid + 1, r);
        segTree[p] = max(segTree[p << 1], segTree[p << 1 | 1]); //当前区间的最大值为两个子区间中的最大值
    }
    int query(int p, int l, int r, int ql, int qr) { //p为当前节点编号，编号代表的区间[l,r]，请求的区间[ql,qr]，返回区间的最大值
        if (ql > r || qr < l) {
            return INT_MIN; //两个区间无交集，返回最小值（因求的是最大值）
        }
        if (ql <= l && r <= qr) { //当前节点代表的区间包含在查询的区间内
            return segTree[p]; //直接返回这个区间的最大值，即节点p记录的值。毕竟再往下拆就没意义了
        }
        int mid = (l + r) >> 1; //如果走到这里的话，说明当前节点代表的区间太大，需要拆成更小的区间来匹配查询需要
        return max(query(p << 1, l, mid, ql, qr),
                   query(p << 1 | 1, mid + 1, r, ql, qr));
    }
    void update(int p, int l, int r, int pos, int val) { //单点更新，将线段树代表的数组的pos处的值更新为val
        if (l == r) {
            segTree[p] = val;
            return;
        }
        int mid = (l + r) >> 1;
        if (pos <= mid) { //判断目标在哪一段子区间
            update(p << 1, l, mid, pos, val);
        } else {
            update(p << 1 | 1, mid + 1, r, pos, val);
        }
        segTree[p] = max(segTree[p << 1], segTree[p << 1 | 1]); //子区间更新了最大值，自然父区间也要更改
    }
    int numOfUnplacedFruits(vector<int>& fruits, vector<int>& baskets) {
        this->baskets = baskets;
        int m = baskets.size();
        int count = 0;
        if (m == 0) {
            return fruits.size();
        }
        build(1, 0, m - 1);
        for (int i = 0; i < m; i++) {
            int l = 0, r = m - 1, res = -1;
            while (l <= r) {
                int mid = (l + r) >> 1;
                if (query(1, 0, m - 1, 0, mid) >= fruits[i]) { //binary search寻找最左边的满足条件的basket
                    res = mid;
                    r = mid - 1;
                } else {
                    l = mid + 1;
                }
            }
            if (res != -1) {
                update(1, 0, m - 1, res, INT_MIN); //标记用过的basket
            } else {
                count++;
            }
        }
        return count;
    }
};
```
线段树可以在O(logN)的时间复杂度内实现单点修改、区间修改、区间查询（区间求和，求区间最大值，求区间最小值）等操作。这题用的是区间最大值操作

关于query的原理：

假如函数没有走前两个if case返回的话，说明第一次调用时的配置可能有以下情况：
```
l ql ... qr r
l=ql ... qr r
l ql ... qr=r
```
只用看第一种，因为剩下两种配置其实差不多。在中间切一刀：
```
l ql mid qr r
```
`l ql mid`这段递归的结果只有两种。要么ql被归到右边那段（左边那段与query完全不重合，返回INT_MIN），走第二个if case返回；要么ql自己是个单区间，走第一个if case。ql被归到左边那段的情况其实就和现在相同，所以不计入

`mid qr r`类似，把上述说法左右交换一下就是了