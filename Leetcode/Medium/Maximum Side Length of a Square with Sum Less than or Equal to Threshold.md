# [Maximum Side Length of a Square with Sum Less than or Equal to Threshold](https://leetcode.com/problems/maximum-side-length-of-a-square-with-sum-less-than-or-equal-to-threshold)

学一下二维prefix sum
```c++
//https://leetcode.com/problems/maximum-side-length-of-a-square-with-sum-less-than-or-equal-to-threshold/editorial
class Solution {
public:
    int getRect(const vector<vector<int>>& P, int x1, int y1, int x2, int y2) {
        //(x1,y1)表示矩形左上角的坐标，(x2,y2)为矩形右下角的坐标
        return P[x2][y2] - P[x1 - 1][y2] - P[x2][y1 - 1] + P[x1 - 1][y1 - 1];
    }

    int maxSideLength(vector<vector<int>>& mat, int threshold) {
        int m = mat.size(), n = mat[0].size();
        vector<vector<int>> P(m + 1, vector<int>(n + 1));
        for (int i = 1; i <= m; ++i) { //从1开始方便处理边界情况
            for (int j = 1; j <= n; ++j) {
                P[i][j] = P[i - 1][j] + P[i][j - 1] - P[i - 1][j - 1] +
                          mat[i - 1][j - 1];
                //这块在脑子里画个图更好理解。计算P[i][j]时，需要相加上面的矩形的左侧的矩形(P[i - 1][j] + P[i][j - 1])。这样会重复相加上方和左侧矩形的重叠部分，所以要减去P[i - 1][j - 1]
            }
        }

        int r = min(m, n), ans = 0;
        for (int i = 1; i <= m; ++i) {
            for (int j = 1; j <= n; ++j) {
                for (int c = ans + 1; c <= r; ++c) {
                    if (i + c - 1 <= m && j + c - 1 <= n &&
                        getRect(P, i, j, i + c - 1, j + c - 1) <= threshold) {
                        ++ans;
                    } else {
                        break;
                    }
                }
            }
        }
        return ans;
    }
};
```
二维prefix sum也叫积分图（Summed-area table），`P[i][j]`表示原矩阵(0,0)到(i-1,j-1)的矩形区域和