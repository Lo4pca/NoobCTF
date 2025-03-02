# [Longest Common Subsequence](https://leetcode.com/problems/longest-common-subsequence)

dp经典题目，hint把答案摆脸上了，还是死在了细节
```c++
//https://leetcode.com/problems/longest-common-subsequence/solutions/348884/c-with-picture-o-nm
class Solution {
public:
    int longestCommonSubsequence(string text1, string text2) {
        vector<vector<int>> dp(text1.length()+1,vector<int>(text2.length()+1));
        for(int i=0;i<text1.length();i++){
            for(int j=0;j<text2.length();j++){
                if(text1[i]==text2[j])
                    dp[i+1][j+1]=dp[i][j]+1;
                else
                    dp[i+1][j+1]=max(dp[i+1][j],dp[i][j+1]);
            }
        }
        return dp[text1.length()][text2.length()];
    }
};
```
其实hint给出dp公式后这道题已经完成80%了：`DP[i][j] = DP[i - 1][j - 1] + 1 , if text1[i] == text2[j] DP[i][j] = max(DP[i - 1][j], DP[i][j - 1]) , otherwise`。仔细一看发现有点不一样，大佬的代码更新时用的是i+1和j+1。个人猜测是为了避免i=0或j=0时的edge case。我自己写的是这样的：
```c++
class Solution {
public:
    int longestCommonSubsequence(string text1, string text2) {
        vector<vector<int>> dp(text1.length(),vector<int>(text2.length()));
        for(int i=0;i<text1.length();i++){
            for(int j=0;j<text2.length();j++){
                if(text1[i]==text2[j])
                    dp[i][j]=dp[max(i-1,0)][max(j-1,0)]+1;
                else
                    dp[i][j]=max(dp[max(i-1,0)][j],dp[i][max(j-1,0)]);
            }
        }
        return dp[text1.length()-1][text2.length()-1];
    }
};
```
遇见某些特殊test case时会得到错误答案。仔细一想可能是贪方便，处理edgecase时直接用了max，导致i=0和i=1时引用到同一个位置了。以下是错误的testcase案例：
```
"aa"
"aaa"
```
鉴定为菜就多练