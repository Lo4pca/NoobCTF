# 沙茶姐姐的Fufu

哇，还有dp

dp的关键在于状态的转换和大小问题的识别。大问题就是题目问的东西：有一个长度为N的fufu列表，在总保养难度不超过沙茶姐姐（沙茶姐姐是谁？）的精力的前提下获取最大的总可爱度

小问题和大问题问的东西一般是一样的，但列表长度应更小。假如fufu的长度为N-1，且我们已经解出了此刻的最大总可爱度，怎么得到长度为N时的最大总可爱度？根据小问题解决后用了多少精力决定是否拿最后一个fufu

因此我们至少需要存储两样东西：
- 小问题的答案（此刻的最大总可爱度）
- 解决小问题时用的精力

于是拿二维数组存储：`dp[i][j]`： $i\in[0,n),j\in[0,M]$ ，表示在索引i处解决的小问题用了j精力，答案为`dp[i][j]`

接下来要考虑状态转换的公式，如何从小问题推出大问题

对于第i号fufu（hardness和cute为保养难度和可爱度），假设用了精力j，我们有两种选择：
- 拿，消耗hardness，获得该fufu的cute。据此选择对应的小问题：以第i-1号小问题为基础，如果当前用了精力j，那么解出上一个小问题时用了`j-hardness`精力。`dp[i][j]=dp[i-1][j-hardness]+cute`
- 不拿,没有消耗任何hardness也没有拿到任何cute：`dp[i][j]=dp[i-1][j]`
```c++
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <utility>
using namespace std;
long long solve(int M,const vector<pair<int,int>>& fufu){
    vector<long long> dp(M+1); //long long防止溢出
    int n=fufu.size();
    for(int i=0;i<n;i++){
        int hardness=fufu[i].first;
        int cute=fufu[i].second;
        for(int j=M;j>=hardness;j--){
            dp[j]=max(dp[j],dp[j-hardness]+cute);
        }
    }
    return dp[M];
}
//感谢deepseek提供的读取逻辑
int main() {
    ifstream file("in.txt");
    int T;
    string line;
    getline(file, line);
    stringstream ss(line);
    ss >> T;
    long long ans=0;
    for (int i = 0; i < T; i++) {
        int N, M;
        getline(file, line);
        stringstream ss_nm(line);
        ss_nm >> N >> M;
        vector<pair<int, int>> currentGroup;
        for (int j = 0; j < N; j++) {
            int c, w;
            getline(file, line);
            stringstream ss_cw(line);
            ss_cw >> c >> w;
            currentGroup.push_back(make_pair(c, w));
        }
        ans^=solve(M,currentGroup);
    }
    file.close();
    cout<<"ans: "<<ans<<endl;
    return 0;
}
```
然后你就会发现代码里写的不一样。这是原逻辑的内存优化版本。观察上述状态转换公式，解决第i号问题时我们只会参考第i-1号问题，因此只需要存储两个数组（维度2\*M）：
- n=i
- n=i-1

但其实还可以缩。关键在于：
```c++
for(int j=M;j>=hardness;j--){
    dp[j]=max(dp[j],dp[j-hardness]+cute);
}
```
是倒着遍历的，便可以保证当前问题更新时不会覆盖上一个小问题的答案。更新`dp[j]`时等于更新`dp[i][j]`，取值`dp[j-hardness]`时等于取值`dp[i-1][j-hardness]`