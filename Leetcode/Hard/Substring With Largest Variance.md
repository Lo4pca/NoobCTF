# Substring With Largest Variance

[题目](https://leetcode.com/problems/substring-with-largest-variance/description/)

首先我看不懂题，其次我没学过这个算法，最后我寄了。
```c#
//与 https://leetcode.com/problems/substring-with-largest-variance/editorial/ 类似思路，但是是优化版本
public class Solution {
    public int LargestVariance(string s) {
        if (string.IsNullOrWhiteSpace(s) || s.Length == 1) {
            return 0;
        }

        HashSet<char> distinct = new HashSet<char>();
        foreach (char c in s) {
            distinct.Add(c);
        }

        int maxVariance = 0;
        foreach (char max in distinct) {
            foreach (char min in distinct) {
                if (max == min) {
                    continue;
                }

                maxVariance = Math.Max(maxVariance, getVariance(max, min, s)); //遍历所有字母pair的可能性
            }
        }

        return maxVariance;
    }

    private int getVariance(char max, char min, string s) {
        int maxVariance = 0;
        int variance = 0;
        bool hasMin = false;
        bool startsWithMin = false;

        foreach (char c in s) {
            if (c != max && c != min) {
                continue;
            } else if (c == max) {
                variance++; //虽然max的数量不一定比min大，应该用绝对值。但是上面遍历所有可能性时已经将这种情况考虑进去了。a，b配对和b，a配对都会被跑一遍，总有一种是大的
            } else if (c == min) {
                hasMin = true;
                if (startsWithMin && variance >= 0) { //这个分支的作用我不太懂，我是这么理解的：因为else if的条件是variance - 1 < 0，所以variance在小于等于0时都会进那个分支。而那个分支又会把variance置为-1，等于交替max和min的值一直是0。拿这个例子看： aababbb ，若没有if这个分支，从第二个a开始，接下来两个abab结果为0，剩下两个b并不是最大的，最大的应该是babbb。有了这个if语句，当一个subarray以min开始（这里是a），if语句会帮助程序摆脱掉最开始的a（不进入else if语句），从而获取最大值。
                    startsWithMin = false;
                } else if (variance - 1 < 0) {
                    startsWithMin = true;
                    variance = -1; //这里相当于把local变量variance置0。又因为当前字母是min，所以要-1，于是-1
                } else {
                    variance--;
                }
            }
            
            if (hasMin) { //当前subarray至少要有一个min字母才能更新maxVariance，若没有，当前subarray代表的variance是无效的
                maxVariance = Math.Max(maxVariance, variance);
            }
        }

        return maxVariance;
    }
}
```
```
Runtime
128 ms
Beats
100%
Memory
37.2 MB
Beats
80%
```
这题的算法叫[Kadane's algorithm](https://medium.com/@rsinghal757/kadanes-algorithm-dynamic-programming-how-and-why-does-it-work-3fd8849ed73d)，dp的一种，专门用来解决Maximum Subarray这类问题。简单总结一下这个算法。在不了解这个算法之前，我们想找到最好的subarray就只能爆破。然而，爆破肯定TLE。所以有没有什么办法提高爆破的效率？有！说有这么些数字：1,-3,4,-1,3,-5,请找出里面和最大的一个subarray。枚举爆破做法需要这么做：
```
1
1,-3
1,-3,4
...
1,-3,4,-1,3,-5

-3
-3,4
...
-3,4,-1,3,-5
```
能发现有好多重复的部分，当我知道1+(-3)后，计算1+(-3)+4就不用把三个数再加一遍，直接拿之前的结果加上4不就好了吗？现在我们有了cache的概念，但是还不够，就算记忆了，你这时间复杂度不还是个乘方，只是优化了计算的时间，subarray的爆破完全没优化。我们再转念一想，1+(-3)已经是负数了，为何还要保留起来加上4？为啥不直接从4开始加？当你意识到这一点后，Kadane's algorithm就出来了。个人感觉这是这个算法里最核心的思想。保留两个变量，一个localMax,表示当前subarray的最大值；一个globalMax，表示全部subarray的最大值。遍历array，将数字加上localMax，同时随时Math.Max更新globalMax。当localMax小于0，说明前面的数字没有保留下去的必要了，将localMax重新置为0，从下一个数开始考虑。具体怎么做在上面的链接有写。

但是再等一等，这题好像不是原生的Kadane's algorithm，要做点改动。这题里的subarray必须要有两种不同的字母，若只有一种字母是不算的。所以我们需要一个hasMin变量，标志着当前subarray是否有效。