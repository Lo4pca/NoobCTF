# Best Time to Buy and Sell Stock using Strategy

prefix sum+sliding window，但是我老是处理不好edge case。遂写了一个poc然后扔给deepseek改edge case，竟然能成？
```c++
class Solution {
public:
    long long maxProfit(vector<int>& prices, vector<int>& strategy, int k) {
        int n = prices.size();
        
        // 计算总策略收益
        long long total_strategy_profit = 0;
        for (int i = 0; i < n; i++) {
            total_strategy_profit += (long long)strategy[i] * prices[i];
        }
        
        long long max_delta = 0;
        
        // 初始化第一个窗口的累积值
        long long before_strategy_sum = 0;  // 前半部分策略加权和
        long long after_price_sum = 0;      // 后半部分价格和
        long long after_strategy_sum = 0;   // 后半部分策略加权和
        
        int half_k = k / 2;
        
        // 计算第一个窗口的前半部分（策略加权）
        for (int i = 0; i < half_k; i++) {
            before_strategy_sum += (long long)strategy[i] * prices[i];
        }
        
        // 计算第一个窗口的后半部分（价格和 + 策略加权）
        for (int i = half_k; i < k; i++) {
            after_price_sum += prices[i];
            after_strategy_sum += (long long)strategy[i] * prices[i];
        }
        
        // 第一个窗口的delta
        max_delta = max(max_delta, after_price_sum - before_strategy_sum - after_strategy_sum);
        
        // 滑动窗口
        for (int i = 1; i <= n - k; i++) {
            // 移除前一个窗口的第一个元素（前半部分）
            before_strategy_sum -= (long long)strategy[i-1] * prices[i-1];
            
            // 移除前一个窗口的中间元素（从后半部分移动到前半部分）
            after_price_sum -= prices[i + half_k - 1];
            after_strategy_sum -= (long long)strategy[i + half_k - 1] * prices[i + half_k - 1];
            
            // 将中间元素添加到前半部分
            before_strategy_sum += (long long)strategy[i + half_k - 1] * prices[i + half_k - 1];
            
            // 添加新窗口的最后一个元素到后半部分
            after_price_sum += prices[i + k - 1];
            after_strategy_sum += (long long)strategy[i + k - 1] * prices[i + k - 1];
            
            // 计算当前窗口的delta
            long long delta = after_price_sum - before_strategy_sum - after_strategy_sum;
            max_delta = max(max_delta, delta);
        }
        
        return total_strategy_profit + max_delta;
    }
};
```