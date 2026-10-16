# [Count Number of Teams](https://leetcode.com/problems/count-number-of-teams)

欠的binary indexed tree总有一天要学的
```c++
//偷瞄了一眼editorial的思路 :P
class Solution {
public:
    int numTeams(vector<int>& rating) {
        int ans=0;
        int leftSmaller;
        int rightLarger;
        for(int mid=1;mid<rating.size();mid++){
            leftSmaller=0;
            rightLarger=0;
            for(int left=0;left<mid;left++){
                if(rating[left]<rating[mid]) leftSmaller++;
            }
            for(int right=mid+1;right<rating.size();right++){
                if(rating[right]>rating[mid]) rightLarger++;
            }
            ans+=leftSmaller*rightLarger;
            ans+=(mid-leftSmaller)*(rating.size()-mid-rightLarger-1);
        }
        return ans;
    }
};
```
上面这个是 $O(n^2)$ 的dp做法。拖慢这个算法的罪魁祸首是中间那两个for语句，作用是“寻找相对于mid点左边小于它的点的数量和右边大于它的点的数量”，复杂度是O(n)。能不能让它快一点？答案是[binary indexed tree](https://cs.stackexchange.com/questions/10538/bit-what-is-the-intuition-behind-a-binary-indexed-tree-and-how-was-it-thought-a)。不过虽然它叫“tree”，它其实不是树(未来的我勘误一下：确实是树，压缩成数组表示了)，只是一个有特别规则的数组。用来算prefix sum（或者说数组里某一段的和）有奇效
```c++
//https://leetcode.com/problems/count-number-of-teams/editorial
class Solution {
public:
    int numTeams(vector<int>& rating) {
        // Find the maximum rating
        int maxRating = 0;
        for (int r : rating) {
            maxRating = max(maxRating, r);
        }

        // Initialize Binary Indexed Trees for left and right sides
        vector<int> leftBIT(maxRating + 1, 0);
        vector<int> rightBIT(maxRating + 1, 0);

        // Populate the right BIT with all ratings initially
        for (int r : rating) {
            updateBIT(rightBIT, r, 1);
        }

        int teams = 0;
        for (int currentRating : rating) {
            // Remove current rating from right BIT
            updateBIT(rightBIT, currentRating, -1);

            // Count soldiers with smaller and larger ratings on both sides
            int smallerRatingsLeft = getPrefixSum(leftBIT, currentRating - 1);
            int smallerRatingsRight = getPrefixSum(rightBIT, currentRating - 1);
            int largerRatingsLeft = getPrefixSum(leftBIT, maxRating) -
                                    getPrefixSum(leftBIT, currentRating);
            int largerRatingsRight = getPrefixSum(rightBIT, maxRating) -
                                     getPrefixSum(rightBIT, currentRating);

            // Count increasing and decreasing sequences
            teams += (smallerRatingsLeft * largerRatingsRight);
            teams += (largerRatingsLeft * smallerRatingsRight);

            // Add current rating to left BIT
            updateBIT(leftBIT, currentRating, 1);
        }

        return teams;
    }

private:
    // Update the Binary Indexed Tree
    void updateBIT(vector<int>& BIT, int index, int value) {
        while (index < BIT.size()) {
            BIT[index] += value;
            index +=
                index & (-index);  // Move to the next relevant index in BIT
        }
    }

    // Get the sum of all elements up to the given index in the BIT
    int getPrefixSum(vector<int>& BIT, int index) {
        int sum = 0;
        while (index > 0) {
            sum += BIT[index];
            index -= index & (-index);  // Move to the parent node in BIT
        }
        return sum;
    }
};
```