# [Find in Mountain Array](https://leetcode.com/problems/find-in-mountain-array)

终于到我说这句话了：“这题感觉不难，应该算medium”
```c#
class Solution {
    public int FindInMountainArray(int target, MountainArray mountainArr) {
        int length=mountainArr.Length();
        int start = 0;
        int end = length-1;
        int mid=0;
        while (start <= end) {
            mid = start + (end-start)/2;
            if (mountainArr.Get(mid) < mountainArr.Get(mid+1)) start = mid+1;
            else end = mid-1;
        }
        if(mountainArr.Get(start)==target) return start;
        int first=BinarySearch(target,mountainArr,0,start-1,true);
        if(first!=-1) return first;
        first=BinarySearch(target,mountainArr,start+1,length-1,false);
        return first;
    }
    int BinarySearch(int target, MountainArray mountainArr, int i,int j,bool mode){
        int left = i;
        int right = j;
        int mid=0;
        int element=0;
        while (left <= right) {
            mid = left + (right - left) / 2;
            element=mountainArr.Get(mid);
            if(mode){
                if (element == target) {
                    return mid;
                } else if (element < target) {
                    left = mid + 1;
                } else {
                    right = mid - 1;
                }
            }
            else{
                if (element == target) {
                    return mid;
                } else if (element > target) {
                    left = mid + 1;
                } else {
                    right = mid - 1;
                }
            }
        }
        return -1;
    }
}
```
```
Runtime
70 ms
Beats
94.12%
Memory
39.5 MB
Beats
100%
```
来三次binary search，第一次找mountain array里的peek，参考[Peak Index in a Mountain Array](../Medium/Peak%20Index%20in%20a%20Mountain%20Array.md)。然后以peek的index为分割线，前面是递增数组，后面是递减数组，分别进行binary search即可。有个写的非常简短的大佬： https://leetcode.com/problems/find-in-mountain-array/solutions/317603/c-find-peak-162-binary-search