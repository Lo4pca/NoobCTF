# [Minimum Operations to Exceed Threshold Value II](https://leetcode.com/problems/minimum-operations-to-exceed-threshold-value-ii)

你的意思是你为了做一道leetcode题手动实现了一个binary heap？
```c++
//采样区
namespace rocksdb {

template<typename T, typename Compare = std::less<T>>
class BinaryHeap {
 public:
  BinaryHeap() { }
  explicit BinaryHeap(Compare cmp) : cmp_(std::move(cmp)) { }

  void push(const T& value) {
    data_.push_back(value);
    upheap(data_.size() - 1);
  }

  void push(T&& value) {
    data_.push_back(std::move(value));
    upheap(data_.size() - 1);
  }

  const T& top() const {
    return data_.front();
  }

  void replace_top(const T& value) {
    data_.front() = value;
    downheap(get_root());
  }

  void replace_top(T&& value) {
    data_.front() = std::move(value);
    downheap(get_root());
  }

  void pop(int index)
  {
      if (index >= data_.size())
          return;

      data_[index] = std::move(data_.back());
      data_.pop_back();

      auto parent = get_parent(index);
      if (cmp_(data_[parent], data_[index])) {
          return upheap(index);
      } else {
          return downheap(index);
      }
  }

  void pop() {
    data_.front() = std::move(data_.back());
    data_.pop_back();
    downheap(get_root());
  }

  void swap(BinaryHeap &other) {
    std::swap(cmp_, other.cmp_);
    data_.swap(other.data_);
    std::swap(root_cmp_cache_, other.root_cmp_cache_);
  }

  void clear() {
    data_.clear();
    reset_root_cmp_cache();
  }

  bool empty() const { return data_.empty(); }

  size_t size() const { return data_.size(); }

  void reset_root_cmp_cache() {
    root_cmp_cache_ = std::numeric_limits<size_t>::max();
  }

 private:
  static inline size_t get_root() { return 0; }
  static inline size_t get_parent(size_t index) { return (index - 1) / 2; }
  static inline size_t get_left(size_t index) { return 2 * index + 1; }
  static inline size_t get_right(size_t index) { return 2 * index + 2; }

  void upheap(size_t index) {
    T v = std::move(data_[index]);
    while (index > get_root()) {
      const size_t parent = get_parent(index);
      if (cmp_(v, data_[parent])) {
        break;
      }
      data_[index] = std::move(data_[parent]);
      index = parent;
    }
    data_[index] = std::move(v);
    reset_root_cmp_cache();
  }

  void downheap(size_t index) {
    T v = std::move(data_[index]);

    size_t picked_child = std::numeric_limits<size_t>::max();
    while (1) {
      const size_t left_child = get_left(index);
      if (get_left(index) >= data_.size()) {
        break;
      }
      const size_t right_child = left_child + 1;
      picked_child = left_child;
      if (index == 0 && root_cmp_cache_ < data_.size()) {
        picked_child = root_cmp_cache_;
      } else if (right_child < data_.size() &&
                 cmp_(data_[left_child], data_[right_child])) {
        picked_child = right_child;
      }
      if (cmp_(data_[picked_child], v)) {
        break;
      }
      data_[index] = std::move(data_[picked_child]);
      index = picked_child;
    }

    if (index == 0) {
      root_cmp_cache_ = picked_child;
    } else {
      reset_root_cmp_cache();
    }

    data_[index] = std::move(v);
  }

  Compare cmp_;
  std::vector<T> data_;
  size_t root_cmp_cache_ = std::numeric_limits<size_t>::max();
};

}  

class Solution {
public:
    int minOperations(vector<int>& nums, int k) {
        rocksdb::BinaryHeap <int64_t, std::greater<>> pq;
        for (int x : nums) {
            if (x < k)
            pq.push(x);
        }
        if (pq.size() <= 1) return pq.size();

        int ans = 0;
        while (pq.top() < k) {
            const auto x = pq.top(); pq.pop();
            if (pq.empty()) {
                ans += 1;
                break;
            };
    
            const auto y = pq.top();
            const auto r = x * 2 + y;
            if (r >= k)
                return ans + (pq.size() + 2) / 2;
            pq.replace_top(r);
            ans++;
        }
        return ans;
    }
};
```
这题本来挺无聊的，用个priority_queue即可。然而我提交完后去采样区看了一下，不是哥们，这是啥玩意？搜了一下，c++的priority_queue的底层实现也是binary heap啊，为啥这个就更快？