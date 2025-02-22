# [Recover a Tree From Preorder Traversal](https://leetcode.com/problems/recover-a-tree-from-preorder-traversal)

我需要告诉全世界（并不是）我的抽象做法
```c++
class Solution {
private:
    int level=0;
    int index=0;
    int getNum(const string& traversal){
        int value=0;
        while(index<traversal.length()&&traversal[index]!='-'){
            value=value*10+traversal[index]-'0';
            index++;
        }
        return value;
    }
public:
    TreeNode* recoverFromPreorder(string traversal) {
        TreeNode* root=new TreeNode(getNum(traversal));
        dfs(root,traversal);
        return root;
    }
    void dfs(TreeNode* tree,const string& traversal){
        int count=0;
        while(index<traversal.length()&&traversal[index]=='-'){
            count++;
            index++;
        }
        if(count>level){
            tree->left=new TreeNode(getNum(traversal));
            level=count;
            dfs(tree->left,traversal);
        }
        else{
            level=count;
            return;
        }
        if(level==count){
            tree->right=new TreeNode(getNum(traversal));
            dfs(tree->right,traversal);
        }
    }
};
```
到最后我也不知道怎么就行了，迷迷糊糊就这样了。查看[editorial](https://leetcode.com/problems/recover-a-tree-from-preorder-traversal/editorial)，和`Approach 1`思路类似，但我太喜欢（只会）全局变量了……