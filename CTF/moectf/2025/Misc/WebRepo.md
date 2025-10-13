# WebRepo

binwalk提供的webp可以发现`0x3E8C`处有一个7z文件（也可以通过`webpinfo -diag`命令发现RIFF大小小于实际文件大小判断末尾隐藏了东西），但不知道为什么binwalk提取不出来
```py
with open("WebRepo.webp",'rb') as f:
    f.seek(0x3E8C)
    file=f.read()
with open("res.7z",'wb') as f:
    f.write(file)
```
解压后得到一个`.git`目录。首先`git log --oneline --graph --all`查看提交历史，发现master分支和flag。然后`git checkout master`发现`flag.txt`已被删除。不过git仓库中很难删干净东西，因为记录还在那。于是拿commit hash恢复flag：`git checkout 249ff41 -- flag.txt`