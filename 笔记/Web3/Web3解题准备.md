# Web3解题准备

记录如何配置解题脚本并运行

## Metamask

今天终于做出来了人生第一道blockchain入门题。漏洞实在太明显了，我这种没有啥经验的都能一眼看出来，所以不记录题目内容。卡了我很久的反而是“怎么deploy我的攻击合约啊“？翻看我的笔记，大佬们都用foundry/cast，但是我怎么样都配置不好……最后从笔记里翻出了这篇[wp](https://github.com/skabdulhaq/CTF-learnings/blob/main/CTF-writeups/BytesbanditCTF/blockchain-GuessTheName.md)，使用remix+metamask的配置。简单好上手，个人认为是最适合入门的

首先安装metamask的chrome插件： https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn ，按照步骤创建新账号即可。接着点击右上角三个点，选择“设置”->“网络”->"添加网络"，把blockchain题目给的rpc url填进去。链ID通常是1，不确定的话可以用python的web3模块查看：
```py
from web3 import Web3
web3=Web3(Web3.HTTPProvider("rpc_url"))
print(web3.eth.chain_id)
```
货币符号感觉不重要，随便填一个就行。保存后返回主页，右上角切换网络为刚才创建的题目所处的网络。接着正中央上方为当前所使用的账号，点击后选择"Add account or hardware wallet"->"导入账户",粘贴题目提供的私钥即可导入题目为我们提供的账号。这步很重要，我们自己的默认账号在题目所处的网络上一分钱没有，要是Remix用这个账号会导致没钱释放攻击合约的情况……

然后就可以去[Remix](https://remix.ethereum.org)了。点击倒数第二个图标（Deploy & run transactioins），最上方的ENVIRONMENT选择Inject Provider - MetaMask。绑定账号时一定要选那个有钱的账号，原因之前提过了。如果不小心绑定了没钱的账号，个人当时（本经验不来自于网络）直接重装了metamask，后面想想应该清除cookie就行了。另外提醒一点，metamask里导入的账户可以随时删除，但是自己创建的不能，要想删除的话只能重装插件（我在官网看到这句话时人都傻了）

这样应该就可以了，后面正常写攻击合约正常deploy并调用函数即可，用大白话说就是“Remix该怎么用咱们就怎么用”。顺便再说一句，开头提到的那篇wp确实是最适合初学者入门的，包括里面攻击合约的编写也是最基础的

remix改版后稍微有点不一样了。还是点击`Deploy & run transactioins`按钮（不过不是倒数第二个了），会发现最上方的ENVIRONMENT点开后有个WalletConnect选项。点击即可连接至metamask（如果显示metamask未安装等一系列内容的话，插件处唤出metamask然后刷新一下）。连接完成后（metamask右上角会显示“已连接”）还是在ENVIRONMENT里，点击`Inject Provider - MetaMask`即可

(但是我连上后发现deploy不了contract……可能是metamask相关的bug，总之还是foundry稳定且好用)

## Foundry

再记录一个foundry的用法

参考 https://book.getfoundry.sh/getting-started/installation ，直接`curl -L https://foundry.paradigm.xyz | bash`，然后运行`foundryup`（可能需要开个新的terminal）即可安装好foundry工具

接下来创建一个foundry项目。运行`forge init projectName`会在当前目录创建一个名为`projectName`的文件夹，里面的文件结构大致如下：
```
Project/
├── src/
│   ├── something.sol
├── test/
│   ├── something.t.sol
├── script/
│   ├── something.s.sol
├── foundry.toml
```
接下来就能在script目录下编写exp了（其实在哪个目录下都行，毕竟不是正式项目）。脚本示例见 https://themj0ln1r.github.io/writeups/glacierctf23

写好exp后用这个命令执行：`forge script script/Attack.s.sol:AttackScript --rpc-url $ETH_RPC_URL --private-key $PRIVATE_KEY --broadcast`

再记录一些杂项内容

- 一般web3题目都会给个nc地址用来管理instance。一定要保存好instance给出的内容。听起来像废话，然而我一直以为终端会给我保存好，我想用的时候可以往上翻。结果foundry会打印一些特殊字符，把我的记录刷掉了……
- 使用`cast call`(view和pure函数)/`cast send`（修改状态的函数）时，被调用的函数得到的`msg.sender`是address(0)。可以用`--from`参数指定msg.sender
- foundry内部会查看一些环境变量。比较常用的如下：
    - `ETH_RPC_URL`：默认使用的rpc url
    - `PRIVATE_KEY`:默认的私钥

设置了这些变量后，调用命令时就无需指定`--rpc-url`或`--private-key`了

另外`--broadcast`是必须的，不带的话就是在本地测试网络下运行，不影响外部内容

如果想用一个项目做多道题，每道题做完后需运行`forge clean`，防止缓存上一道题不需要的文件

## Sepolia testnet

今天遇见一道sepolia testnet上的题。下列资源比较有用

- https://sepolia.etherscan.io ：用题目提供的地址可以搜索对应的合约，可用来查看合约内容是否匹配，或者确认自己在正确的testnet上
- https://rpc.info/ethereum-sepolia ：查找sepolia testnet的rpc url
- https://cloud.google.com/application/web3/faucet/ethereum/sepolia ：google的Faucet，用于获取sepolia testnet上的ETH（没ETH就没法释放合约，付gas之类的）

## Others

这里是一个blockchain（solidity）的javascript web3开发教程： https://www.youtube.com/watch?v=gyMwXuJrbJQ ,不过也有blockchain（solidity）的基础/深度知识讲解

一些练习题：
- https://ethernaut.openzeppelin.com
- https://www.damnvulnerabledefi.xyz