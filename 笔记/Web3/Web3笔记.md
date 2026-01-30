# Web3笔记

不要再乱分类了……

## Legacy

把web笔记里所有和solidity、blockchain相关的迁移过来。这里放分散的条目

- [Guess The Name](https://github.com/skabdulhaq/CTF-learnings/blob/main/CTF-writeups/BytesbanditCTF/blockchain-GuessTheName.md)
    - 智能合约（[solidity](https://docs.soliditylang.org/en/v0.8.17/index.html)语言）初探
    - 此题代码很简单，解法是自己写另一个合约，内部根据Challenge合约里已有的接口重写方法，使其返回True；然后连上题目提供的Challenge合约，使用[msg.sender](https://stackoverflow.com/questions/48562483/solidity-basics-what-msg-sender-stands-for)地址[释放](https://www.web3.university/tracks/create-a-smart-contract/deploy-your-first-smart-contract)刚才的写的合约。Challenge合约调用重写的函数，获取flag。
    - 在[ctf wiki](https://ctf-wiki.org/blockchain/ethereum/basics/#txorigin-vs-msgsender)看见了msg.sender的详细解释。msg.sender 是函数的直接调用方，在用户手动调用该函数时是发起交易的账户地址，但也可以是调用该函数的一个智能合约的地址。给定这样一个场景，如用户通过合约 A 调合约 B，此时对于合约 A : msg.sender 是用户；对于合约 B : msg.sender 是合约 A
- [evmvm](../../CTF/LA%20CTF/Web/evmvm.md)
    - EVM虚拟机[opcode](https://www.evm.codes/?fork=merge)
    - solidity [assembly](https://docs.soliditylang.org/en/v0.8.19/assembly.html)内部的语言是[yul](https://docs.soliditylang.org/en/v0.8.17/yul.html)。
    - [GAS](https://zhuanlan.zhihu.com/p/34960267)，[calldata](https://www.oreilly.com/library/view/solidity-programming-essentials/9781788831383/f958b119-5a8d-4050-ad68-6422d10a7655.xhtml)和[function selector](https://solidity-by-example.org/function-selector/)等概念
- [Oh sh. Here we go again ?](https://github.com/m4k2/HeroCTF-V5-WU-Foundry/tree/main#challenge-00--oh-sh-here-we-go-again-)
    - 题目给出contract被deploy的地址后，可以利用[Foundry](https://learnblockchain.cn/docs/foundry/i18n/zh/getting-started/installation.html)命令cast code获取其bytecode。`cast code <contract addr> --rpc-url $RPC_URL`.其中RPC_URL题目会提供。也可以用node js的web3库。获取的bytecode后可以[反编译](https://library.dedaub.com/decompile)
    - 调用指定地址的contract的函数
        - `cast send <addr> <func,exa:0x3c5269d8> --rpc-url $RPC_URL --private-key $PRIVATE_KEY --legacy`.private_key可以通过在另一个窗口运行anvil获取，不过我运行的时候提示gas超了，把gas改高了又有新问题
        - 使用solidity。用remix释放的话需要有metamask，然后选项里的environment选injected provider,连上自己的provider即可（如metamask）。参考：https://avan.sh/posts/hero-ctf-v5/
        ```solidity
        contract hero2300_pwn
        {
            function exploit(address addr) public 
            {
                addr.call(abi.encodeWithSelector(0x3c5269d8));
            }
        }
        ```
    - 用python web3和blockchain交互的[课程](https://www.youtube.com/watch?v=UBK2BoFv6Lo&list=PLCwnLq3tOElrubfUWHa1qKrJv1apO8Aag)
- [Classic one tbh](https://github.com/m4k2/HeroCTF-V5-WU-Foundry/tree/main#challenge-01--classic-one-tbh)
    - [selfdestruct](https://solidity-by-example.org/hacks/self-destruct)漏洞。特征点：合约判断balance的逻辑依赖于`address(this).balance`。该函数会将一个合约从blockchain上删除，并将合约内剩余的全部ether转账到制定地址。可用于给没有实现接收转账功能的合约强行转账。
    ```
    The selfdestruct function in Solidity is used to delete a contract from the blockchain and transfer any remaining ether stored in the contract to a specified address.

    The selfdestruct function is a built-in function in Solidity that can be called from a contract to delete itself and transfer its remaining ether balance to a specified address.

    The selfdestruct function can also be used maliciously to force ether to be sent to a specific target by creating a contract with a selfdestruct function, sending ether to it, and calling selfdestruct(target).

    There are three ways to transfer ether in Solidity: transfer, send, and call.value().gas. Each of these ways requires the target to receive the funds to transfer them to the correct address. However, the selfdestruct function can transfer funds without obtaining the funds first.

    To prevent vulnerabilities caused by the selfdestruct function, developers can use a local state variable to update the current balance of the contract when the user deposits funds, instead of using address(this).balance.
    ```
    攻击合约例子：
    ```solidity
    pragma solidity 0.8.17;

    contract Selfdestruct{
        constructor() payable{
            require(msg.value == 0.5 ether);
        }

        function kill(address addr) public {
            selfdestruct(payable(addr));
        }
    }
    ```
    foundry释放/调用相关命令：
    ```sh
    forge create selfdestruct.sol:Selfdestruct --value 0.5ether --rpc-url $RPC_URL --private-key $PRIVATE_KEY
    cast send 0x[Selfdestruct] "kill(address)" 0x[target address] --rpc-url $RPC_URL --private-key $PRIVATE_KEY
    ```
    攻击原理：攻击合约实现了selfdestruct，kill函数的addr填题目的address。这样执行攻击合约的kill函数就会把攻击合约全部的ether转给题目合约。由于题目合约依赖`address(this).balance`计算自身balance，但又有局部变量计算应该有的balance：
    ```solidity
        function sell(uint256 _amount) external {
            require(userBalances[msg.sender] >= _amount, "Insufficient balance");

            userBalances[msg.sender] -= _amount;
            totalSupply -= _amount;

            (bool success, ) = msg.sender.call{value: _amount * TOKEN_PRICE}("");
            require(success, "Failed to send Ether");
            //getEtherBalance()内部使用address(this).balance
            assert(getEtherBalance() == totalSupply * TOKEN_PRICE);
        }
    ```
    那么assert永远不会通过

- [gambling](https://github.com/Kaiziron/gpnctf2023-writeup/blob/main/gambling.md)
    - blockchain solidity [frontrunning](https://omniatech.io/pages/decoding-frontrunning-understanding-the-key-terms-and-techniques)例题。想快速了解这种技巧可以看[视频](https://www.youtube.com/watch?v=uElOqz-Htos).个人认为frontrunning打的是信息差。一个简单的案例：假设有A和攻击者B，以及货币C，价格为1。A尝试购买C货币时被B提前得知，于是B尝试在A之前购买C货币（支付更高的gas fee从而先处理B的请求）。那么到A购买的时候，C货币的价格就涨了，比如涨到1.2。等A买完，B再卖掉，净赚1.2-1的货币差值。
    - [VRF Security Considerations](https://docs.chain.link/vrf/v2/security)(Verifiable Random Function)：Don't accept bids/bets/inputs after you have made a randomness request。此题正是违反了这条导致frontrunning。接着上一条，其实frontrunning不一定要两个人，它只是“提前知道某个信息并获利”的手段。现在有个这样逻辑的合约A：
        - enter(num)函数：输入一个num数字，同时合约A向随机数合约B发送随机数请求
        - 合约B返回随机数
        - claim函数：判断num是否与合约B返回的随机数相同

    漏洞点在于，在发送随机数请求和返回随机数的中间，没有限制用户不能再调用enter函数。加上合约运行时的一举一动是可以在mempool里看到的，并且任何人都能从RPC provider（如[quicknode](https://www.quicknode.com)）那里获取到mempool内容，便有了frontrunning。我们可以随便enter一个数字，在合约B返回随机数之前，提前从mempool读取到这个随机数，然后使用更高的gas fee再次enter这个正确的随机数，让oracle先处理我们这个请求。最后在第二次随机数返回前，调用claim，完成攻击。
    - 一些python web3脚本编写的基础知识
    ```py
    from web3 import Web3, HTTPProvider
    web3 = Web3(HTTPProvider('<rpc url>'))
    gambling_abi = #https://www.quicknode.com/guides/ethereum-development/smart-contracts/what-is-an-abi 。可在Remix里compile合约后获得
    gambling_contract = web3.eth.contract(address='', abi=gambling_abi)
    #wp里还包含：如何转账（transaction）
    #如何从RPC provider那里获取mempool内容
    #cast命令调用合约函数
    ```
- [Positive](https://sh4dy.com/posts/crewCTF-web3-Writeups/#challenge-1--positive),题目源码（包括下面的Infinite和Deception）： https://github.com/Kaiziron/crewctf2023-writeup
    - solidity中也有整形溢出
    - cast call和cast send的区分及使用
        - `cast call` is used to perform a call on an account without publishing a transaction. Use `cast call` when you want to retrieve data from the blockchain or execute a function on a smart contract without making any changes to the blockchain state. This is useful for querying information or performing read-only operations. The `cast call` command requires the account address, the function name or signature to call, and the RPC URL of the blockchain network
        - `cast send` is used to send arbitrary messages or transactions between accounts. Use `cast send` when you want to send transactions or messages that will modify the blockchain state. This is useful for executing functions that have side effects, such as updating contract variables or transferring tokens. The `cast send` command requires the private key of the sender account, the recipient account address, and the message or transaction data
- [Infinite](https://sh4dy.com/posts/crewCTF-web3-Writeups/#challenge-2-infinite)
    - [ERC-20 token](https://ethereum.org/en/developers/docs/standards/tokens/erc-20)使用案例
        - approve(spender addr,amount)：允许addr处的contract使用amount这么多的token（所有者使用该函数后其他contract才能使用transferFrom将最多amount的token从所有者那里转走）
        - allowance(spender,this)：返回spender（token所有者）允许被转走的token数量
        - balanceOf(addr):返回addr拥有的token数量
    - 使用forge释放contract:`forge create file.sol:<contract_name> --private-key <private_key> --rpc-url <rpc_url>`
- [Deception](https://sh4dy.com/posts/crewCTF-web3-Writeups/#challenge-3-deception)
    - 利用cast code获取指定地址处的contract的bytecode
    - 使用cast storage分析指定地址处的contract的storage layout：`cast storage <contract_addr> <storage_slot_num> --rpc-url <rpc_url>`
    - 使用cast send调用含参数的函数
- [Re-Remix](https://github.com/minaminao/ctf-blockchain/tree/main/src/ProjectSekaiCTF2023)
    - solidity [Read-only reentrancy](https://medium.com/@zokyo.io/read-only-reentrancy-attacks-understanding-the-threat-to-your-smart-contracts-99444c0a7334)攻击。算reentrancy下的一个小分支，利用错误的逻辑导致程序读取一些重要的值时出错。这种攻击一般都出现在不遵守[Checks, Effects, Interactions](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-11-coding-patterns/topic/checks-effects-interactions)的代码中。Checks, Effects, Interactions指的是代码需要先检查，再更改状态，最后与用户交互。一个例子就是取钱逻辑，首先要判断用户是否有那么多的钱，然后在帐户上扣除相应的钱，最后再调用用户的诸如`payable(msg.sender).call`函数。如果反过来，检查后先与用户交互，再扣除钱，那么用户可以在call函数内再来一次取钱。因为状态未更新，凭空就多出来了双倍的钱
    - 简述一下这道题的Read-only reentrancy。在getGlobalInfo函数中，d和_totalVolumeGain的值正常情况下是一样的，`(d * 10 ** DECIMALS) / _totalVolumeGain`最终结果是`10 ** DECIMALS`，1后面跟着很多0。我们的目标是让这个结果包含更多数字（不只是1和0）。increaseVolume和decreaseVolume可以修改_totalVolumeGain，但是正常调用的话d的值也会改，效果就是_totalVolumeGain继续等于d。关键点在于decreaseVolume中有句`payable(msg.sender).sendValue(amount);`,此时其中一个值改了但另一个值没改（就是上面提到的Effects, Interactions反了）。那么就能在攻击合约的`receive()`函数中调用finish间接调用getGlobalInfo，利用d和_totalVolumeGain值不一样的时机完成攻击
    - 这题的代码似乎从 https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem 更改而来
- [Play for Free](https://mcfx.us/posts/2023-09-01-sekaictf-2023-writeup/#blockchain-play-for-free)
    - Solang contract blockchain题目。目标是读取合约的private storage并与其交互。a Solang contract saves data in another data account/search value in dispatch table
- [Eight Five Four Five](https://www.youtube.com/watch?v=1FxjP_hwqec)
    - 使用python web3与solidity blockchain进行基础交互：连接，调用函数。题目一般会给出以下值：
        - player wallet address
        - private key
        - contract address:题目合约所在的地址
        - rpc url
        - abi：也可以从题目给出的源码那里自行编译获取
        - initial gas price
    ```py
    from web3 import Web3
    web3=Web3(Web3.HTTPProvider(rpc_url))
    contract=web3.eth.contract(address=contract_address,abi=abi)
    #contract.functions为全部可调用的函数
    contract.functions.function_name().call() #调用名为function_name的函数。注意这种调用方式只能调用那些仅从blockchain读取数据的函数（例如单纯return某个值），无法调用会改变合约状态的函数（例如函数内部会给一个属性赋值）。调用这类函数参考下面：
    #有些POA chain在build之前需要middleware，否则会引发ExtraDataLengthError
    from web3.middleware import geth_poa_middleware
    web3.middleware_onion.inject(geth_poa_middleware,layer=0)
    #get nonce
    nonce=web3.eth.get_transaction_count(caller)
    #build transaction
    trx=contract.functions.function_name().build_transaction({'from':player_wallet_address,'nonce':nonce,'gasPrice':initial_gas_price})
    #用私钥签名transaction
    strx=web3.eth.account.sign_transaction(trx,private_key=private_key)
    hstrx=web3.eth.send_raw_transaction(strx.rawTransaction)
    #当status为1时表示处理成功
    res=web3.eth.wait_for_transaction_receipt(hstrx)
    ```
    - 文字版的wp： https://justinapplegate.me/2023/ductf-8545 ，连接的方法是一样的，不过多了个怎么用remix找合约的abi
    - remix解法： https://bsempir0x65.github.io/CTF_Writeups/DownUnderCTF_2023
    - cast命令解法： https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/blockchain/eightfivefourfive
- [ZKPLite](https://github.com/sahuang/my-ctf-challenges/tree/main/vsctf-2023/misc_zkplite)
    - blockchain如何计算/预测合约地址（msg.sender）： https://docs.soliditylang.org/en/latest/control-structures.html#salted-contract-creations-create2
- [Venue](https://chovid99.github.io/posts/tcp1p-ctf-2023/#venue)
    - solidity blockchain的EVM里有两种与合约交互的形式：
        - call：A read-only operation that executes a contract function locally without altering the blockchain state. It’s used to query or test functions and doesn’t require gas since it doesn’t create a transaction on the blockchain
        - transaction：A write operation that alters the blockchain state (such as updating variables, transferring ETH, or contract deployment). It requires gas and confirmation by the network, and the changes are permanently recorded on the blockchain
    - 长话短说，call用来调用那些不会改变合约自身状态的函数（只读）；transaction则与之相反。用foundry call函数时不需要private key，而transaction需要
- [Location](https://chovid99.github.io/posts/tcp1p-ctf-2023)
    - solidity blockchain EVM slot。EVM中的每个合约都有persistent storage。每个合约中的字段都会按顺序放到storage slots里，直到当前slot已满（一个slot 32字节）。有些被标记immutable的字段除外，它们不被存储在任何slot里。可以用solc命令查看详细的storage slots信息：`solc test.sol --storage-layout`。也可以用remix查看slot。在remix里编译合约后查看STORAGELAYOUT（跟ABI在一样的地方）即可
- [VIP](https://chovid99.github.io/posts/tcp1p-ctf-2023)
    - 如何安装MetaMask并获取private key。在执行合约的transaction时必须有自己的wallet和私钥
    - foundry 与合约进行交互：call/transaction。foundry使用补充： https://themj0ln1r.github.io/posts/tcp1pctf
- [Invitation](https://chovid99.github.io/posts/tcp1p-ctf-2023)
    - EVM内部有function selector，selector是一个以hex格式表示的长度为4个字节的标识符，从函数签名中得来。无法逆向selector，意味着无法在得到selector的情况下的得知该函数的签名；但是可以里用[网站](https://www.4byte.directory)的数据库查询。可以从合约的bytecode里获取selector，关注下面这段汇编：
    ```
    PUSH4 <selector>
    EQ
    PUSH <code_dest>
    JUMPI
    ```
- [GlacierCoin](https://themj0ln1r.github.io/archive/glacierctf23)
    - solidity blockchain Reentrancy attack
    - `(msg.sender).call`会调用msg.sender的fallback()函数。用receive()也行： https://github.com/Brivan-26/GlacierCTF2k23-SmartContracts-writeups
    - forge script使用
- [GlacierVault](https://themj0ln1r.github.io/archive/glacierctf23)
    - solidity blockchain [delegatecall使用](https://medium.com/@ajaotosinserah/mastering-delegatecall-in-solidity-a-comprehensive-guide-with-evm-walkthrough-6ddf027175c7)。简单来说，假设合约A使用delegatecall调用合约B的某个方法C，则执行方法C时内部所使用的storage是合约A而不是B的。也就是，本来方法C内部修改的是合约B的某些字段，假设在D处；但使用delegatecall后，实际修改的storage是合约A在D处的内存
    - 其他wp： https://github.com/Brivan-26/GlacierCTF2k23-SmartContracts-writeups
- [ChairLift](https://themj0ln1r.github.io/archive/glacierctf23)
    - solidity blockchain erecover的特殊情况。erecover的函数签名如下：`ecrecover(digest, v, r, s)`，用于恢复签名者的地址。当v，r和s都是0时，会恢复出address(0)（这种情况表示签名invalid，代码中应该有检查签名是否valid然后revert的逻辑）
    - 其他wp： https://github.com/Brivan-26/GlacierCTF2k23-SmartContracts-writeups
- [BabyBlackJack](https://github.com/n0kto/ctf-writeups/tree/main/BackdoorCTF/BabyBlackJack)
    - solidity有关`block.number`的知识：one block contains one transaction which can contain multiple call (with all the same block number)
- [SafeBridge](https://chovid99.github.io/posts/real-world-ctf-2024)
    - 两个blockchain网络之间无法通信，需要借助bridge来在两者之间传输资源。遇见的第一个环境内有多个blockchain的题目
    - foundry CLI工具使用+如何创建自己的简易token并deploy。注意自己的token若想给别的合约使用需要调用approve函数
    - 其他wp（使用solidity+forge）：
        - https://github.com/iczc/rwctf-6th-safebridge/tree/main/project/script
        - https://github.com/Kaiziron/real-world-ctf-6th-writeups
        - https://hodl.page/entry/RealWorldCTF-2023-blockchainsafebridge
- [floordrop](https://hodl.page/entry/DiceCTF-2024-Quals-floordropblockchain)
    - (完全看不懂)solidity blockchain frontrunning。唯一明白的点是提高gas price让服务器先执行我们要的函数再执行其他函数。作者还提到了一个bomb的概念，用bomb将一个block内所有的gas消耗完毕，剩下的调用会推迟到下一个block执行
- [Staker](/CTF/Codegate%20Junior/Staker.md)
    - web3 blockchain solidity题目实践

1. [First Drop](https://github.com/GCC-ENSIBS/GCC-CTF-2024/tree/main/Web3/first_drop)
- 检查一个地址是否是contract不能采用“是否有bytecode”的判断方式。因为合约在构造时（构造函数内）是没有bytecode的
- re-entrancty攻击：`_safeMint`与onERC721Received
2. [Pincer](https://github.com/GCC-ENSIBS/GCC-CTF-2024/tree/main/Web3/pincer)
- sandwich attack (front running + back running)
3. [cr3dao](https://icypetal.github.io/ctf/cr3ctf)
- 一道foundry使用例题。也是solidity里DAO概念的示例
- [官方wp](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/block/cr3dao)更详细。这题的两个漏洞为 https://docs.soliditylang.org/en/latest/security-considerations.html#clearing-mappings 和 https://blog.oxor.io/exploring-the-bugs-and-features-of-solidity-compiler-versions-a-guide-for-smart-contract-fe04e852ea64 。前者是solidity语言的特性：无法删除map。一般将map设为新的空白map看作删除操作，但如果是包含map的数组，使用delete删除数组并创建新数组后数组内部的map保存着删除前的值。后者是solidity 0.8.10之前的漏洞，从calldata或者memory拷贝bytes时，即使数据长度不足32字节也会直接拷贝32字节，导致出现dirty byte。对byte数组调用无参数的`.push()`函数时会泄露这些dirty byte
4. [cr3proxy](https://icypetal.github.io/ctf/cr3ctf/#cr3proxy)
- 合约升级（upgrade）和delegate call示例
5. [Bank](https://github.com/NoobMaster9999/My-CTF-Challenges/tree/main/ImaginaryCTF-2024/Misc/bank)
- 爆炸了，比赛期间看到uint48有个整数溢出，但是依稀记得solidity里有自动的溢出检查所以没试。结果学艺不精，查了后发现小于0.8.0版本的程序是没有的……
6. [Tree](https://marziano.top/tree.html)
- [Merkle Tree](https://dev.to/olanetsoft/merkle-proofs-a-simple-guide-3l02)的[second preimage attack](https://www.rareskills.io/post/merkle-tree-second-preimage-attack)。merkle tree整体呈二叉树状，最下面的叶子（leaf）为保存的数据，其他node为底下两个子node的hash拼接结果。比如：
```
		A
	   / \
	  B   C
	 / \ / \
	D  E F  G
```
D,E,F和G为要保存的数据的hash，比如D保存的数据是d，D里存储的就是`H(d)`。接着`H(B)=H(H(D)+H(E))`,C同理。一直这么递推上去，最后root处为`H(A)=H(H(B)+H(C))`。注意leaf存储的数据的长度不能正好是使用的hash函数输出字节的长度的两倍。否则就会出现second preimage attack。攻击者可以把B看成leaf（此时这个“leaf”代表的数据为`H(D)+H(E)`），提供C作为proof，也是一个正确的proof（merkle proof建议看上面提供的链接，有图会比较好理解）。当然，如果leaf不满足这个攻击前提，攻击者就没法把中间node B看成leaf，因为`H(D)+H(E)`的长度不满足合法leaf的数据长度

7. [Play to Earn](https://blog.blockmagnates.com/sekai-ctf-2024-deep-dive-into-the-play-to-earn-blockchain-challenge-a8156be9d44e)
- 这题的知识点之前见过：[ChairLift](https://themj0ln1r.github.io/archive/glacierctf23)，主要是erecover无法正确处理address(0)。整个bug我都找出来了，但是不知道为什么remix连不上远程rpc还是什么别的，无法调用函数……这篇wp提供了python web3模块的远程交互代码，下次用这个试试（foundry还是太难配置了，懒）
- 使用cast命令行工具的做法： https://7rocky.github.io/en/ctf/other/sekaictf/play-to-earn 。终于找到个记录如何配置的wp，下次试试
8. [zoo](https://blog.soreatu.com/posts/writeup-for-3-blockchain-challs-in-sekaictf-2024)
- 这题是个很诡异的东西。虽然是solidity，但是具体原理和pwn差不多……还是放在web3分类下吧
- 题目由solidity assembly（基于EVM的栈语言）编写，目标是改动storage中位于slot 1处的issolved变量。整个assembly只有一个opcode可以修改storage里的内容：sstore
- 如何查看文件a里b合约的storage布局：`forge inspect a.sol:b storageLayout`
- Pausable合约：当`_pause`标志为true时，执行带有whenNotPaused修饰符的函数会被revert
- [EVM memory layout](https://docs.soliditylang.org/en/latest/internals/layout_in_memory.html)和[EVM opcodes](https://www.evm.codes/)。注意区分memory和storage。memory是暂时存储空间，存那些无需跨函数调用的数据，比如局部变量，参数和返回值等；storage则是永久存储，存全局变量等。memory按0x20字节（一个slot的大小）对齐，前4 slot `0x00~0x80`被保留。重点是`0x40~0x60`:指向空闲内存。文档里说是“当前已分配内存空间”，等同于说“指向空闲内存的指针”。注意这里只有一个指针，引用时取0x40。`0x40~0x60`准确地说是这个slot的大小。这个指针很重要，汇编里经常引用
- 可用`forge inspect a.sol:b deployedBytecode`查看文件a里b合约的字节码。 https://bytegraph.xyz 可以查看汇编的控制流图表，可以在 https://www.evm.codes/playground 调试汇编
- 这题的其中一个漏洞是攻击者可以修改函数指针。题目有一个数组，数组里装着一个函数指针a，a指向被whenNotPaused修饰的函数b。假如我们可以修改函数指针，就能将a修改为修饰符逻辑下面的函数b逻辑内容，进而绕过修饰符检查，从而正常执行函数b（相当于修改got表时因为某种原因改成backdoor函数的开头不行，于是就把got修改为backdoor函数的重要部分）。注意solidity里jump的目的地必须是某个jumpdest字节码。剩下的漏洞是内存溢出（有点像堆溢出）和out of bounce read（指程序读取了预期之外的内容）
- [预期解](https://blog.solidity.kr/posts/(ctf)-2024-SekaiCTF)里提到了[foundry debugger](https://book.getfoundry.sh/forge/debugger)。感觉和radare2一样都是基于命令行的图形ui调试器
9. [SURVIVE](https://blog.soreatu.com/posts/writeup-for-3-blockchain-challs-in-sekaictf-2024)
- ERC-4337 Abstract Account system。相关学习链接：
    - https://www.alchemy.com/blog/account-abstraction
    - https://www.alchemy.com/blog/account-abstraction-paymasters
    - https://www.alchemy.com/blog/account-abstraction-wallet-creation
- 此题的漏洞在于，实现Abstract Account system的wrapper时关键正则部分写错了，导致攻击者可以将beneficiary(bundlers)填写为任意地址，进而获取多余的ETH
10. [Arctic Vault](https://writeups.hanz.dev/GCTF24MostBlockchainChallenges.pdf)
- delegatecall相关漏洞。去年在GlacierVault见过这个知识点。这题做个补充。delegatecall保留`msg.sender`和`msg.value`的值。所以类似这样的结构是危险的：
```solidity
for(uint256 i = 0; i < _data.length; i++)
{
    (bool success, ) = address(this).delegatecall(_data[i]); //设想这里如果调用deposit会发生什么
}
```
我对这里的`msg.value`的理解是“调用者调用某个函数时附带的eth数“。假如攻击者正常调用两次deposit，就需要付两次eth。但利用上面的for循环+delegatecall，可调用任意次deposit，且只用付一次eth。withdraw的时候就能凭空提取不属于自己的eth

11. [Mafia2](https://github.com/DK27ss/PWNME-CTF-Mafia2-WriteUp)
- solidity里的private字段值可以通过`cast storage`获得……并非private
12. [Golden-Bridge](https://eddwastaken.github.io/posts/dicectf-2025-quals-golden-bridge)
- 再一次遇到这类用bridge合约串联Ethereum和Solana的资源的题。不过这次感觉对brdige的概念有了更好的认识。因为Ethereum和Solana之间无法通信，故在将a token转成b token（反之亦然）时双方都无法得知对面是否真的有请求数量这么多的token。所以需要在两个之间插入一个双方都信任的中介同时记录双边token的数量
- 漏洞在于将sol token转成eth token时，没有确认solana方已完成转账就交付eth token了（solana转账速度较慢）。所以可以获取比实际数量多得多的eth token（某种意义上很像限时的重入攻击？）
13. [House of Illusions](http://blog.kudaliar.id/blog/0xl4ugh-ctf-v5-house-of-illusions)
- 自solidity `0.8.0`后，脚本默认使用v2 abi encoder，使用v1需要在脚本顶部加上`pragma abicoder v1;`
- v2对calldata的编码检查更加严格，会拒绝诸如脏地址（地址的高12字节不为0）这类不规范的编码；而v1不会
- 题目源码： https://github.com/pi-1337/Blockchain-CTF-Writeups/tree/master/script/0xL4ugh_CTF_2026/House_of_Illusions