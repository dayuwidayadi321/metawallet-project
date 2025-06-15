// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Nuclear {
    function detonate(address target) public payable {
        selfdestruct(payable(target));
    }
}

contract NuclearForwarder {
    address public immutable owner;
    Nuclear public nuclear;
    
    event FundsDetonated(address indexed sender, uint256 amount, address target);

    constructor() {
        owner = msg.sender;
        nuclear = new Nuclear();
    }

    function autoDestruct(address target, bytes memory signature) external payable {
        require(_verifySignature(target, msg.value, signature), "Invalid signature");
        

        nuclear.detonate{value: msg.value}(target);
        
        emit FundsDetonated(msg.sender, msg.value, target);
    }

    function _verifySignature(address target, uint256 amount, bytes memory signature) 
        internal view returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender,
            target,
            amount,
            address(this)
        );
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", 
            messageHash
        ));
        return ecrecover(ethSignedHash, signature) == owner;
    }

    receive() external payable {}
}