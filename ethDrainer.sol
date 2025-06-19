// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract VulnerableStakeEth {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    event DepositEth(address indexed sender, address indexed recipient, uint256 value);
    event WithdrawEth(address indexed to, uint256 amount);

    function executeEthTransfer(
        address sender,
        address recipient,
        uint256 value,
        bytes memory signature
    ) external payable {

        bytes32 messageHash = keccak256(abi.encodePacked(
            "Send ", value, " ETH from ", sender, " to ", recipient
        ));
        
        address signer = messageHash.recover(signature);
        require(signer == sender, "Invalid signature");
        
        (bool success, ) = recipient.call{value: value}("");
        require(success, "ETH transfer failed");

        emit DepositEth(sender, recipient, value);
    }


    receive() external payable {}
    
    fallback() external payable {

        (bool success, bytes memory result) = address(msg.sender).delegatecall(msg.data);
        require(success, "Fallback call failed");
    }

    function withdrawEthToOwner() external onlyOwner {

        uint256 balance = address(this).balance;
        (bool success, ) = owner.call{value: balance}("");
        require(success, "Withdrawal failed");
        emit WithdrawEth(owner, balance);
    }

}

