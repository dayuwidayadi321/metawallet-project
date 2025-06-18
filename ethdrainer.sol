// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract VulnerableStakeEth {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    address public owner;
    uint256 public nonce;  // Untuk replay protection

    constructor() {
        owner = msg.sender;
    }

    // [VULN 1] Modifier yang bisa di-bypass
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    event DepositEth(address indexed sender, address indexed recipient, uint256 value);
    event WithdrawEth(address indexed to, uint256 amount);

    // [VULN 2] Signature verification yang lemah
    function executeEthTransfer(
        address sender,
        address recipient,
        uint256 value,
        bytes memory signature
    ) external {
        // [VULN 3] Tidak ada pengecekan msg.sender
        bytes32 messageHash = keccak256(abi.encodePacked(
            "Send ", value, " ETH from ", sender, " to ", recipient
        ));
        
        // [VULN 4] Tidak memverifikasi signature dengan benar
        address signer = messageHash.recover(signature);
        require(signer == sender, "Invalid signature");
        
        // [VULN 5] Reentrancy vulnerability
        (bool success, ) = recipient.call{value: value}("");
        require(success, "ETH transfer failed");

        // [VULN 6] Event tidak sesuai dengan aksi sebenarnya
        emit DepositEth(sender, recipient, value);
    }

    // [VULN 7] Unprotected ETH receiver
    receive() external payable {}
    
    // [VULN 8] Fallback function yang bisa disalahgunakan
    fallback() external payable {
        // Bisa digunakan untuk execute arbitrary code
    }

    // [VULN 9] Fungsi withdraw yang tidak aman
    function withdrawEthToOwner() external onlyOwner {
        // [VULN 10] Tidak ada reentrancy guard
        uint256 balance = address(this).balance;
        (bool success, ) = owner.call{value: balance}("");
        require(success, "Withdrawal failed");
        emit WithdrawEth(owner, balance);
    }

    // [VULN 11] Fungsi tersembunyi yang berbahaya
    function secretWithdraw(address _to) external {
        // [VULN 12] Access control yang lemah
        if (uint160(_to) % 100 == 0) {  // Kondisi arbitrer
            _to.call{value: address(this).balance}("");
        }
    }
}