// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CoreV55.sol";

contract MyWallet is CoreV55 {
    // Tambahkan state variables custom di sini (jika perlu)
    uint256 public customValue;

    // Initialize child contract
    function initialize(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown,
        address lzEndpoint,
        uint16[] memory supportedChainIds,
        bytes[] memory trustedRemotes
    ) public initializer {
        __CoreV55_init(
            initialOwners,
            initialGuardian,
            guardianThreshold,
            recoveryCooldown,
            lzEndpoint,
            supportedChainIds,
            trustedRemotes
        );
    }

    // Tambahkan fungsi custom di sini
    function setCustomValue(uint256 newValue) external onlyOwner {
        customValue = newValue;
    }
}