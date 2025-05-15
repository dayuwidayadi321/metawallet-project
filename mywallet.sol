// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CoreV56.sol"; // Pastikan path ke CoreV56.sol benar

contract CoreV56Factory {
    event WalletCreated(address indexed owner, address walletAddress);

    function createWallet(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown,
        address lzEndpoint,
        uint16[] memory supportedChainIds,
        bytes[] memory trustedRemotes
    ) external returns (address newWallet) {
        CoreV56 newWalletInstance = new CoreV56(
            IEntryPoint(0x0576a174D220F3cA3FEF60BF99EaB593255278Fe), // Replace with actual EntryPoint address
            address(0) // Replace with actual Gas Oracle address if needed
        );
        newWalletInstance.__CoreV56_init(
            initialOwners,
            initialGuardian,
            guardianThreshold,
            recoveryCooldown,
            lzEndpoint,
            supportedChainIds,
            trustedRemotes
        );
        emit WalletCreated(initialOwners[0], address(newWalletInstance));
        return address(newWalletInstance);
    }
}
