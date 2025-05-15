// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./CoreV55.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract CoreV55Factory {
    event WalletCreated(address indexed wallet, address[] owners, address guardian, address indexed creator);

    address public immutable ENTRY_POINT;
    address public immutable GAS_ORACLE;
    address public immutable LZ_ENDPOINT;
    
    constructor(
        IEntryPoint _entryPoint,
        address _gasOracle,
        address _lzEndpoint
    ) {
        ENTRY_POINT = address(_entryPoint);
        GAS_ORACLE = _gasOracle;
        LZ_ENDPOINT = _lzEndpoint;
    }

    function createWallet(
        address[] memory initialOwners,
        address initialGuardian
    ) public returns (address wallet) {
        require(initialOwners.length > 0, "No owners provided");
        require(initialGuardian != address(0), "Invalid guardian");

        // 1. Deploy CoreV55 secara langsung
        wallet = address(new CoreV55(
            IEntryPoint(ENTRY_POINT),
            GAS_ORACLE
        ));

        // 2. Initialize wallet
        CoreV55(payable(wallet)).__CoreV55_init(
            initialOwners,
            initialGuardian,
            1, // DEFAULT_GUARDIAN_THRESHOLD
            3 days, // DEFAULT_RECOVERY_COOLDOWN
            LZ_ENDPOINT,
            new uint16[](0), // Kosongkan dulu, bisa di-set kemudian
            new bytes[](0)   // Kosongkan dulu, bisa di-set kemudian
        );

        emit WalletCreated(wallet, initialOwners, initialGuardian, msg.sender);
    }
}