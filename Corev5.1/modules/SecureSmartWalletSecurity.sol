// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./SecureSmartWalletCore.sol";

/**
 * @title SecureSmartWalletSecurity v5.1
 * @dev Enhanced security module with:
 * - Cross-chain threat detection
 * - Plugin-aware security policies
 * - Real-time monitoring hooks
 */
abstract contract SecureSmartWalletSecurity is SecureSmartWalletCore {
    /* ========== STATE VARIABLES ========== */
    mapping(bytes4 => bool) public suspiciousSelectors;
    uint64 public lastSecurityUpdate;
    mapping(address => uint256) public lastActivity; // Track per-address activity

    /* ========== EVENTS ========== */
    event WalletLocked(string indexed reason, address indexed initiator);
    event WalletUnlocked(address indexed initiator);
    event SuspiciousActivityDetected(
        address indexed target, 
        bytes4 selector,
        bytes32 indexed threatId
    );
    event SecurityPolicyUpdated(bytes4 indexed selector, bool status);

    /* ========== ERRORS ========== */
    error WalletIsLocked();
    error SuspiciousOperation(bytes4 selector);
    error HighRiskTarget(address target);

    /* ========== MODIFIERS ========== */
    modifier whenNotLocked() {
        if (env.isLocked) revert WalletIsLocked();
        _;
    }

    /* ========== INITIALIZER ========== */
    function __Security_init() internal onlyInitializing {
        // Initialize default threats
        suspiciousSelectors[0x00000000] = true; // empty selector
        suspiciousSelectors[0x45454545] = true; // known attack pattern
        lastSecurityUpdate = uint64(block.timestamp);
    }

    /* ========== EXTERNAL FUNCTIONS ========== */
    function lockWallet(string calldata reason) external onlyOwner {
        env.isLocked = true;
        _updateSecurity();
        emit WalletLocked(reason, msg.sender);
    }

    function updateSecurityPolicy(
        bytes4[] calldata selectors, 
        bool[] calldata statuses
    ) external onlyOwner {
        for (uint256 i = 0; i < selectors.length; i++) {
            suspiciousSelectors[selectors[i]] = statuses[i];
            emit SecurityPolicyUpdated(selectors[i], statuses[i]);
        }
    }

    /* ========== ENHANCED SECURITY CHECKS ========== */
    function _validateOperation(
        address target,
        bytes4 selector
    ) internal view {
        // Global lock check
        if (env.isLocked) revert WalletIsLocked();
        
        // Threat detection
        if (suspiciousSelectors[selector]) {
            revert SuspiciousOperation(selector);
        }

        // Plugin-specific checks
        address plugin = selectorToPlugin[selector];
        if (plugin != address(0) && isBlacklisted[plugin]) {
            revert HighRiskTarget(plugin);
        }
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}