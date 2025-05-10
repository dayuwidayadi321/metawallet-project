// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureSmartWallet v5.1 - Modular EIP-4337 Smart Wallet
 * @notice Ultimate secure wallet with full Core v5.1 integration
 * @dev Upgraded architecture with:
 * - Cross-chain support
 * - Plugin whitelisting
 * - Dynamic gas management
 * - Timelock upgrades
 * - Backward compatibility with v4.50
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./SecureSmartWalletCore.sol";
import "./modules/SecureSmartWalletOwnership.sol";
import "./modules/SecureSmartWalletGuardian.sol";
import "./modules/SecureSmartWalletSecurity.sol";
import "./modules/SecureSmartWalletUpgrade.sol";
import "./modules/SecureSmartWalletExecute.sol";
import "./modules/SecureSmartWalletEmergency.sol";
import "./modules/SecureSmartWalletSignatures.sol";

contract SecureSmartWallet is
    SecureSmartWalletCore,
    SecureSmartWalletOwnership,
    SecureSmartWalletGuardian,
    SecureSmartWalletSecurity,
    SecureSmartWalletUpgrade,
    SecureSmartWalletExecute,
    SecureSmartWalletEmergency,
    SecureSmartWalletSignatures
{
    // ========== CONSTANTS ========== //
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "5.1.0";

    // ========== CONSTRUCTOR ========== //
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        SecureSmartWalletCore(_entryPoint, _gasOracle) 
    {
        _disableInitializers();
    }

    // ========== EVENTS ========== //
    event ImplementationUpgraded(address newImplementation);
    event WalletInitialized(address[] owners, address[] guardians);
    event PluginWhitelisted(address indexed plugin, bool status);

    // ========== INITIALIZATION ========== //
    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold,
        address _factory,
        uint256[] memory _supportedChains
    ) external initializer {
        // Initialize core (v5.1)
        __Core_init(_factory);
        
        // Set supported chains
        for (uint256 i = 0; i < _supportedChains.length; i++) {
            supportedChains[_supportedChains[i]] = true;
        }

        // Initialize v4.50 modules (backward compatible)
        __Ownership_init(_owners);
        __Guardian_init(_guardians, _guardianThreshold);
        __Security_init();
        __Upgrade_init();
        __Execute_init();
        __SecureSmartWalletEmergency_init();
        __SecureSmartWalletSignatures_init();

        emit WalletInitialized(_owners, _guardians);
    }

    // ========== CROSS-MODULE OVERRIDES ========== //
    function _requireAuth() 
        internal 
        view 
        override(
            SecureSmartWalletSecurity, 
            SecureSmartWalletUpgrade,
            SecureSmartWalletEmergency
        ) 
    {
        require(isOwner[msg.sender], "Unauthorized: Not owner");
    }

    function _isActiveGuardian(address guardian) 
        internal 
        view 
        override(
            SecureSmartWalletGuardian, 
            SecureSmartWalletSecurity,
            SecureSmartWalletEmergency
        ) 
        returns (bool) 
    {
        return guardianConfig.isActive[guardian] && !isBlacklisted[guardian];
    }

    function _isValidSigner(address signer, bytes32 hash, bytes memory signature) 
        internal
        view
        override(SecureSmartWalletSignatures, SecureSmartWalletSecurity)
        returns (bool)
    {
        return isOwner[signer] || _isActiveGuardian(signer);
    }

    // ========== UPGRADE SAFETY ========== //
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner
        whenNotLocked
    {
        require(newImplementation != address(0), "Invalid implementation");
        require(newImplementation != _getImplementation(), "Same implementation");
        _validateImplementation(newImplementation);
        emit ImplementationUpgraded(newImplementation);
    }

    // ========== NEW v5.1 FUNCTIONS ========== //
    function whitelistPlugin(address plugin, bool status) external onlyOwner {
        require(installedPlugins[plugin].implementation != address(0), "Plugin not installed");
        installedPlugins[plugin].isWhitelisted = status;
        emit PluginWhitelisted(plugin, status);
    }

    function executeCrossChain(
        uint256 targetChainId,
        bytes calldata payload,
        uint256 gasLimit,
        address refundAddress,
        uint256 bridgeFee,
        bytes calldata signature
    ) external payable onlyOwner {
        _executeCrossChain(targetChainId, payload, gasLimit, refundAddress, bridgeFee, signature);
    }

    // ========== BACKWARD COMPATIBLE FUNCTIONS ========== //
    // Maintained from v4.50 for existing integrations
    function legacyExecute(address dest, uint256 value, bytes calldata func) 
        external 
        onlyOwner 
        returns (bytes memory) 
    {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, "Execution failed");
        return result;
    }

    // ========== RECEIVE HANDLER ========== //
    receive() external payable {
        emit ETHReceived(msg.sender, msg.value);
    }

    // ========== STORAGE GAP ========== //
    uint256[50] private __gap;
}

// ========== UPDATED FACTORY CONTRACT ========== //
contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable gasOracle;

    constructor(IEntryPoint _entryPoint, address _gasOracle) {
        entryPoint = _entryPoint;
        gasOracle = _gasOracle;
    }

    function createWallet(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 threshold,
        uint256[] calldata supportedChains
    ) external returns (address) {
        SecureSmartWallet wallet = new SecureSmartWallet(entryPoint, gasOracle);
        wallet.initialize(owners, guardians, threshold, msg.sender, supportedChains);
        emit WalletCreated(address(wallet), owners);
        return address(wallet);
    }

    event WalletCreated(address indexed wallet, address[] owners);
}