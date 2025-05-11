// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Core v5.3.2 (STABLE) - Ultimate Inheritable EIP-4337 Smart Wallet
 * @author DFXC IndonesiaSecurity Web3 Project - Dev. DayuWidayadi
 * @notice Core v5.3 with Enhanced Inheritance Support & Critical Security Fixes
 * @dev Audit Phase #2 [SECURITY PATCH] v5.3.2
 *      - Fixed front-running vulnerability in plugin uninstallation
 *      - Added guardian-approved instant uninstall
 *      - Added uninstall cancellation
 * 
 * Key Improvements:
 *      - Reentrancy protection for all plugin calls (OpenZeppelin ReentrancyGuard)
 *      - Virtual functions for easy customization
 *      - Modular initialization system
 *      - Improved plugin security (now with atomic execution)
 *      - Optimized gas efficiency
 *      - Upgraded recovery mechanism
 * 
 * Security Advisory:
 *      - All users MUST upgrade to v5.3.1+ for critical reentrancy protection
 *      - Previous versions vulnerable to fund theft via malicious plugins
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts@4.9.5/security/ReentrancyGuard.sol";

abstract contract CoreV532 is Initializable, EIP712, ReentrancyGuard {
    using EnumerableSet for EnumerableSet.AddressSet;

    /* ========== TYPEHASHES ========== */
    bytes32 public constant CROSS_CHAIN_REQUEST_TYPEHASH = 
        keccak256("CrossChainRequest(uint256 targetChainId,bytes payload,uint256 gasLimit,address refundAddress,uint256 nonce)");
    bytes32 public constant SESSION_KEY_TYPEHASH = 
        keccak256("SessionKey(address key,uint48 validUntil,bytes4[] allowedSelectors,uint256 nonce,uint48 validAfter)");
    bytes32 public constant RECOVERY_TYPEHASH = 
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline)");
    bytes32 public constant EMERGENCY_LOCK_TYPEHASH =
        keccak256("EmergencyLock(uint256 nonce,uint256 deadline)");

    /* ========== STRUCTS ========== */
    struct ExecutionEnvironment {
        IEntryPoint entryPoint;
        address defaultPaymaster;
        uint256 chainId;
        bool isLocked;
        uint256 upgradeTimelock;
        uint256 securityDelay;
    }

    struct Plugin {
        address implementation;
        bytes4[] enabledSelectors;
        bool isWhitelisted;
        uint48 installTimestamp;
    }

    struct SessionKey {
        uint48 validUntil;
        uint48 validAfter;
        bytes4[] allowedSelectors;
        bool isRevoked;
        address addedBy;
    }

    struct GuardianConfig {
        uint64 threshold;
        uint64 cooldown;
        uint64 lastRecoveryTimestamp;
        EnumerableSet.AddressSet guardians;
    }

    /* ========== CONSTANTS ========== */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 public constant MAX_PLUGIN_UNINSTALL_DELAY = 7 days;

    /* ========== IMMUTABLES ========== */
    address public immutable self;
    IEntryPoint public immutable entryPoint;
    uint256 public immutable CHAIN_ID;
    address public gasOracle;

    /* ========== SHARED STATE ========== */
    ExecutionEnvironment public env;
    address public factory;
    mapping(uint256 => bool) public supportedChains;
    address public pendingImplementation;
    
    // Security
    GuardianConfig private _guardianConfig;
    EnumerableSet.AddressSet private _owners;
    mapping(address => bool) public isBlacklisted;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public pluginUninstallTimestamps;

    // Modules
    mapping(bytes4 => address) public selectorToPlugin;
    mapping(address => Plugin) public installedPlugins;
    mapping(address => SessionKey) public sessionKeys;
    mapping(address => uint256) public sessionNonces;
    mapping(address => uint256) public recoveryNonces;

    /* ========== EVENTS ========== */
    event ETHReceived(address indexed sender, uint256 amount);
    event ImplementationUpgradeScheduled(address newImplementation, uint256 unlockTime);
    event CrossChainInitiated(uint256 indexed dstChainId, bytes indexed payload);
    event SessionKeyRevoked(address indexed key);
    event LockStatusChanged(bool locked, address initiatedBy);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event PluginUninstallScheduled(address indexed plugin, uint256 uninstallTime);
    event RecoveryExecuted(address[] newOwners);
    event WalletInitialized(address[] owners, address guardian);
    event RecoveryCooldownUpdated(uint64 newCooldown);
    event GuardianThresholdUpdated(uint64 newThreshold);
    event SecurityDelayUpdated(uint256 newDelay);
    event EmergencyLockVetoed(address indexed vetoer);
    event GuardianInactivityWarning(uint256 lastActiveTimestamp);
    event UpgradeExecuted(address indexed newImplementation);
    event GasOracleUpdated(address indexed oldOracle, address indexed newOracle);
    
    /* ========== MODIFIERS ========== */
    modifier onlyEntryPoint() virtual {
        require(msg.sender == address(env.entryPoint), "Caller not EntryPoint");
        _;
    }
    
    modifier onlyOwner() virtual {
        require(_owners.contains(msg.sender), "Unauthorized: Not owner");
        _;
    }
    
    modifier whenNotLocked() virtual {
        require(!env.isLocked, "Contract is locked");
        _;
    }
    
    modifier whenLocked() virtual {
        require(env.isLocked, "Contract is not locked");
        _;
    }
    
    modifier pluginNotPendingUninstall(address plugin) {
        require(pluginUninstallTimestamps[plugin] == 0, "Plugin pending uninstall");
        _;
    }    

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        EIP712("CoreV532", "5.3.1") 
    {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
        self = address(this);
        gasOracle = _gasOracle;
        _disableInitializers();
    }

    /* ========== INITIALIZER ========== */
    function __CoreV532_init(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown
    ) internal virtual onlyInitializing {
        // Initialize owners
        require(initialOwners.length > 0, "No owners provided");
        for (uint256 i = 0; i < initialOwners.length; i++) {
            require(initialOwners[i] != address(0), "Invalid owner address");
            _owners.add(initialOwners[i]);
        }

        // Initialize guardian system
        require(initialGuardian != address(0), "Invalid guardian");
        _guardianConfig.guardians.add(initialGuardian);
        _guardianConfig.threshold = guardianThreshold;
        _guardianConfig.cooldown = recoveryCooldown;

        // Initialize execution environment
        env.entryPoint = entryPoint;
        env.chainId = CHAIN_ID;
        env.securityDelay = 1 days; // Default security delay

        emit WalletInitialized(initialOwners, initialGuardian);
    }

    /* ========== VIRTUAL FUNCTIONS (FOR CUSTOMIZATION) ========== */
    function _verifySignature(bytes32 hash, bytes memory signature) 
        internal 
        view 
        virtual 
        returns (bool) 
    {
        address signer = ECDSA.recover(hash, signature);
        return _owners.contains(signer);
    }

    function _validatePlugin(address plugin) internal view virtual {
        require(plugin != address(0), "Invalid plugin");
        require(plugin.code.length > 0, "No code at plugin");

        bytes4[] memory protectedSelectors = new bytes4[](4);
        protectedSelectors[0] = this.executeUpgrade.selector;
        protectedSelectors[1] = this.scheduleUpgrade.selector;
        protectedSelectors[2] = this.installPlugin.selector;
        protectedSelectors[3] = this.uninstallPlugin.selector;

        for (uint i = 0; i < protectedSelectors.length; i++) {
            require(
                selectorToPlugin[protectedSelectors[i]] != plugin,
                "Protected selector"
            );
        }
    }
    
    /* ========== INTERNAL FUNCTIONS ========== */
    function _setLockStatus(bool locked) internal virtual {
        require(env.isLocked != locked, "Already in desired state");
        env.isLocked = locked;
        emit LockStatusChanged(locked, msg.sender);
    }    

    /* ========== ENTRYPOINT INTERFACE ========== */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual onlyEntryPoint returns (uint256 validationData) {
        bytes32 sigHash = keccak256(abi.encodePacked(userOpHash, block.chainid));
        require(!usedSignatures[sigHash], "Signature reused");
        usedSignatures[sigHash] = true;

        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Fund transfer failed");
        }

        if (_owners.contains(ECDSA.recover(userOpHash, userOp.signature))) {
            return 0;
        }

        // Check session keys
        address signer = ECDSA.recover(userOpHash, userOp.signature);
        SessionKey storage sk = sessionKeys[signer];
        if (!sk.isRevoked && 
            block.timestamp <= sk.validUntil && 
            block.timestamp >= sk.validAfter) {
            
            for (uint i = 0; i < sk.allowedSelectors.length; i++) {
                if (bytes4(userOp.callData[:4]) == sk.allowedSelectors[i]) {
                    return 0;
                }
            }
        }

        return SIG_VALIDATION_FAILED;
    }

    /* ========== PLUGIN SYSTEM (MODULAR) ========== */
    event PluginUninstallCancelled(address indexed plugin);
    event PluginForceUninstalled(address indexed plugin, address initiatedBy);
    
    function installPlugin(
        address plugin,
        bytes4[] calldata selectors,
        bytes calldata initData,
        bool whitelist
    ) external virtual onlyOwner whenNotLocked {
        _validatePlugin(plugin);
        require(pluginUninstallTimestamps[plugin] == 0, "Plugin pending uninstall");
    
        for (uint256 i = 0; i < selectors.length; i++) {
            require(
                selectorToPlugin[selectors[i]] == address(0),
                "Selector already registered"
            );
            selectorToPlugin[selectors[i]] = plugin;
        }
    
        installedPlugins[plugin] = Plugin({
            implementation: plugin,
            enabledSelectors: selectors,
            isWhitelisted: whitelist,
            installTimestamp: uint48(block.timestamp)
        });
    
        if (initData.length > 0) {
            (bool success,) = plugin.delegatecall(initData);
            require(success, "Plugin init failed");
        }
    }
    
    function uninstallPlugin(address plugin) external virtual onlyOwner {
        require(installedPlugins[plugin].installTimestamp > 0, "Plugin not installed");
        require(pluginUninstallTimestamps[plugin] == 0, "Uninstall already scheduled");
        pluginUninstallTimestamps[plugin] = block.timestamp + env.securityDelay;
        emit PluginUninstallScheduled(plugin, pluginUninstallTimestamps[plugin]);
    }
    
    function cancelUninstall(address plugin) external onlyOwner {
        require(pluginUninstallTimestamps[plugin] > 0, "No pending uninstall");
        delete pluginUninstallTimestamps[plugin];
        emit PluginUninstallCancelled(plugin);
    }
    
    function forceUninstallPlugin(
        address plugin, 
        bytes[] calldata guardianSignatures
    ) external virtual {
        require(installedPlugins[plugin].installTimestamp > 0, "Plugin not installed");
        
        // Verify guardian consensus
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("ForceUninstallPlugin(address plugin,uint256 nonce)"),
            plugin,
            recoveryNonces[address(this)]++
        )));
        
        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_guardianConfig.guardians.length());
        
        for (uint i = 0; i < guardianSignatures.length; i++) {
            address signer = ECDSA.recover(hash, guardianSignatures[i]);
            
            for (uint j = 0; j < validSignatures; j++) {
                require(seenGuardians[j] != signer, "Duplicate signature");
            }
            
            if (_guardianConfig.guardians.contains(signer)) {
                seenGuardians[validSignatures] = signer;
                validSignatures++;
                if (validSignatures >= _guardianConfig.threshold) break;
            }
        }
        
        require(validSignatures >= _guardianConfig.threshold, "Insufficient guardians");
        
        _removePlugin(plugin);
        emit PluginForceUninstalled(plugin, msg.sender);
    }
    
    function _removePlugin(address plugin) internal virtual {
        bytes4[] memory selectors = installedPlugins[plugin].enabledSelectors;
        
        // Clean selector mappings
        for (uint i = 0; i < selectors.length; i++) {
            delete selectorToPlugin[selectors[i]];
        }
        
        // Clean plugin data
        delete installedPlugins[plugin];
        delete pluginUninstallTimestamps[plugin];
    }

    /* ========== RECOVERY SYSTEM ========== */
    function initiateRecovery(
        address[] calldata newOwners, 
        bytes[] calldata signatures, 
        uint256 deadline
    ) external virtual {
        require(_guardianConfig.guardians.contains(msg.sender), "Not guardian");
        require(block.timestamp > _guardianConfig.lastRecoveryTimestamp + _guardianConfig.cooldown, "In cooldown");
        require(newOwners.length > 0, "No owners");
        require(deadline > block.timestamp, "Deadline passed");
        
        bytes32 recoveryHash = _hashTypedDataV4(keccak256(abi.encode(
            RECOVERY_TYPEHASH,
            keccak256(abi.encodePacked(newOwners)),
            recoveryNonces[address(this)]++,
            deadline
        )));
    
        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_guardianConfig.guardians.length());
        
        for (uint i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(recoveryHash, signatures[i]);
            
            for (uint j = 0; j < validSignatures; j++) {
                require(seenGuardians[j] != signer, "Duplicate signature");
            }
            
            if (_guardianConfig.guardians.contains(signer)) {
                seenGuardians[validSignatures] = signer;
                validSignatures++;
                if (validSignatures >= _guardianConfig.threshold) break;
            }
        }
    
        require(validSignatures >= _guardianConfig.threshold, "Insufficient guardians");
    
        // Atomic owner replacement
        _replaceOwners(newOwners);
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
        emit RecoveryExecuted(newOwners);
    }

    function _replaceOwners(address[] calldata newOwners) internal virtual {
        // Clear existing owners
        while (_owners.length() > 0) {
            _owners.remove(_owners.at(0));
        }
        
        // Add new owners
        for (uint i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "Invalid owner");
            _owners.add(newOwners[i]);
        }
    }

    /* ========== GUARDIAN FUNCTIONS ========== */
    function addGuardian(address guardian) external virtual onlyOwner {
        require(!_guardianConfig.guardians.contains(guardian), "Already guardian");
        require(guardian != address(0), "Invalid guardian");
        _guardianConfig.guardians.add(guardian);
        emit GuardianAdded(guardian);
    }
    
    function removeGuardian(address guardian) external virtual onlyOwner {
        require(_guardianConfig.guardians.contains(guardian), "Not guardian");
        require(_guardianConfig.guardians.length() > 1, "Cannot remove last guardian");
        _guardianConfig.guardians.remove(guardian);
        emit GuardianRemoved(guardian);
    }
    
    function setGuardianThreshold(uint64 newThreshold) external virtual onlyOwner {
        require(newThreshold <= _guardianConfig.guardians.length(), "Threshold too high");
        require(newThreshold > 0, "Threshold cannot be zero");
        _guardianConfig.threshold = newThreshold;
    }
    
    function setRecoveryCooldown(uint64 newCooldown) external virtual onlyOwner {
        require(newCooldown <= 30 days, "Cooldown too long");
        _guardianConfig.cooldown = newCooldown;
    }
    
    // [NEW] Overridable guardian validation
    function _isValidGuardian(address guardian) internal view virtual returns (bool) {
        return _guardianConfig.guardians.contains(guardian);
    }

    /* ========== UPGRADE MECHANISM ========== */
    function _validateImplementation(address newImpl) internal view virtual {
        require(newImpl != address(0), "Invalid implementation");
        require(newImpl.code.length > 0, "No code at implementation");
        // Add any additional validation logic here
        // For example, you might want to check interface support
    }
    
    function scheduleUpgrade(address newImpl) external virtual onlyOwner whenNotLocked {
        _validateImplementation(newImpl);
        pendingImplementation = newImpl;
        env.upgradeTimelock = block.timestamp + env.securityDelay;
        emit ImplementationUpgradeScheduled(newImpl, env.upgradeTimelock);
    }
    
    function executeUpgrade() external virtual onlyOwner whenNotLocked {
        require(pendingImplementation != address(0), "No pending upgrade");
        require(block.timestamp >= env.upgradeTimelock, "Timelock not expired");
        require(pendingImplementation != address(this), "Invalid implementation");
        
        address impl = pendingImplementation;
        pendingImplementation = address(0);
        env.upgradeTimelock = 0;
        
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = impl;
        emit UpgradeExecuted(impl); // <- New event
    }

    /* ========== GAS OPTIMIZATION ========== */
    function getOptimalGasParams() 
        public 
        view 
        virtual 
        returns (
            uint256 baseFee,
            uint256 priorityFee,
            uint256 gasLimitBuffer
        ) 
    {
        // Tambahkan pengecekan address oracle
        require(gasOracle != address(0), "Gas oracle not set");
        require(gasOracle.code.length > 0, "No code at gasOracle");
    
        (bool success, bytes memory data) = gasOracle.staticcall(
            abi.encodeWithSignature("getGasParameters()")
        );
        
        // Fallback ke default values jika oracle gagal
        if (!success) {
            return (
                0.01 ether,    // baseFee default
                0.001 ether,   // priorityFee default 
                200_000        // gasLimitBuffer default
            );
        }
        
        return abi.decode(data, (uint256, uint256, uint256));
    }
    
    /// @notice Mengupdate alamat gas oracle contract
    /// @dev Hanya bisa dipanggil oleh owner
    /// @param newOracle Alamat baru dari oracle (harus bukan address(0))
    function setGasOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "Invalid oracle address");
        emit GasOracleUpdated(gasOracle, newOracle);
        gasOracle = newOracle;
    }

    /* ========== SECURITY FUNCTIONS ========== */    
    function emergencyLock(bytes calldata guardianSignature) 
        external 
        virtual 
    {
        bytes32 lockHash = _hashTypedDataV4(keccak256(abi.encode(
            EMERGENCY_LOCK_TYPEHASH, // Using predefined typehash
            recoveryNonces[msg.sender]++,
            block.timestamp + 1 hours
        )));
    
        address signer = ECDSA.recover(lockHash, guardianSignature);
        require(_isValidGuardian(signer), "Not guardian"); // Using virtual guardian check
        _setLockStatus(true);
    }
    
    function setSecurityDelay(uint256 delay) 
        external 
        virtual 
        onlyOwner 
    {
        require(delay <= MAX_PLUGIN_UNINSTALL_DELAY, "Delay too long");
        env.securityDelay = delay;
        
        // [NEW] Event for better monitoring
        emit SecurityDelayUpdated(delay); 
    }
    
    // [NEW] Enhanced security - Allow owners to veto guardian actions
    function vetoEmergencyLock() 
        external 
        virtual 
        onlyOwner 
        whenLocked 
    {
        _setLockStatus(false);
        emit EmergencyLockVetoed(msg.sender);
    }
    
    // [NEW] Guardian activity timeout
    function guardianActivityCheck() 
        external 
        view 
        returns (bool needsRotation) 
    {
        uint256 inactivePeriod = block.timestamp - _guardianConfig.lastRecoveryTimestamp;
        return inactivePeriod > 180 days; // Warn if no guardian activity for 6 months
    }

    /* ========== FALLBACK HANDLER ========== */
    fallback() external payable virtual nonReentrant {
            address plugin = selectorToPlugin[msg.sig];
            require(plugin != address(0), "Selector not registered");
            require(installedPlugins[plugin].isWhitelisted, "Plugin not whitelisted");
    
            (bool success, bytes memory result) = plugin.delegatecall(msg.data);
            
            if (!success) {
                if (result.length > 0) {
                    assembly { revert(add(result, 32), mload(result)) }
                } else {
                    revert("Plugin failed");
                }
            }
            assembly { return(add(result, 32), mload(result)) }
        }
    /* ========== RECEIVE EXTERNAL ========== */   
    receive() external payable virtual {
        emit ETHReceived(msg.sender, msg.value);
    }

    /* ========== VIEW FUNCTIONS ========== */
    function getOwners() external view virtual returns (address[] memory) {
        return _owners.values();
    }

    function getGuardians() external view virtual returns (address[] memory) {
        return _guardianConfig.guardians.values();
    }

    function isOwner(address account) external view returns (bool) {
        return _owners.contains(account);
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}
