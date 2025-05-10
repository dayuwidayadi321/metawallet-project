// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureSmartWalletCore v5.2(Enterprise) - Enhanced EIP-4337 Infrastructure
 * @author DFXC IndonesiaSecurity Web3 Project - Dev. DayuWidayadi
 * @notice Core v5.2 Parent Contract with Advanced Security Features
 * @dev Added proper initializer functions for better inheritance support
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

abstract contract SecureSmartWalletCore is Initializable, EIP712 {
    using EnumerableSet for EnumerableSet.AddressSet;

    /* ========== TYPEHASHES ========== */
    bytes32 public constant CROSS_CHAIN_REQUEST_TYPEHASH = 
        keccak256("CrossChainRequest(uint256 targetChainId,bytes payload,uint256 gasLimit,address refundAddress,uint256 nonce)");
    bytes32 public constant SESSION_KEY_TYPEHASH = 
        keccak256("SessionKey(address key,uint48 validUntil,bytes4[] allowedSelectors,uint256 nonce,uint48 validAfter)");
    bytes32 public constant RECOVERY_TYPEHASH = 
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline)");

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
    address public immutable gasOracle;

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
    event WalletInitialized(address[] owners, address[] guardians);

    /* ========== MODIFIERS ========== */
    modifier onlyEntryPoint() {
        require(msg.sender == address(env.entryPoint), "Caller not EntryPoint");
        _;
    }

    modifier onlyOwner() {
        require(_owners.contains(msg.sender), "Unauthorized: Not owner");
        _;
    }

    modifier whenNotLocked() {
        require(!env.isLocked, "Contract is locked");
        _;
    }

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) EIP712("SecureSmartWallet", "5.2") {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
        self = address(this);
        gasOracle = _gasOracle;
        _disableInitializers();
    }

    /* ========== INITIALIZERS ========== */
    /**
     * @dev Initializes the core contract (basic version)
     * @param _factory The factory address that deployed this wallet
     * @param _defaultPaymaster The default paymaster to use for transactions
     */
    function __SecureSmartWalletCore_init(
        address _factory,
        address _defaultPaymaster
    ) internal onlyInitializing {
        __EIP712_init("SecureSmartWallet", "5.2");
        
        env = ExecutionEnvironment({
            entryPoint: IEntryPoint(entryPoint),
            defaultPaymaster: _defaultPaymaster,
            chainId: CHAIN_ID,
            isLocked: false,
            upgradeTimelock: 0,
            securityDelay: 1 days
        });
        
        factory = _factory;
        _guardianConfig.cooldown = 1 days;
    }

    /**
     * @dev Extended initialization with owners and guardians
     * @param _owners Array of initial owners
     * @param _guardians Array of initial guardians
     * @param _guardianThreshold Minimum number of guardians required for recovery
     * @param _factory The factory address
     * @param _supportedChains Array of supported chain IDs for cross-chain
     * @param _defaultPaymaster Default paymaster address
     */
    function __SecureSmartWalletCore_init_with_guardians(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint64 _guardianThreshold,
        address _factory,
        uint256[] calldata _supportedChains,
        address _defaultPaymaster
    ) internal onlyInitializing {
        __SecureSmartWalletCore_init(_factory, _defaultPaymaster);

        // Set owners
        for (uint i = 0; i < _owners.length; i++) {
            _owners.add(_owners[i]);
        }

        // Set guardians
        for (uint i = 0; i < _guardians.length; i++) {
            _guardianConfig.guardians.add(_guardians[i]);
        }
        _guardianConfig.threshold = _guardianThreshold;

        // Set supported chains
        for (uint i = 0; i < _supportedChains.length; i++) {
            supportedChains[_supportedChains[i]] = true;
        }

        emit WalletInitialized(_owners, _guardians);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    function _verifySignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address signer = ECDSA.recover(hash, signature);
        return _owners.contains(signer);
    }

    function _validateImplementation(address newImpl) internal view {
        require(newImpl != address(0), "Invalid implementation");
        require(newImpl.code.length > 0, "No code at implementation");
    }

    function _setLockStatus(bool locked) internal {
        env.isLocked = locked;
        emit LockStatusChanged(locked, msg.sender);
    }

    function _validatePlugin(address plugin) internal view {
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

    /* ========== ENTRYPOINT INTERFACE ========== */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
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

    /* ========== CROSS-CHAIN BRIDGE ========== */
    function executeCrossChain(
        uint256 targetChainId,
        bytes calldata payload,
        uint256 gasLimit,
        address refundAddress,
        uint256 bridgeFee,
        bytes calldata signature
    ) external payable whenNotLocked {
        require(supportedChains[targetChainId], "Unsupported chain");
        
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            CROSS_CHAIN_REQUEST_TYPEHASH,
            targetChainId,
            keccak256(payload),
            gasLimit,
            refundAddress,
            sessionNonces[msg.sender]++
        )));

        require(_verifySignature(digest, signature), "Invalid signature");

        (bool success,) = gasOracle.call{value: bridgeFee}(
            abi.encodeWithSignature("estimateFees(uint256,bytes)", targetChainId, payload)
        );
        require(success, "Bridge fee payment failed");

        emit CrossChainInitiated(targetChainId, payload);
    }

    /* ========== PLUGIN SYSTEM (SANDBOXED) ========== */
    function installPlugin(
        address plugin,
        bytes4[] calldata selectors,
        bytes calldata initData,
        bool whitelist
    ) external onlyOwner whenNotLocked {
        _validatePlugin(plugin);

        for (uint256 i = 0; i < selectors.length; i++) {
            selectorToPlugin[selectors[i]] = plugin;
        }

        installedPlugins[plugin] = Plugin({
            implementation: plugin,
            enabledSelectors: selectors,
            isWhitelisted: whitelist,
            installTimestamp: uint48(block.timestamp)
        });

        if (initData.length > 0) {
            (bool success,) = plugin.call(initData);
            require(success, "Plugin init failed");
        }
    }

    function uninstallPlugin(address plugin) external onlyOwner {
        require(installedPlugins[plugin].installTimestamp > 0, "Plugin not installed");
        pluginUninstallTimestamps[plugin] = block.timestamp + env.securityDelay;
        emit PluginUninstallScheduled(plugin, pluginUninstallTimestamps[plugin]);
    }

    function completePluginUninstall(address plugin) external onlyOwner {
        require(pluginUninstallTimestamps[plugin] > 0, "No uninstall scheduled");
        require(block.timestamp >= pluginUninstallTimestamps[plugin], "Delay not passed");

        Plugin storage p = installedPlugins[plugin];
        for (uint i = 0; i < p.enabledSelectors.length; i++) {
            delete selectorToPlugin[p.enabledSelectors[i]];
        }
        delete installedPlugins[plugin];
        delete pluginUninstallTimestamps[plugin];
    }

    /* ========== SESSION MANAGEMENT ========== */
    function revokeSessionKey(address key) external onlyOwner {
        require(sessionKeys[key].validUntil > block.timestamp, "Session expired");
        sessionKeys[key].isRevoked = true;
        emit SessionKeyRevoked(key);
    }

    function registerSessionKey(
        address key,
        uint48 validUntil,
        uint48 validAfter,
        bytes4[] calldata allowedSelectors,
        bytes calldata signature
    ) external {
        require(validUntil > block.timestamp, "Expired validity");
        require(validAfter < validUntil, "Invalid time window");
        require(allowedSelectors.length > 0, "No selectors");

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            SESSION_KEY_TYPEHASH,
            key,
            validUntil,
            keccak256(abi.encodePacked(allowedSelectors)),
            sessionNonces[key]++,
            validAfter
        ));

        require(_verifySignature(digest, signature), "Invalid signature");
        
        sessionKeys[key] = SessionKey({
            validUntil: validUntil,
            validAfter: validAfter,
            allowedSelectors: allowedSelectors,
            isRevoked: false,
            addedBy: msg.sender
        });
    }

    /* ========== GUARDIAN FUNCTIONS ========== */
    function addGuardian(address guardian) external onlyOwner {
        require(!_guardianConfig.guardians.contains(guardian), "Already guardian");
        _guardianConfig.guardians.add(guardian);
        emit GuardianAdded(guardian);
    }

    function removeGuardian(address guardian) external onlyOwner {
        require(_guardianConfig.guardians.contains(guardian), "Not guardian");
        _guardianConfig.guardians.remove(guardian);
        emit GuardianRemoved(guardian);
    }

    /* ========== RECOVERY SYSTEM ========== */
    function initiateRecovery(address[] calldata newOwners, bytes[] calldata signatures, uint256 deadline) external {
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
    
        for (uint i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "Invalid owner");
            for (uint j = i + 1; j < newOwners.length; j++) {
                require(newOwners[i] != newOwners[j], "Duplicate owner");
            }
        }
        
        while (_owners.length() > 0) {
            _owners.remove(_owners.at(0));
        }
        
        for (uint i = 0; i < newOwners.length; i++) {
            _owners.add(newOwners[i]);
        }
    
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
        emit RecoveryExecuted(newOwners);
    }

    /* ========== UPGRADE MECHANISM ========== */
    function scheduleUpgrade(address newImpl) external onlyOwner whenNotLocked {
        _validateImplementation(newImpl);
        pendingImplementation = newImpl;
        env.upgradeTimelock = block.timestamp + env.securityDelay;
        emit ImplementationUpgradeScheduled(newImpl, env.upgradeTimelock);
    }
    
    function executeUpgrade() external onlyOwner {
        require(block.timestamp >= env.upgradeTimelock, "Timelock not expired");
        require(pendingImplementation != address(0), "No upgrade scheduled");
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = pendingImplementation;
        pendingImplementation = address(0);
    }

    /* ========== GAS OPTIMIZATION ========== */
    function getOptimalGasParams() public view returns (
        uint256 baseFee,
        uint256 priorityFee,
        uint256 gasLimitBuffer
    ) {
        (bool success, bytes memory data) = gasOracle.staticcall(
            abi.encodeWithSignature("getGasParameters()")
        );
        require(success, "Gas oracle call failed");
        return abi.decode(data, (uint256, uint256, uint256));
    }

    /* ========== SECURITY FUNCTIONS ========== */
    function emergencyLock(bytes calldata guardianSignature) external {
        bytes32 lockHash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("EmergencyLock(uint256 nonce,uint256 deadline)"),
            recoveryNonces[msg.sender]++,
            block.timestamp + 1 hours
        )));

        address signer = ECDSA.recover(lockHash, guardianSignature);
        require(_guardianConfig.guardians.contains(signer), "Not guardian");
        _setLockStatus(true);
    }

    function setSecurityDelay(uint256 delay) external onlyOwner {
        require(delay <= 7 days, "Delay too long");
        env.securityDelay = delay;
    }

    /* ========== FALLBACK HANDLER ========== */
    fallback() external payable {
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
    
    /* ========== RECEIVE FUNCTION ========== */
    receive() external payable {
        emit ETHReceived(msg.sender, msg.value);
    }

    /* ========== VIEW FUNCTIONS ========== */
    function getOwners() external view returns (address[] memory) {
        return _owners.values();
    }

    function getGuardians() external view returns (address[] memory) {
        return _guardianConfig.guardians.values();
    }

    function isOwner(address account) external view returns (bool) {
        return _owners.contains(account);
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}