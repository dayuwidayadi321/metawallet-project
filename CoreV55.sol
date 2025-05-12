// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Core v5.5 - Ultimate Inheritable EIP-4337 Smart Wallet Best Multi-Chain
 * @author DFXC IndonesiaSecurity Web3 Project - Dev. DayuWidayadi
 * @notice Core v5.5 with Critical Recovery System Overhaul & Advanced Security
 * @dev Audit Phase #4 [CRITICAL RECOVERY PATCH] v5.5
 *      - Fixed cross-contract signature replay vulnerability
 *      - Implemented request-bound recovery nonces
 *      - Added contract address binding to recovery signatures
 * NEW INTREGRATION : LAYER ZERO MULTI-CHAIN INSFRACTRUCTURE
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
import "./interface/ILayerZeroEndpoint.sol";
import "./interface/ILayerZeroReceiver.sol";
import "./interface/ILayerZeroUserApplicationConfig.sol";

abstract contract CoreV55 is Initializable, EIP712, ReentrancyGuard {
    using EnumerableSet for EnumerableSet.AddressSet;

    /* ========== TYPEHASHES ========== */
    bytes32 public constant CROSS_CHAIN_REQUEST_TYPEHASH = 
        keccak256("CrossChainRequest(uint256 targetChainId,bytes payload,uint256 gasLimit,address refundAddress,uint256 nonce)");
    bytes32 public constant SESSION_KEY_TYPEHASH = 
        keccak256("SessionKey(address key,uint48 validUntil,bytes4[] allowedSelectors,uint256 nonce,uint48 validAfter)");
    bytes32 public constant RECOVERY_TYPEHASH = 
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline,bytes32 ownersHash)");
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
    
    // ========== LAYERZERO STATE ==========
    ILayerZeroEndpoint public lzEndpoint;
    uint16 public constant LZ_VERSION = 1;
    mapping(uint16 => bytes) public trustedRemoteLookup; // chainId => remote address
    mapping(uint16 => uint256) public chainGasBalances;  // chainId => native gas balance
        
    // Security
    GuardianConfig private _guardianConfig;
    EnumerableSet.AddressSet private _owners;
    mapping(address => bool) public isBlacklisted;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public pluginUninstallTimestamps;
    mapping(address => uint256) public guardianRecoveryNonces;

    // Modules
    mapping(address => SessionKey) public sessionKeys;
    mapping(address => uint256) public sessionNonces;
    mapping(address => uint256) public recoveryNonces;

    /* ========== ALL EVENTS ========== */
    event ImplementationUpgradeScheduled(address newImplementation, uint256 unlockTime);
    event CrossChainInitiated(uint256 indexed dstChainId, bytes indexed payload);
    event SessionKeyRevoked(address indexed key);
    event LockStatusChanged(bool locked, address initiatedBy);
    event PluginUninstallScheduled(address indexed plugin, uint256 uninstallTime);
    event WalletInitialized(address[] owners, address guardian);
    event RecoveryCooldownUpdated(uint64 newCooldown);
    event GuardianThresholdUpdated(uint64 newThreshold);
    event SecurityDelayUpdated(uint256 newDelay);
    event EmergencyLockVetoed(address indexed vetoer);
    event GuardianInactivityWarning(uint256 lastActiveTimestamp);
    event UpgradeExecuted(address indexed newImplementation);
    event GasOracleUpdated(address indexed oldOracle, address indexed newOracle);
    event OwnerAdded(address indexed owner);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian); 
    event RecoveryExecuted(address[] newOwners, bytes32 ownersHash, uint256 recoveryNonce);
    event ETHReceived(address indexed sender, uint256 amount);
    event PluginUninstallCancelled(address indexed plugin);
    event PluginForceUninstalled(address indexed plugin, address initiatedBy);
    event LZMessageSent(uint16 indexed dstChainId, bytes indexed payload);
    event LZMessageReceived(uint16 indexed srcChainId, bytes indexed payload);
    
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
        EIP712("CoreV55", "5.5") 
    {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
        self = address(this);
        gasOracle = _gasOracle;
        _disableInitializers();
    }

    /* ========== INITIALIZER ========== */
    function __CoreV55_init(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown,
        address _lzEndpoint,
        uint16[] memory _supportedChainIds,
        bytes[] memory _trustedRemotes
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
        
        // Initialize LayerZero
        require(_lzEndpoint != address(0), "Invalid LZ endpoint");
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);
        
        // Set supported chains and trusted remotes
        require(_supportedChainIds.length == _trustedRemotes.length, "Mismatched chain config");
        for (uint256 i = 0; i < _supportedChainIds.length; i++) {
            trustedRemoteLookup[_supportedChainIds[i]] = _trustedRemotes[i];
            supportedChains[_supportedChainIds[i]] = true;
        }
    
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

    // ========== CROSS-CHAIN FUNCTIONS ==========
    
    // Custom Errors (lebih hemat gas dari require)
    error InvalidEndpoint(address endpoint);
    error ChainNotSupported(uint16 chainId);
    error InsufficientGasFee(uint256 required, uint256 provided);
    error RemoteAddressMismatch(bytes remote);
    error TransferFailed(address token, address from, uint256 amount);
    error FailedCrossChainCall(uint16 chainId, bytes reason);
    
    function setLZEndpoint(address _endpoint) external onlyOwner {
        // Pastikan endpoint valid dan memiliki code
        if (_endpoint.code.length == 0) revert InvalidEndpoint(_endpoint);
        lzEndpoint = ILayerZeroEndpoint(_endpoint);
    }
    
    function setTrustedRemote(uint16 _chainId, bytes calldata _remoteAddress) external onlyOwner {
        // Validasi panjang address (20 bytes + padding)
        if (_remoteAddress.length != 40) revert RemoteAddressMismatch(_remoteAddress);
        trustedRemoteLookup[_chainId] = _remoteAddress;
    }
    
    function sendCrossChain(
        uint16 _dstChainId,
        bytes calldata _payload,
        address _refundAddress,
        address _gasPaymentToken  // Gunakan address(0) untuk native gas
    ) external payable onlyOwner {
        // Cache storage variable untuk hemat gas
        bytes memory remote = trustedRemoteLookup[_dstChainId];
        if (remote.length == 0) revert ChainNotSupported(_dstChainId);
    
        // Gunakan gasleft() dengan buffer 20% untuk antisipasi fluktuasi
        uint256 gasLimit = (gasleft() * 120) / 100;
        bytes memory adapterParams = abi.encodePacked(LZ_VERSION, gasLimit);
    
        // Estimate gas fee sekali saja
        uint256 gasFee = lzEndpoint.estimateFees(
            _dstChainId,
            address(this),
            _payload,
            false,
            adapterParams
        );
    
        // Handle native token atau ERC20
        if (_gasPaymentToken == address(0)) {
            if (msg.value < gasFee) revert InsufficientGasFee(gasFee, msg.value);
            
            lzEndpoint.send{value: gasFee}(
                _dstChainId,
                remote, // Gunakan cached remote
                _payload,
                _refundAddress,
                address(0),
                adapterParams
            );
            
            // Kembalikan kelebihan ETH jika ada
            if (msg.value > gasFee) {
                (bool success, ) = msg.sender.call{value: msg.value - gasFee}("");
                if (!success) revert TransferFailed(address(0), msg.sender, msg.value - gasFee);
            }
        } else {
            // Gunakan low-level call untuk transferFrom (hindari extra gas dari SafeERC20)
            (bool success, bytes memory data) = _gasPaymentToken.call(
                abi.encodeWithSelector(
                    IERC20.transferFrom.selector,
                    msg.sender,
                    address(this),
                    gasFee
                )
            );
            
            if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
                revert TransferFailed(_gasPaymentToken, msg.sender, gasFee);
            }
    
            // Approve dan kirim
            IERC20(_gasPaymentToken).approve(address(lzEndpoint), gasFee);
            lzEndpoint.sendFrom{value: msg.value}(
                address(this),
                _dstChainId,
                remote,
                _payload,
                _refundAddress,
                address(0),
                adapterParams
            );
        }
    
        emit LZMessageSent(_dstChainId, _payload);
    }

    // ========== LAYERZERO CALLBACK ==========
    function _nonblockingLzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        bytes calldata _payload
    ) internal virtual {
        // Verifikasi trustedRemote dengan chainId
        bytes memory trustedRemote = trustedRemoteLookup[_srcChainId];
        require(trustedRemote.length > 0, "Invalid chain");
    
        // Bandingkan alamat remote secara byte-per-byte
        require(
            _srcAddress.length == trustedRemote.length &&
            keccak256(_srcAddress) == keccak256(trustedRemote),
            "Invalid remote"
        );
    
        // Pastikan payload tidak kosong
        require(_payload.length > 0, "Empty payload");
    
        (bool success, bytes memory reason) = address(this).delegatecall(_payload);
        if (!success) {
            revert FailedCrossChainCall(_srcChainId, reason);
        }
    
        emit LZMessageReceived(_srcChainId, _payload);
    }

    /* ========== PLUGIN SYSTEM COREV54 (ULTIMATE MODULAR) ========== */
    // Storage optimization: Group plugin-related mappings
    struct PluginSystem {
        mapping(bytes4 => address) selectorToPlugin;
        mapping(address => Plugin) installedPlugins;
        mapping(address => uint256) pluginUninstallTimestamps;
        mapping(bytes32 => bool) usedUninstallNonces;
    }
    
    PluginSystem private _pluginSystem;
    
    // Events with indexed parameters for better filtering
    event PluginInstalled(
        address indexed plugin,
        bytes4[] selectors,
        bool whitelisted,
        address indexed installedBy
    );
    event PluginUninstallScheduled(
        address indexed plugin,
        uint256 uninstallTime,
        address indexed initiatedBy
    );
    event PluginForceUninstalled(
        address indexed plugin,
        address indexed executedBy,
        uint256 nonce
    );
    event PluginUpgraded(
        address indexed oldPlugin,
        address indexed newPlugin,
        address indexed upgradedBy
    );
    
    function installPlugin(
        address plugin,
        bytes4[] calldata selectors,
        bytes calldata initData,
        bool whitelist
    ) external virtual onlyOwner whenNotLocked {
        _beforePluginInstall(plugin, selectors);
        _validatePlugin(plugin);
        
        require(
            _pluginSystem.pluginUninstallTimestamps[plugin] == 0,
            "Plugin pending uninstall"
        );
    
        Plugin storage p = _pluginSystem.installedPlugins[plugin];
        p.implementation = plugin;
        p.enabledSelectors = selectors;
        p.isWhitelisted = whitelist;
        p.installTimestamp = uint48(block.timestamp);
    
        for (uint256 i = 0; i < selectors.length; ) {
            require(
                _pluginSystem.selectorToPlugin[selectors[i]] == address(0),
                "Selector already registered"
            );
            _pluginSystem.selectorToPlugin[selectors[i]] = plugin;
            unchecked { ++i; } // Gas optimization
        }
    
        if (initData.length > 0) {
            _initializePlugin(plugin, initData);
        }
    
        emit PluginInstalled(plugin, selectors, whitelist, msg.sender);
        _afterPluginInstall(plugin);
    }
    
    function uninstallPlugin(address plugin) external virtual onlyOwner {
        require(
            _pluginSystem.installedPlugins[plugin].installTimestamp > 0,
            "Plugin not installed"
        );
        require(
            _pluginSystem.pluginUninstallTimestamps[plugin] == 0,
            "Uninstall already scheduled"
        );
        
        _pluginSystem.pluginUninstallTimestamps[plugin] = block.timestamp + env.securityDelay;
        emit PluginUninstallScheduled(plugin, block.timestamp + env.securityDelay, msg.sender);
    }
    
    function forceUninstallPlugin(
        address plugin,
        bytes[] calldata guardianSignatures,
        uint256 uninstallNonce
    ) external virtual {
        require(
            _pluginSystem.installedPlugins[plugin].installTimestamp > 0,
            "Plugin not installed"
        );
    
        bytes32 nonceKey = keccak256(abi.encodePacked(plugin, uninstallNonce));
        require(!_pluginSystem.usedUninstallNonces[nonceKey], "Nonce already used");
        _pluginSystem.usedUninstallNonces[nonceKey] = true;
    
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("ForceUninstall(address plugin,uint256 nonce,uint256 deadline)"),
            plugin,
            uninstallNonce,
            block.timestamp + 24 hours
        )));
    
        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_guardianConfig.guardians.length());
        
        for (uint i = 0; i < guardianSignatures.length; ) {
            address signer = ECDSA.recover(hash, guardianSignatures[i]);
            
            for (uint j = 0; j < validSignatures; ) {
                require(seenGuardians[j] != signer, "Duplicate signature");
                unchecked { ++j; }
            }
            
            if (_guardianConfig.guardians.contains(signer)) {
                seenGuardians[validSignatures] = signer;
                unchecked { ++validSignatures; }
                if (validSignatures >= _guardianConfig.threshold) break;
            }
            unchecked { ++i; }
        }
    
        require(
            validSignatures >= _guardianConfig.threshold,
            "Insufficient guardians"
        );
    
        _removePlugin(plugin);
        emit PluginForceUninstalled(plugin, msg.sender, uninstallNonce);
    }
    
    function upgradePlugin(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) external virtual onlyOwner {
        _validatePluginUpgrade(oldPlugin, newPlugin);
        
        // Make migration function external
        (bool success, bytes memory result) = address(this).call(
            abi.encodeWithSelector(
                this.externalMigratePluginState.selector,
                oldPlugin,
                newPlugin,
                migrationData
            )
        );
        
        if (!success) {
            revert PluginUpgradeFailed(result);
        }
        
        _updatePluginMappings(oldPlugin, newPlugin);
        _cleanupOldPlugin(oldPlugin);
        emit PluginUpgraded(oldPlugin, newPlugin, msg.sender);
    }
    
    // New external function for migration
    function externalMigratePluginState(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) external {
        require(msg.sender == address(this), "Internal only");
        require(oldPlugin != address(0), "Invalid old plugin");
        _migratePluginState(oldPlugin, newPlugin, migrationData);
    }
    
    /* ========== INTERNAL FUNCTIONS (OVERRIDABLE) ========== */
    function _beforePluginInstall(
        address plugin,
        bytes4[] calldata selectors
    ) internal virtual {
        // Can be overridden to add pre-install checks
    }
    
    function _afterPluginInstall(address plugin) internal virtual {
        // Can be overridden for post-install hooks
    }
    
    function _validatePlugin(address plugin) internal view virtual {
        require(plugin != address(0), "Invalid plugin");
        require(plugin.code.length > 0, "No code at plugin");
        require(!isBlacklisted[plugin], "Plugin blacklisted");
    
        bytes4[6] memory protectedSelectors = [
            this.executeUpgrade.selector,
            this.scheduleUpgrade.selector,
            this.installPlugin.selector,
            this.uninstallPlugin.selector,
            this.initiateRecovery.selector,
            this.emergencyLock.selector
        ];
    
        for (uint i = 0; i < protectedSelectors.length; ) {
            require(
                _pluginSystem.selectorToPlugin[protectedSelectors[i]] != plugin,
                "Cannot override protected selector"
            );
            unchecked { ++i; }
        }
    }
    
    function _initializePlugin(
        address plugin,
        bytes calldata initData
    ) internal virtual {
        (bool success, bytes memory result) = plugin.delegatecall(initData);
        if (!success) {
            if (result.length > 0) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            revert("Plugin init failed");
        }
    }
    
    function _removePlugin(address plugin) internal virtual {
        bytes4[] memory selectors = _pluginSystem.installedPlugins[plugin].enabledSelectors;
        
        for (uint i = 0; i < selectors.length; ) {
            delete _pluginSystem.selectorToPlugin[selectors[i]];
            unchecked { ++i; }
        }
        
        delete _pluginSystem.installedPlugins[plugin];
        delete _pluginSystem.pluginUninstallTimestamps[plugin];
    }
    
    function _validatePluginUpgrade(
        address oldPlugin,
        address newPlugin
    ) internal view virtual {
        require(newPlugin.code.length > 0, "Invalid plugin");
        require(
            _pluginSystem.installedPlugins[oldPlugin].installTimestamp > 0,
            "Plugin not installed"
        );
        require(oldPlugin != newPlugin, "Cannot upgrade to same plugin");
        require(
            _pluginSystem.pluginUninstallTimestamps[oldPlugin] == 0,
            "Plugin pending uninstall"
        );
    }
    
    function _migratePluginState(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) internal virtual {
        if (migrationData.length > 0) {
            (bool success, bytes memory result) = newPlugin.delegatecall(migrationData);
            if (!success) {
                if (result.length > 0) {
                    assembly {
                        revert(add(result, 32), mload(result))
                    }
                }
                revert("Migration failed");
            }
        }
    }
    
    function _updatePluginMappings(
        address oldPlugin,
        address newPlugin
    ) internal virtual {
        Plugin storage oldData = _pluginSystem.installedPlugins[oldPlugin];
        bytes4[] storage selectors = oldData.enabledSelectors;
        
        _pluginSystem.installedPlugins[newPlugin] = Plugin({
            implementation: newPlugin,
            enabledSelectors: selectors,
            isWhitelisted: oldData.isWhitelisted,
            installTimestamp: uint48(block.timestamp)
        });
    
        for (uint256 i = 0; i < selectors.length; ) {
            _pluginSystem.selectorToPlugin[selectors[i]] = newPlugin;
            unchecked { ++i; }
        }
    }
    
    function _cleanupOldPlugin(address oldPlugin) internal virtual {
        delete _pluginSystem.installedPlugins[oldPlugin];
    }
    
    // Custom errors for better gas efficiency
    error PluginUpgradeFailed(bytes revertReason);
    error PluginInitializationFailed();
    error PluginMigrationFailed();

    /* ========== RECOVERY SYSTEM ========== */
    function initiateRecovery(
        address[] calldata newOwners, 
        bytes[] calldata signatures, 
        uint256 deadline,
        uint256 recoveryNonce
    ) external virtual {
        // Input validation
        require(block.timestamp <= deadline, "CoreV54: Signature expired");
        require(_guardianConfig.guardians.contains(msg.sender), "CoreV54: Caller not guardian");
        require(newOwners.length > 0, "CoreV54: No new owners provided");
        
        // Validate new owners array
        for (uint256 i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "CoreV54: Invalid owner address");
        }
    
        // Cooldown check
        require(
            block.timestamp > _guardianConfig.lastRecoveryTimestamp + _guardianConfig.cooldown,
            "CoreV54: Recovery cooldown active"
        );
    
        // Generate recovery hash with chain-specific binding
        bytes32 ownersHash = keccak256(abi.encodePacked(newOwners));
        bytes32 recoveryHash = _hashTypedDataV4(keccak256(abi.encode(
            RECOVERY_TYPEHASH,
            keccak256(abi.encodePacked(newOwners)),
            recoveryNonce,
            deadline,
            ownersHash,
            address(this),
            block.chainid
        )));
    
        // Chain-specific nonce tracking
        bytes32 recoveryId = keccak256(abi.encodePacked(recoveryHash, block.chainid));
        require(!usedSignatures[recoveryId], "CoreV54: Nonce already used");
        usedSignatures[recoveryId] = true;
    
        // Signature verification
        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_guardianConfig.guardians.length());
        
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(recoveryHash, signatures[i]);
            
            // Check for duplicate signatures
            for (uint256 j = 0; j < validSignatures; j++) {
                require(seenGuardians[j] != signer, "CoreV54: Duplicate signature");
            }
            
            if (_guardianConfig.guardians.contains(signer)) {
                seenGuardians[validSignatures] = signer;
                validSignatures++;
                if (validSignatures >= _guardianConfig.threshold) break;
            }
        }
    
        require(
            validSignatures >= _guardianConfig.threshold,
            "CoreV54: Insufficient guardian approvals"
        );
    
        // Execute recovery
        _replaceOwners(newOwners);
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
        
        emit RecoveryExecuted(
            newOwners,
            ownersHash,
            recoveryNonce,
            block.chainid,
            msg.sender
        );
    }

    function _replaceOwners(address[] calldata newOwners) internal virtual {
        // Clear owners dengan cara yang lebih efisien
        address[] memory oldOwners = _owners.values();
        for (uint i = 0; i < oldOwners.length; i++) {
            _owners.remove(oldOwners[i]);
        }
        
        // Tambahkan owners baru
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
    
    function _isValidGuardian(address guardian) internal view virtual returns (bool) {
        return _guardianConfig.guardians.contains(guardian) && 
               !isBlacklisted[guardian] &&
               guardian.code.length == 0;
    }

    /* ========== UPGRADE MECHANISM ========== */
    function _validateImplementation(address newImpl) internal view {
        require(newImpl != address(0), "Invalid implementation");
        require(newImpl.code.length > 0, "No code at implementation");
        
        // Check Version
        (bool success, bytes memory data) = newImpl.staticcall(
            abi.encodeWithSignature("version()")
        );
        require(success && keccak256(data) == keccak256(bytes("5.4")), "Incompatible version");
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
        
        assembly {
        sstore(_IMPLEMENTATION_SLOT, impl)
    }
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
    
    function setGasOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "Invalid oracle address");
        emit GasOracleUpdated(gasOracle, newOracle);
        gasOracle = newOracle;
    }

    /* ========== SECURITY FUNCTIONS ========== */    
    function emergencyLock(bytes calldata guardianSignature) external virtual {
        uint256 deadline = block.timestamp + 1 hours;
        
        bytes32 lockHash = _hashTypedDataV4(keccak256(abi.encode(
            EMERGENCY_LOCK_TYPEHASH,
            recoveryNonces[msg.sender]++,
            deadline
        )));
    
        require(block.timestamp <= deadline, "Signature expired");
    
        address signer = ECDSA.recover(lockHash, guardianSignature);
        require(_isValidGuardian(signer), "Not guardian");
        _setLockStatus(true);
    }
    
    function setSecurityDelay(uint256 delay) 
        external 
        virtual 
        onlyOwner 
    {
        require(delay <= MAX_PLUGIN_UNINSTALL_DELAY, "Delay too long");
        env.securityDelay = delay;
        emit SecurityDelayUpdated(delay); 
    }
    
    function vetoEmergencyLock() 
        external 
        virtual 
        onlyOwner 
        whenLocked 
    {
        _setLockStatus(false);
        emit EmergencyLockVetoed(msg.sender);
    }
    
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
        address plugin = _pluginSystem.selectorToPlugin[msg.sig];
        require(plugin != address(0), "Selector not registered");
        
        // Periksa whitelist status dari storage yang benar
        Plugin storage p = _pluginSystem.installedPlugins[plugin];
        require(p.isWhitelisted, "Plugin not whitelisted");
    
        // Lock state sebelum delegatecall
        bool wasLocked = env.isLocked;
        env.isLocked = true;
    
        (bool success, bytes memory result) = plugin.delegatecall(msg.data);
        
        // Restore lock state
        env.isLocked = wasLocked;
    
        if (!success) {
            if (result.length > 0) {
                assembly { revert(add(result, 32), mload(result)) }
            } else {
                revert("PluginExecutionFailed");
            }
        }
        assembly { return(add(result, 32), mload(result)) }
    }

    /* ========== RECEIVE EXTERNAL ========== */   
    receive() external payable virtual {
        emit ETHReceived(msg.sender, msg.value);
    }    

    /* ========== VIEW VIRTUAL FUNCTIONS ========== */
    function getOwners() external view virtual returns (address[] memory) {
        return _owners.values();
    }

    function getGuardians() external view virtual returns (address[] memory) {
        return _guardianConfig.guardians.values();
    }

    function isOwner(address account) external view virtual returns (bool) {
        return _owners.contains(account);
    }
    
    function isGuardian(address account) external view virtual returns (bool) {
        return _guardianConfig.guardians.contains(account);
    }    
    
    function version() external pure returns (string memory) {
        return "5.5";
    }    

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}


DeclarationError: Undeclared identifier.
   --> CoreV55.sol:889:36:
    |
889 |         require(block.timestamp <= deadline, "Signature expired");
    |                                    ^^^^^^^^
