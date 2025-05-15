// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CoreV55 - Inheritable EIP-4337 Smart Wallet with Multi-Chain Support  
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi  
 * @notice Version 5.5.1 with Critical Security Upgrades  
 * @dev Audit Phase #6 - Major Fixes:  
 *      - [CRITICAL] Fixed plugin reentrancy attack vector  
 *      - [SECURITY] Added strict selector whitelisting for plugins  
 *      - [SECURITY] Enhanced recovery signature checks (anti-replay + guardian uniqueness)  
 *      - [GAS] Optimized cross-chain gas handling with fail-safes  
 *  
 * Key Improvements:  
 * [FIXED] Reentrancy protection in `_executePlugin`  
 * [ADDED] Pre-flight staticcall checks for plugin safety  
 * [UPGRADED] Stricter input validation across all critical functions  
 *  
 * Security Model:  
 * - EIP-4337 + ERC-7201 (Reentrancy Protection Standard)  
 * - Guardian multi-sig with chain-bound nonces  
 * - Time-locked upgrades with health checks  
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts-upgradeable/utils/StorageSlotUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/IERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/ERC1967/ERC1967UpgradeUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "./interface/ILayerZeroEndpoint.sol";
import "./interface/ILayerZeroReceiver.sol";
import "./interface/ILayerZeroUserApplicationConfig.sol";

    /* ========== Interface ========== */
    interface IUpgradable {
        function VERSION() external view returns (string memory);
        function healthCheck() external returns (bool);
    }    

    interface IStorageCheck {
        function isStorageCompatible(address oldImpl) external view returns (bool);
    }

abstract contract CoreV55 is Initializable, UUPSUpgradeable, EIP712Upgradeable, ReentrancyGuardUpgradeable, ERC1967UpgradeUpgradeable {
    using AddressUpgradeable for address;
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    /* ========== TYPEHASHES ========== */
    bytes32 public constant CROSS_CHAIN_REQUEST_TYPEHASH = 
        keccak256("CrossChainRequest(uint256 targetChainId,bytes payload,uint256 gasLimit,address refundAddress,uint256 nonce)");
    bytes32 public constant SESSION_KEY_TYPEHASH = 
        keccak256("SessionKey(address key,uint48 validUntil,bytes4[] allowedSelectors,uint256 nonce,uint48 validAfter)");
    bytes32 public constant RECOVERY_TYPEHASH = 
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline,bytes32 ownersHash,address verifyingContract,uint256 chainId)");
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
        EnumerableSetUpgradeable.AddressSet guardians;
    }
    
    /* ========== CONSTANTS ========== */
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 public constant MAX_PLUGIN_UNINSTALL_DELAY = 7 days;
    uint256 public constant CONFIRM_WINDOW = 24 hours;

    /* ========== IMMUTABLES ========== */
    address public immutable self;
    IEntryPoint public immutable entryPoint;
    uint256 public immutable CHAIN_ID;
    address public gasOracle;

    /* ========== SHARED STATE ========== */
    ExecutionEnvironment public env;
    address public paymaster;
    address public factory;
    mapping(uint256 => bool) public supportedChains;
    mapping(uint256 => mapping(address => mapping(uint256 => bool))) public usedChainNonces;
    address public pendingImplementation;
    address public previousImplementation;
    uint256 public upgradeFailureTimestamp;
    uint256 public constant ROLLBACK_WINDOW = 24 hours;
    uint256 public upgradeTimestamp;
    bool public upgradeInProgress;
        
    // ========== LAYERZERO STATE ==========
    ILayerZeroEndpoint public lzEndpoint;
    uint16 public constant LZ_VERSION = 1;
    mapping(uint16 => bytes) public trustedRemoteLookup; // chainId => remote address
    mapping(uint16 => uint256) public chainGasBalances;  // chainId => native gas balance
        
    // Security
    GuardianConfig private _guardianConfig;
    EnumerableSetUpgradeable.AddressSet private _owners;
    mapping(address => bool) public isBlacklisted;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public pluginUninstallTimestamps;
    mapping(address => uint256) public guardianRecoveryNonces;
    mapping(address => mapping(uint256 => bool)) public usedRecoveryNonces;

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
    event GuardianActionExecuted(address indexed guardian, bytes4 action, uint256 timestamp);
    event UpgradeExecuted(address indexed newImplementation);
    event GasOracleUpdated(address indexed oldOracle, address indexed newOracle);
    event OwnerAdded(address indexed owner);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian); 
    event RecoveryExecuted(address[] newOwners, bytes32 ownersHash, uint256 recoveryNonce, uint256 chainId, address initiator);
    event ETHReceived(address indexed sender, uint256 amount);
    event PluginUninstallCancelled(address indexed plugin);
    event PluginForceUninstalled(address indexed plugin, address initiatedBy);
    event LZMessageSent(uint16 indexed dstChainId, bytes indexed payload);
    event LZMessageReceived(uint16 indexed srcChainId, bytes indexed payload);
    event UpgradeInitiated(address indexed newImplementation);
    event UpgradeHealthChecked(bool isHealthy);
    event UpgradeRolledBack(address indexed previousImplementation);
    event UpgradeConfirmed(address indexed newImplementation);
    event UpgradeAuthorized(address indexed newImplementation);  
    event UpgradeCompleted(address indexed newImplementation);
    
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
    
    modifier noReplay(uint256 nonce, address signer) {
        require(!usedChainNonces[block.chainid][signer][nonce], "Nonce already used");
        _;
        usedChainNonces[block.chainid][signer][nonce] = true;
    }

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) {
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
    ) public virtual onlyInitializing {
        __EIP712_init("CoreV55", "5.5");
        __ReentrancyGuard_init();
        
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
    function _verifySignature(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Tambahkan pengecekan malleability
        require(signature.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid signature");
        
        return ECDSAUpgradeable.recover(hash, v, r, s);
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

        address signer = _verifySignature(userOpHash, userOp.signature);
        if (_owners.contains(signer)) {
            return 0;
        }

        // Check session keys
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
    
    function initializeForUserOp(IEntryPoint _entryPoint, address _paymaster) external virtual {
        require(address(env.entryPoint) == address(0), "Already initialized");
        env.entryPoint = _entryPoint;
        paymaster = _paymaster;
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
        // Decode remote address first
        address remoteAddr;
        assembly {
            remoteAddr := calldataload(_remoteAddress.offset)
        }
        
        // Pastikan remote address memiliki kode yang sesuai
        (bool success, bytes memory data) = remoteAddr.staticcall(abi.encodeWithSignature("supportsInterface(bytes4)", type(ILayerZeroReceiver).interfaceId));
        require(success && abi.decode(data, (bool)), "Invalid remote: tidak implementasikan ILayerZeroReceiver");
        trustedRemoteLookup[_chainId] = _remoteAddress;
    }
    
    /**
     * @dev Sends a cross-chain message via LayerZero
     * @param _dstChainId Destination chain ID
     * @param _payload Encoded function call
     * @param _refundAddress Address for gas refunds
     * @param _gasPaymentToken Token used for gas payment (address(0) for native)
     */
    function sendCrossChain(
        uint16 _dstChainId,
        bytes calldata _payload,
        address payable _refundAddress,
        address _gasPaymentToken
    ) external payable onlyOwner {
        // Check 1: Chain support
        require(
            supportedChains[_dstChainId],
            "Chain not supported"
        );
    
        // Check 2: Payload size limit
        require(
            _payload.length <= 10_000,
            "Payload too large"
        );
    
        // Check 3: Gas limit with buffer
        uint256 gasLimit = (gasleft() * 120) / 100;
        require(
            gasLimit <= 5_000_000,
            "Gas limit too high"
        );
    
        // Get LayerZero fees
        (uint256 gasFee,) = lzEndpoint.estimateFees(
            _dstChainId,
            address(this),
            _payload,
            false,
            abi.encodePacked(LZ_VERSION, gasLimit)
        );
    
        // Handle payment
        if (_gasPaymentToken == address(0)) {
            require(
                msg.value >= gasFee,
                "Insufficient native gas"
            );
            lzEndpoint.send{value: gasFee}(
                _dstChainId,
                trustedRemoteLookup[_dstChainId],
                _payload,
                _refundAddress,
                address(0),
                abi.encodePacked(LZ_VERSION, gasLimit)
            );
            
            // Refund excess
            if (msg.value > gasFee) {
                (bool success, ) = msg.sender.call{
                    value: msg.value - gasFee
                }("");
                require(success, "Refund failed");
            }
        } else {
            // ERC20 gas payment
            IERC20Upgradeable(_gasPaymentToken).transferFrom(
                msg.sender,
                address(this),
                gasFee
            );
            IERC20Upgradeable(_gasPaymentToken).approve(
                address(lzEndpoint),
                gasFee
            );
            lzEndpoint.send{value: msg.value}(
                _dstChainId,
                trustedRemoteLookup[_dstChainId],
                _payload,
                _refundAddress,
                address(0),
                abi.encodePacked(LZ_VERSION, gasLimit)
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

    /* ========== PLUGIN SYSTEM CoreV55 (ULTIMATE MODULAR) ========== */
    // Storage optimization: Group plugin-related mappings
    struct PluginSystem {
        bool reentrancyLock;
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
    event PluginExecuted(
        address indexed plugin,
        bytes4 indexed selector,
        address indexed caller,
        uint256 value
    );
    event PluginInitialized(
        address indexed plugin,
        bool success,
        bytes result
    );
    
    function installPlugin(
        address plugin,
        bytes4[] calldata selectors,
        bytes calldata initData,
        bool whitelist
    ) external virtual onlyOwner whenNotLocked {
        require(selectors.length <= 50, "Too many selectors"); // Batasi jumlah selector
        _beforePluginInstall(plugin, selectors);
        _validatePlugin(plugin, selectors);
        
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
    
    function _initializePlugin(
        address plugin,
        bytes calldata initData
    ) internal virtual {
        require(initData.length <= 1024, "Init data too large");
        
        // Cache gas sebelum eksekusi
        uint256 gasBefore = gasleft();
        
        // Optimasi: Skip delegatecall jika initData kosong
        if (initData.length == 0) {
            emit PluginInitialized(plugin, true, "");
            return;
        }
    
        // Gunakan staticcall untuk pre-check
        (bool preCheckSuccess, ) = plugin.staticcall(initData);
        require(preCheckSuccess, "Plugin pre-check failed");
    
        // Eksekusi dengan delegatecall
        (bool success, bytes memory result) = plugin.delegatecall(initData);
        
        // Gas check dengan buffer 10%
        require((gasBefore - gasleft()) * 11 < 10_000_000, "Initialization used too much gas");
        
        emit PluginInitialized(plugin, success, result);
        
        if (!success) {
            bytes memory revertData = result.length > 0 ? result : bytes("No revert message");
            revert PluginInitializationFailed(revertData);
        }
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
        uint256 uninstallNonce,
        uint256 deadline
    ) external virtual {
        require(block.timestamp <= deadline, "Signature expired");
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
            deadline
        )));
    
        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_guardianConfig.guardians.length());
        
        for (uint i = 0; i < guardianSignatures.length; ) {
            address signer = _verifySignature(hash, guardianSignatures[i]);
            
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
        delete _pluginSystem.pluginUninstallTimestamps[plugin];
        emit PluginForceUninstalled(plugin, msg.sender, uninstallNonce);
    }
    
    /**
     * @dev Upgrades a plugin with state migration
     * @param oldPlugin Previous plugin address
     * @param newPlugin New plugin address
     * @param migrationData Calldata for state migration
     */
    function upgradePlugin(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) external onlyOwner {
        // Check 1: Validate plugins
        require(oldPlugin != newPlugin, "Same plugin");
        require(
            _pluginSystem.installedPlugins[oldPlugin].installTimestamp > 0,
            "Old plugin not installed"
        );
        require(
            newPlugin.code.length > 0,
            "New plugin has no code"
        );
    
        // Check 2: Storage compatibility
        if (IERC165Upgradeable(newPlugin).supportsInterface(
            type(IStorageCheck).interfaceId
        )) {
            require(
                IStorageCheck(newPlugin).isStorageCompatible(oldPlugin),
                "Storage mismatch"
            );
        }
    
        // Migrate state
        if (migrationData.length > 0) {
            (bool success, ) = newPlugin.delegatecall(migrationData);
            require(success, "Migration failed");
        }
    
        // Update plugin mappings
        bytes4[] storage selectors = _pluginSystem
            .installedPlugins[oldPlugin]
            .enabledSelectors;
        
        for (uint256 i = 0; i < selectors.length; i++) {
            _pluginSystem.selectorToPlugin[selectors[i]] = newPlugin;
        }
    
        // Install new plugin
        _pluginSystem.installedPlugins[newPlugin] = Plugin({
            implementation: newPlugin,
            enabledSelectors: selectors,
            isWhitelisted: _pluginSystem.installedPlugins[oldPlugin].isWhitelisted,
            installTimestamp: uint48(block.timestamp)
        });
    
        // Remove old plugin
        delete _pluginSystem.installedPlugins[oldPlugin];
        
        emit PluginUpgraded(oldPlugin, newPlugin, msg.sender);
    }
    
    /* ========== INTERNAL FUNCTIONS (OVERRIDABLE) ========== */
    function _beforePluginInstall(
        address,
        bytes4[] calldata selectors
    ) internal virtual {
        // Can be overridden to add pre-install checks
        require(selectors.length > 0, "No selectors provided");
    }
    
    function _afterPluginInstall(address plugin) internal virtual {
        // Can be overridden for post-install hooks
    }
    
    function _validatePlugin(address plugin, bytes4[] calldata selectors) internal view {
        require(selectors.length > 0, "No selectors provided");
        require(plugin.isContract(), "Invalid plugin");
        
        // Cache plugin code untuk efisiensi
        bytes memory code = plugin.code;
        uint256 size = code.length;
    
        // Validasi ukuran kontrak
        require(size > 512 && size < 24_576, "Invalid plugin size");
        
        // Validasi selector tersedia di kontrak
        for (uint256 i = 0; i < selectors.length; ) {
            bool selectorFound = false;
            for (uint256 j = 0; j < size - 3; ) {
                if (bytes4(code[j]) == selectors[i]) {
                    selectorFound = true;
                    break;
                }
                unchecked { j++; }
            }
            require(selectorFound, string(abi.encodePacked("Selector ", 
                _bytes4ToHexString(selectors[i]), " not found")));
            unchecked { i++; }
        }
    
        // Deteksi opcode berbahaya dengan optimasi gas
        require(
            !_containsBytes(code, hex"f0f5ff"), // Gabungkan semua pattern dalam 1 pencarian
            "Dangerous opcodes detected"
        );
    }
    
    // Optimasi helper function
    function _containsBytes(bytes memory data, bytes4 patterns) internal pure returns (bool) {
        bytes4 mask = 0xFFFFFFFF;
        for (uint256 i = 0; i < data.length - 3; ) {
            bytes4 chunk;
            assembly {
                chunk := mload(add(add(data, 32), i))
            }
            chunk &= mask;
            if (chunk & patterns == patterns) {
                return true;
            }
            unchecked { i++; }
        }
        return false;
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
        
        // Validasi ukuran plugin baru
        uint256 size;
        assembly {
            size := extcodesize(newPlugin)
        }
        require(size > 0 && size < 24576, "Invalid new plugin size");
    }
    
    event PluginStateMigrated(address indexed oldPlugin, address indexed newPlugin, bool success);

    function _migratePluginState(
        address oldPlugin, 
        address newPlugin,
        bytes calldata migrationData
    ) internal virtual {
        if (migrationData.length > 0) {
            require(oldPlugin != newPlugin, "Cannot migrate to same plugin");
            require(newPlugin.isContract(), "New plugin must be contract");
            
            uint256 gasBefore = gasleft();
            (bool success, bytes memory result) = newPlugin.delegatecall(migrationData);
            require(gasBefore - gasleft() < 1_000_000, "Migration used too much gas");
            
            emit PluginStateMigrated(oldPlugin, newPlugin, success);
            
            if (!success) {
                if (result.length > 0) {
                    assembly {
                        revert(add(result, 32), mload(result))
                    }
                }
                revert PluginMigrationFailed();
            }
        }
    }
    
    function _updatePluginMappings(
        address oldPlugin,
        address newPlugin
    ) internal virtual {
        Plugin storage oldData = _pluginSystem.installedPlugins[oldPlugin];
        bytes4[] memory selectors = oldData.enabledSelectors;
        
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
    
    /**
     * @dev Executes a plugin function with security checks
     * @param plugin Address of the plugin contract
     * @param data Calldata for the plugin function
     * @notice Adds reentrancy protection and selector whitelisting
     */
    function _executePlugin(
        address plugin,
        bytes calldata data
    ) internal nonReentrant {
        // Check 1: Plugin must be installed and not pending uninstall
        require(
            _pluginSystem.installedPlugins[plugin].installTimestamp > 0,
            "Plugin not installed"
        );
        require(
            _pluginSystem.pluginUninstallTimestamps[plugin] == 0,
            "Plugin pending uninstall"
        );
    
        // Check 2: Validate selector against whitelist
        bytes4 selector = bytes4(data[:4]);
        require(
            _isSelectorAllowed(plugin, selector),
            "Selector not whitelisted"
        );
    
        // Check 3: Pre-flight staticcall check
        (bool preCheckSuccess, ) = plugin.staticcall(data);
        require(preCheckSuccess, "Plugin pre-check failed");
    
        // Check 4: Gas limit protection
        uint256 gasBefore = gasleft();
        require(gasBefore > 100_000, "Insufficient gas");
    
        // Execute with delegatecall
        (bool success, bytes memory result) = plugin.delegatecall(data);
    
        // Post-execution checks
        require(
            gasBefore - gasleft() < 1_000_000,
            "Plugin used excessive gas"
        );
    
        if (!success) {
            if (result.length > 0) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            revert("PluginExecutionFailed");
        }
    
        emit PluginExecuted(
            plugin,
            selector,
            msg.sender,
            msg.value
        );
    }
    
    /**
     * @dev Checks if a selector is allowed for a plugin
     */
    function _isSelectorAllowed(
        address plugin,
        bytes4 selector
    ) internal view returns (bool) {
        bytes4[] memory allowedSelectors = _pluginSystem
            .installedPlugins[plugin]
            .enabledSelectors;
    
        for (uint256 i = 0; i < allowedSelectors.length; i++) {
            if (selector == allowedSelectors[i]) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * @dev Internal function to replace all owners with new ones
     * @param newOwners Array of new owner addresses
     */
    function _replaceOwners(address[] calldata newOwners) internal virtual {
        // Clear existing owners
        uint256 currentOwnerCount = _owners.length();
        for (uint256 i = 0; i < currentOwnerCount; ) {
            _owners.remove(_owners.at(0));
            unchecked { ++i; }
        }
        
        // Add new owners
        for (uint256 i = 0; i < newOwners.length; ) {
            require(newOwners[i] != address(0), "Invalid owner address");
            _owners.add(newOwners[i]);
            unchecked { ++i; }
        }
        
        emit RecoveryExecuted(
            newOwners,
            keccak256(abi.encodePacked(newOwners)),
            0, // nonce will be set by the calling function
            block.chainid,
            msg.sender
        );
    }    
    
    // Custom errors for better gas efficiency
    error PluginInitializationFailed(bytes revertData);
    error PluginUpgradeFailed(bytes revertReason);
    error PluginMigrationFailed();
    error PluginExecutionFailed();
    error InvalidPluginAddress();
    error SelectorAlreadyRegistered();
    error PluginSizeExceeded();

    /* ========== RECOVERY SYSTEM ========== */
    /**
     * @dev Initiates wallet recovery with multi-guardian approval
     * @param newOwners Array of new owner addresses
     * @param signatures Guardian signatures
     * @param deadline Signature expiry timestamp
     * @param recoveryNonce Unique nonce per guardian
     */
    function initiateRecovery(
        address[] calldata newOwners,
        bytes[] calldata signatures,
        uint256 deadline,
        uint256 recoveryNonce
    ) external virtual {
        // Check 1: Input validation
        require(block.timestamp <= deadline, "Signature expired");
        require(newOwners.length > 0, "No new owners");
        require(
            !usedRecoveryNonces[msg.sender][recoveryNonce],
            "Nonce already used"
        );
    
        // Check 2: Cooldown period
        require(
            block.timestamp >= _guardianConfig.lastRecoveryTimestamp + _guardianConfig.cooldown,
            "Cooldown active"
        );
    
        // Check 3: Owners uniqueness
        bytes32 ownersHash = keccak256(abi.encodePacked(newOwners));
        for (uint256 i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "Invalid owner");
            for (uint256 j = i + 1; j < newOwners.length; j++) {
                require(
                    newOwners[i] != newOwners[j],
                    "Duplicate owner"
                );
            }
        }
    
        // Verify signatures
        bytes32 recoveryHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVERY_TYPEHASH,
                    ownersHash,
                    recoveryNonce,
                    deadline,
                    address(this),
                    block.chainid
                )
            )
        );
    
        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_guardianConfig.guardians.length());
    
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _verifySignature(recoveryHash, signatures[i]);
            
            // Check 4: Guardian validity and non-duplicate
            if (_guardianConfig.guardians.contains(signer)) {
                bool isDuplicate;
                for (uint256 j = 0; j < validSignatures; j++) {
                    if (seenGuardians[j] == signer) {
                        isDuplicate = true;
                        break;
                    }
                }
                
                if (!isDuplicate) {
                    seenGuardians[validSignatures] = signer;
                    validSignatures++;
                    
                    if (validSignatures >= _guardianConfig.threshold) {
                        break;
                    }
                }
            }
        }
    
        require(
            validSignatures >= _guardianConfig.threshold,
            "Insufficient guardian approvals"
        );
    
        // Execute recovery
        _replaceOwners(newOwners);
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
        usedRecoveryNonces[msg.sender][recoveryNonce] = true;
    
        emit RecoveryExecuted(
            newOwners,
            ownersHash,
            recoveryNonce,
            block.chainid,
            msg.sender
        );
    }
    
    /* ========== UTILITY FUNCTIONS ========== */
    function _bytes4ToHexString(bytes4 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        
        bytes memory str = new bytes(10);
        str[0] = '0';
        str[1] = 'x';
        for (uint i = 0; i < 4; i++) {
            str[2+i*2] = alphabet[uint8(data[i] >> 4)];
            str[3+i*2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
    
    function _toHexString(address account) internal pure returns (string memory) {
        bytes20 value = bytes20(account);
        bytes memory alphabet = "0123456789abcdef";
        
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint8(value[i] >> 4)];
            str[3+i*2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }
    
    /* ========== GUARDIAN FUNCTIONS ========== */
    function addGuardian(address guardian) external virtual onlyOwner {
        require(!_guardianConfig.guardians.contains(guardian), "Already guardian");
        require(guardian != address(0), "Invalid guardian");
        _guardianConfig.guardians.add(guardian);
        emit GuardianAdded(guardian);
    }
    
    function removeGuardian(address guardian) external virtual onlyOwner {
        require(_guardianConfig.guardians.contains(guardian), 
            string(abi.encodePacked("CoreV55: Address 0x", _toHexString(guardian), " is not a guardian")));
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
        require(AddressUpgradeable.isContract(newImpl), "No code at implementation");
        
        // Version check dengan format yang ketat
        (bool success, bytes memory data) = newImpl.staticcall(
            abi.encodeWithSignature("VERSION()")
        );
        require(success && data.length > 0, "Version check failed");
        string memory versionStr = abi.decode(data, (string));
        require(bytes(versionStr).length == 3 && keccak256(bytes(versionStr)) == keccak256(bytes("5.5")), "Incompatible version");
        
        // ERC165 check untuk interface yang diperlukan
        (success, data) = newImpl.staticcall(
            abi.encodeWithSelector(
                IERC165Upgradeable.supportsInterface.selector,
                type(IUpgradable).interfaceId
            )
        );
        require(success && data.length > 0 && abi.decode(data, (bool)), "Missing IUpgradable interface");
        
        (success, data) = newImpl.staticcall(
            abi.encodeWithSelector(
                IERC165Upgradeable.supportsInterface.selector,
                type(IERC1967Upgradeable).interfaceId
            )
        );
        require(success && data.length > 0 && abi.decode(data, (bool)), "Missing IERC1967Upgradeable interface");
        
        // Tambahkan pengecekan storage layout (opsional)
        (success, data) = newImpl.staticcall(
            abi.encodeWithSelector(
                IERC165Upgradeable.supportsInterface.selector,
                type(IStorageCheck).interfaceId
            )
        );
        
        if (success && data.length > 0 && abi.decode(data, (bool))) {
            (success, data) = newImpl.staticcall(
                abi.encodeWithSelector(
                    IStorageCheck.isStorageCompatible.selector,
                    address(this)
                )
            );
            require(success && data.length > 0 && abi.decode(data, (bool)), "Storage layout mismatch");
        }
    }
    
    function executeUpgrade() external virtual onlyOwner whenNotLocked nonReentrant {
        require(pendingImplementation != address(0), "No pending upgrade");
        require(block.timestamp >= env.upgradeTimelock, "Timelock not expired");
        
        // Validasi ulang implementasi sebelum upgrade
        _validateImplementation(pendingImplementation);
    
        // Change this line:
        previousImplementation = _getImplementation(); // Now you can access it directly
        
        upgradeInProgress = true;
        upgradeFailureTimestamp = block.timestamp + ROLLBACK_WINDOW;
        
        // Change this line:
        _upgradeTo(pendingImplementation); // Now you can call it directly
        
        // Panggil initializeV2() dengan delegatecall terpisah
        (bool success,) = pendingImplementation.call(
            abi.encodeWithSignature("initializeV2()")
        );
        require(success, "Post-upgrade init failed");
    
        require(checkUpgradeHealth(), "Upgrade health check failed");
        
        emit UpgradeCompleted(pendingImplementation);
        pendingImplementation = address(0);
        upgradeInProgress = false;
    }
    
    function checkStorageConsistency() external view returns (bool) {
        return address(env.entryPoint) != address(0) &&
               _owners.length() > 0 &&
               _guardianConfig.guardians.length() > 0 &&
               keccak256(bytes(this.VERSION())) == keccak256(bytes("5.5"));
    }
    
    function checkUpgradeHealth() public returns (bool) {
        require(_owners.contains(msg.sender) || msg.sender == address(this), "Unauthorized");
        require(upgradeInProgress, "No upgrade in progress");
        
        bool isHealthy = true;
        
        try this.VERSION{gas: 50_000}() returns (string memory v) {
            isHealthy = keccak256(bytes(v)) == keccak256(bytes("5.5"));
        } catch {
            return false;
        }
        
        // 2. Validate critical functions if version check passed
        if (isHealthy) {
            isHealthy = _validateCriticalFunctions();
        }
        
        // 3. Check for invalid function calls
        if (isHealthy) {
            isHealthy = _checkInvalidFunctionResponse();
        }
        
        // 4. Verify storage consistency
        if (isHealthy) {
            try this.checkStorageConsistency{gas: 200_000}() returns (bool result) {
                isHealthy = result;
            } catch {
                isHealthy = false;
            }
        }
        
        emit UpgradeHealthChecked(isHealthy);
        return isHealthy;
    }
    
    function _validateCriticalFunctions() private returns (bool) {
        try this.validateUserOp{gas: 200_000}(
            UserOperation({
                sender: address(this),
                nonce: 0,
                initCode: "",
                callData: "",
                callGasLimit: 0,
                verificationGasLimit: 0,
                preVerificationGas: 0,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                paymasterAndData: "",
                signature: ""
            }),
            bytes32(0),
            0
        ) returns (uint256 validationData) {
            return validationData == 0;
        } catch {
            return false;
        }
    }
    
    function _checkInvalidFunctionResponse() private view returns (bool) {
        (bool success, bytes memory data) = address(this).staticcall{gas: 30_000}(
            abi.encodeWithSignature("nonExistentABC123XYZ()")
        );
        return !success && data.length == 0;
    }
    
    function rollbackUpgrade() external onlyOwner nonReentrant {
        require(previousImplementation != address(0), "No previous version");
        require(upgradeInProgress, "No upgrade in progress");
        require(block.timestamp <= upgradeFailureTimestamp + ROLLBACK_WINDOW, "Rollback window expired");
        require(AddressUpgradeable.isContract(previousImplementation), "Invalid previous impl");
        
        require(!checkUpgradeHealth(), "Current impl healthy");
        
        ERC1967UpgradeUpgradeable._upgradeTo(previousImplementation);
        require(ERC1967UpgradeUpgradeable._getImplementation() == previousImplementation, "Rollback failed");
        
        // Reset state
        (previousImplementation, upgradeInProgress, upgradeFailureTimestamp) = (address(0), false, 0);
        emit UpgradeRolledBack(previousImplementation);
    }
    
    function confirmUpgrade() external onlyOwner {
        require(upgradeInProgress, "No upgrade in progress");
        require(block.timestamp <= upgradeTimestamp + CONFIRM_WINDOW, "Confirmation expired");
        require(checkUpgradeHealth(), "Unhealthy upgrade");
        
        // Reset state
        (previousImplementation, upgradeInProgress, upgradeFailureTimestamp) = (address(0), false, 0);
        emit UpgradeConfirmed(ERC1967UpgradeUpgradeable._getImplementation());
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
    
        address signer = _verifySignature(lockHash, guardianSignature);
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

    /* ========== UUPS UPGRADE AUTHORIZATION ========== */
    function _authorizeUpgrade(address newImpl) 
        internal 
        override 
        onlyOwner 
        whenNotLocked 
    {
        require(AddressUpgradeable.isContract(newImpl), "No code at implementation");
        
        // Version check
        (bool success, bytes memory data) = newImpl.staticcall(
            abi.encodeWithSignature("VERSION()")
        );
        require(success && data.length > 0, "Version check failed");
        string memory versionStr = abi.decode(data, (string));
        require(keccak256(bytes(versionStr)) == keccak256(bytes("5.5")), "Version mismatch");
        
        // Storage compatibility check - use IERC165Upgradeable to check interface support
        if (IERC165Upgradeable(newImpl).supportsInterface(type(IStorageCheck).interfaceId)) {
            require(
                IStorageCheck(newImpl).isStorageCompatible(address(this)),
                "Storage layout mismatch"
            );
        }
        
        emit UpgradeAuthorized(newImpl);
    }

    /* ========== FALLBACK HANDLER ========== */
    fallback() external payable virtual nonReentrant {
        address plugin = _pluginSystem.selectorToPlugin[msg.sig];
        require(plugin != address(0), "Selector not registered");
        
        // Block dangerous selectors
        bytes4 selector = msg.sig;
        if (selector == 0x9e5faafc || selector == 0x71e4150e) {
            revert("Dangerous selector blocked");
        }
    
        // Lock state sebelum delegatecall
        bool wasLocked = env.isLocked;
        env.isLocked = true;
        
        (bool success, bytes memory result) = plugin.delegatecall(msg.data);
        
        // Restore lock state
        env.isLocked = wasLocked;
        
        emit PluginExecuted(plugin, msg.sig, msg.sender, msg.value);
    
        if (!success) {
            if (result.length > 0) {
                assembly { revert(add(result, 32), mload(result)) }
            }
            revert("PluginExecutionFailed");
        }
        
        assembly { return(add(result, 32), mload(result)) }
    }
    
    /* ========== RECEIVE EXTERNAL ========== */   
    receive() external payable virtual {
        emit ETHReceived(msg.sender, msg.value);
    }    

    /* ========== VIEW VIRTUAL FUNCTIONS ========== */
    function getOwners() external view returns (address[] memory) {
        EnumerableSetUpgradeable.AddressSet storage owners = _owners;
        uint256 length = owners.length();
        address[] memory result = new address[](length);
        
        for (uint256 i = 0; i < length; ) {
            result[i] = owners.at(i);
            unchecked { ++i; }
        }
        return result;
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
    
    function VERSION() external pure virtual returns (string memory) {
        return "5.5";
    }

    /* ========== STORAGE GAP ========== */
    uint256[100] private __gap;
}


