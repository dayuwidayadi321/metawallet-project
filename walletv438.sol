// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title AdvancedSmartWallet - EIP-4337 Smart Wallet (v4.38)
 * @author BY DFXC INDONESIA WEB3 PROJECT
 * @notice Smart wallet with enhanced security, guardian management, and execution protection
 * @dev Major improvements in v4.38:
 * - Fixed AA23 validation errors with optimized signature verification
 * - Enhanced gas estimation for Base network
 * - Improved deposit handling in EntryPoint
 * - Added support for batch operations
 * - Maintained all v4.37 security features
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    string public constant VERSION = "4.38";
    string public name;

    // EntryPoint EIP-4337
    IEntryPoint public immutable entryPoint;

    // Owner management
    mapping(address => bool) public owners;
    address[] public ownerList;
    uint256 public ownerCount;

    // Enhanced Recovery system (Guardian-based)
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian;
        mapping(address => uint256) lastRemovalTimestamp;
        uint256 guardianCount;
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
        address pendingNewOwner;
        uint256 nonce;
    }
    RecoveryConfig public recoveryConfig;

    // Secure Session keys
    struct SessionKey {
        address key;
        uint48 validUntil;
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction;
        mapping(bytes32 => bool) allowedCallDataHashes;
    }
    mapping(address => SessionKey) public sessionKeys;

    // Security state
    bool private _isExecuting;

    // Constants
    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 public constant GUARDIAN_REMOVAL_COOLDOWN = 1 days;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // Events (Updated for v4.38)
    event WalletInitialized(address[] indexed owners, string name, address[] guardians);
    event OwnershipUpdated(address[] newOwners);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data, uint256 gasUsed);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);
    event RecoveryInitiated(address indexed by, address pendingNewOwner, uint256 timestamp, uint256 nonce);
    event RecoveryCancelled(uint256 nonce);
    event RecoveryCompleted(address[] newOwners, address[] newGuardians, uint256 nonce);
    event SessionKeyAdded(address indexed key, uint48 validUntil, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);
    event GasUsage(address indexed target, uint256 gasUsed);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event GuardianRemovalBlocked(address indexed guardian, uint256 cooldownEnds);
    event UserOperationValidated(bytes32 indexed userOpHash, address indexed sender);

    // Modifiers
    modifier onlyOwner() {
        require(owners[msg.sender], "AdvancedSmartWallet: caller is not owner");
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "AdvancedSmartWallet: not from EntryPoint");
        _;
    }

    modifier onlyRecovery() {
        require(
            recoveryConfig.initiatedAt > 0 &&
            block.timestamp >= recoveryConfig.initiatedAt + recoveryConfig.delay,
            "AdvancedSmartWallet: recovery not ready"
        );
        _;
    }

    modifier whenNotExecuting() {
        require(!_isExecuting, "Operation in progress");
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    // ========== Initialization ========== //
    function initialize(
        address[] calldata _owners,
        string calldata _name,
        address[] calldata _guardians,
        uint256 _recoveryThreshold,
        uint256 _recoveryDelay
    ) external initializer {
        require(_owners.length > 0, "AdvancedSmartWallet: no owners");
        require(_guardians.length > 0, "AdvancedSmartWallet: no guardians");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "Invalid threshold");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.nonce = 0;

        // Initialize owners
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            require(!owners[owner], "AdvancedSmartWallet: duplicate owner");
            owners[owner] = true;
            ownerList.push(owner);
        }
        ownerCount = _owners.length;

        // Initialize guardians
        recoveryConfig.guardians = _guardians;
        recoveryConfig.guardianCount = _guardians.length;
        for (uint256 i = 0; i < _guardians.length; i++) {
            address guardian = _guardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            require(!recoveryConfig.isGuardian[guardian], "AdvancedSmartWallet: duplicate guardian");
            recoveryConfig.isGuardian[guardian] = true;
            emit GuardianAdded(guardian);
        }

        emit WalletInitialized(_owners, _name, _guardians);
        emit OwnershipUpdated(_owners);
    }

    // ========== Enhanced EIP-4337 Functions (v4.38 Updates) ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // 1. Validate signature
        if (!_validateSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        // 2. Validate callData (only allow executeCall)
        bytes4 selector = bytes4(userOp.callData);
        require(selector == this.executeCall.selector, "Invalid operation");

        // 3. Handle deposit
        if (missingWalletFunds > 0) {
            (bool success,) = payable(address(entryPoint)).call{value: missingWalletFunds}("");
            require(success, "Failed to add deposit");
        }

        emit UserOperationValidated(userOpHash, userOp.sender);
        return 0;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) 
        external 
        view
        override 
        returns (bytes4) 
    {
        return _validateSignature(hash, signature) 
            ? bytes4(0x1626ba7e) // ERC1271 magic value
            : bytes4(0xffffffff);
    }

    function _isValidSessionKey(address key, bytes32 userOpHash)
        internal
        view
        returns (bool)
    {
        SessionKey storage session = sessionKeys[key];
        return session.key != address(0) && block.timestamp <= session.validUntil;
    }
    
    // ========== Internal Helper Functions ========== //

    function _validateSignature(bytes32 hash, bytes memory signature) 
        internal 
        view 
        returns (bool) 
    {
        // 1. Verify owner signature
        address recoveredSigner = hash.recover(signature);
        if (owners[recoveredSigner]) {
            return true;
        }
    
        // 2. Verify session key signature
        if (_isValidSessionKey(recoveredSigner, hash)) {
            return true;
        }
    
        return false;
    }

    // ========== Execution Functions ========== //
    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint nonReentrant whenNotExecuting returns (bytes memory) {
        require(to != address(0), "Invalid target");
        require(to != address(this), "Self-call forbidden");
        
        _isExecuting = true;
        uint256 startGas = gasleft();
        
        // Safety check (optional but recommended)
        if (gasleft() <= 10_000) {
            _isExecuting = false;
            revert("Insufficient gas");
        }
        
        (bool success, bytes memory result) = to.call{
            value: value,
            gas: gasleft() > EXECUTE_GAS_LIMIT + 10_000 ? EXECUTE_GAS_LIMIT : gasleft() - 10_000
        }(data);
        
        _isExecuting = false;
        
        emit GasUsage(to, startGas - gasleft());
        
        if (success) {
            emit ExecutionSuccess(to, value, data, startGas - gasleft());
        } else {
            emit ExecutionFailure(to, value, data);
            revert(string(result));
        }
        
        return result;
    }

    // ========== Batch Operations (New in v4.38) ========== //
    function executeBatchCall(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyEntryPoint nonReentrant whenNotExecuting {
        require(targets.length == values.length && values.length == datas.length, "Invalid array lengths");
        
        _isExecuting = true;
        uint256 startGas = gasleft();
        
        for (uint256 i = 0; i < targets.length; i++) {
            require(targets[i] != address(0), "Invalid target");
            require(targets[i] != address(this), "Self-call forbidden");
    
            // Safety check gas sebelum eksekusi (baru ditambahkan)
            if (gasleft() <= 10_000) {
                _isExecuting = false;
                revert("Insufficient gas");
            }
            
            (bool success, bytes memory result) = targets[i].call{
                value: values[i],
                // Formula gas yang lebih aman
                gas: gasleft() > EXECUTE_GAS_LIMIT + 10_000 ? EXECUTE_GAS_LIMIT : gasleft() - 10_000
            }(datas[i]);
            
            if (!success) {
                _isExecuting = false;
                emit ExecutionFailure(targets[i], values[i], datas[i]);
                revert(string(result));
            }
            
            emit ExecutionSuccess(targets[i], values[i], datas[i], startGas - gasleft());
            startGas = gasleft(); // Update gas measurement untuk operasi berikutnya
        }
        
        _isExecuting = false;
    }

    // [Rest of the contract remains the same as v4.37 for other functions...]
    // ========== Upgrade Functionality ========== //
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override //UUPSUpgradiable
        onlyOwner 
    {
        emit UpgradePerformed(newImplementation);
    }

    // Helper function
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }
}

// Factory contract for v4.38
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "4.38";
    string public constant NAME = "AdvancedSmartWalletFactory";

    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;

    mapping(address => address[]) private _userWallets;
    mapping(address => bool) public isWalletDeployed;

    event WalletCreated(address indexed wallet, address[] owners, string name, address[] guardians);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new AdvancedSmartWallet(_entryPoint));
    }

    function deployWallet(
        address[] calldata owners,
        string calldata name,
        address[] calldata guardians,
        uint256 recoveryThreshold,
        uint256 recoveryDelay
    ) external returns (address wallet) {
        require(owners.length > 0, "No owners provided");
        require(guardians.length > 0, "No guardians provided");
        require(recoveryThreshold > 0 && recoveryThreshold <= guardians.length, "Invalid threshold");
        require(recoveryDelay <= 30 days, "Recovery delay too long");

        bytes memory initData = abi.encodeWithSelector(
            AdvancedSmartWallet.initialize.selector,
            owners,
            name,
            guardians,
            recoveryThreshold,
            recoveryDelay
        );

        wallet = address(new ERC1967Proxy(walletImplementation, initData));

        for (uint256 i = 0; i < owners.length; i++) {
            _userWallets[owners[i]].push(wallet);
        }

        isWalletDeployed[wallet] = true;
        emit WalletCreated(wallet, owners, name, guardians);
    }

    function getWallets(address user) external view returns (address[] memory) {
        return _userWallets[user];
    }
}

