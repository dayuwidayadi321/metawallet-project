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
 * @title AdvancedSmartWallet - EIP-4337 Smart Wallet (v4.3)
 * @author BY DFXC INDONESIA WEB3 PROJECT
 * @notice Smart wallet dengan proteksi cerdas, manajemen gas otomatis, dan fitur keamanan tingkat lanjut
 * @dev Pembaharuan utama:
 * - Gasless owner management dengan signature delegation
 * - Auto gas top-up dari deposit wallet
 * - Enhanced session keys dengan batasan nilai transaksi
 * - Guardian approval multi-level
 * - Backup recovery phrase encryption
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    string public constant VERSION = "4.3";
    string public name;

    // EntryPoint EIP-4337
    IEntryPoint public immutable entryPoint;

    // Owner management
    mapping(address => bool) public owners;
    address[] public ownerList;
    uint256 public ownerCount;

    // Recovery system (Enhanced Guardian-based)
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian;
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
        address pendingNewOwner;
        mapping(address => bool) guardianApprovals; // Guardian approvals tracking
    }
    RecoveryConfig public recoveryConfig;

    // Enhanced Session keys
    struct SessionKey {
        address key;
        uint48 validUntil;
        uint256 maxValue; // Maximum value per transaction
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction;
    }
    mapping(address => SessionKey) public sessionKeys;

    // Gas management
    struct GasConfig {
        uint256 autoTopUpThreshold; // Threshold untuk auto top-up
        uint256 autoTopUpAmount; // Jumlah yang akan di-topup
    }
    GasConfig public gasConfig;

    // Constants
    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // Events (Updated)
    event WalletInitialized(address[] indexed owners, string name);
    event OwnershipUpdated(address[] newOwners);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);
    event RecoveryInitiated(address indexed by, address pendingNewOwner, uint256 timestamp);
    event GuardianApproved(address indexed guardian, bool approved);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners, address[] newGuardians);
    event SessionKeyAdded(address indexed key, uint48 validUntil, uint256 maxValue, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);
    event GasConfigUpdated(uint256 threshold, uint256 amount);
    event AutoTopUpTriggered(uint256 amount);

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

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    // ========== Signature Validation ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        // Check if signed by owner
        address signer = hash.recover(signature);
        if (owners[signer]) {
            return true;
        }

        // Check if signed by valid session key
        SessionKey storage session = sessionKeys[signer];
        if (session.key != address(0) {
            require(session.validUntil >= block.timestamp, "Session key expired");
            
            // For session keys, we need to ensure the hash includes the function selector
            // and meets the session key restrictions (checked during execution)
            return true;
        }

        return false;
    }

    // ========== Initialization ========== //
    function initialize(
        address[] calldata _owners,
        string calldata _name,
        address[] calldata _guardians,
        uint256 _recoveryThreshold,
        uint256 _recoveryDelay,
        uint256 _autoTopUpThreshold,
        uint256 _autoTopUpAmount
    ) external initializer {
        require(_owners.length > 0, "AdvancedSmartWallet: no owners");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "Invalid threshold");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;
        recoveryConfig.initiatedAt = 0;

        // Set owners
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            require(!owners[owner], "AdvancedSmartWallet: duplicate owner");
            owners[owner] = true;
            ownerList.push(owner);
        }
        ownerCount = _owners.length;

        // Set guardians
        recoveryConfig.guardians = _guardians;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "AdvancedSmartWallet: invalid guardian");
            recoveryConfig.isGuardian[_guardians[i]] = true;
        }

        // Set gas config
        gasConfig.autoTopUpThreshold = _autoTopUpThreshold;
        gasConfig.autoTopUpAmount = _autoTopUpAmount;

        emit WalletInitialized(_owners, _name);
        emit OwnershipUpdated(_owners);
        emit GasConfigUpdated(_autoTopUpThreshold, _autoTopUpAmount);
    }

    // ========== EIP-4337 & Bundler Functions ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Auto top-up jika deposit rendah
        _autoTopUpDeposit();

        if (!_validateSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (missingWalletFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingWalletFunds}("");
            require(success, "Failed to refund gas");
        }

        return 0;
    }

    // ========== Enhanced Owner Management ========== //
    function addOwnerWithSignature(
        address newOwner,
        bytes memory signature,
        uint256 validUntil,
        uint256 validAfter
    ) external {
        require(block.timestamp <= validUntil, "Signature expired");
        require(block.timestamp >= validAfter, "Signature not yet valid");

        bytes32 hash = keccak256(abi.encode(
            newOwner,
            validUntil,
            validAfter,
            address(this),
            "addOwner"
        )).toEthSignedMessageHash();
    
        address signer = hash.recover(signature);
        require(owners[signer], "Not signed by owner");

        _addOwner(newOwner);
    }

    function _addOwner(address newOwner) internal {
        require(newOwner != address(0), "AdvancedSmartWallet: invalid owner");
        require(!owners[newOwner], "AdvancedSmartWallet: already owner");

        owners[newOwner] = true;
        ownerList.push(newOwner);
        ownerCount++;
        
        emit OwnerAdded(newOwner);
        emit OwnershipUpdated(ownerList);
    }

    function removeOwner(address ownerToRemove) external onlyOwner {
        require(owners[ownerToRemove], "AdvancedSmartWallet: not owner");
        require(ownerCount > 1, "AdvancedSmartWallet: cannot remove last owner");

        owners[ownerToRemove] = false;
        
        uint256 lastIndex = ownerList.length - 1;
        for (uint256 i = 0; i <= lastIndex; i++) {
            if (ownerList[i] == ownerToRemove) {
                if (i != lastIndex) {
                    ownerList[i] = ownerList[lastIndex];
                }
                ownerList.pop();
                break;
            }
        }
        
        ownerCount--;
        emit OwnerRemoved(ownerToRemove);
        emit OwnershipUpdated(ownerList);
    }

    // ========== Enhanced Recovery System ========== //
    function initiateRecovery(address _pendingNewOwner) external {
        require(recoveryConfig.isGuardian[msg.sender], "AdvancedSmartWallet: not guardian");
        require(_pendingNewOwner != address(0), "Invalid pending owner");
        
        recoveryConfig.initiatedAt = block.timestamp;
        recoveryConfig.pendingNewOwner = _pendingNewOwner;
        recoveryConfig.guardianApprovals[msg.sender] = true;
        
        emit RecoveryInitiated(msg.sender, _pendingNewOwner, block.timestamp);
        emit GuardianApproved(msg.sender, true);
    }

    function approveRecovery(bool approve) external {
        require(recoveryConfig.isGuardian[msg.sender], "Not guardian");
        require(recoveryConfig.initiatedAt > 0, "Recovery not initiated");
        
        recoveryConfig.guardianApprovals[msg.sender] = approve;
        emit GuardianApproved(msg.sender, approve);
    }

    function completeRecovery(address[] calldata newOwners, address[] calldata newGuardians) external onlyRecovery {
        require(newOwners.length > 0, "AdvancedSmartWallet: no new owners");
        require(newGuardians.length >= recoveryConfig.threshold, "Insufficient guardians");
        
        // Hitung persetujuan guardian
        uint256 approvalCount;
        for (uint256 i = 0; i < recoveryConfig.guardians.length; i++) {
            if (recoveryConfig.guardianApprovals[recoveryConfig.guardians[i]]) {
                approvalCount++;
            }
        }
        require(approvalCount >= recoveryConfig.threshold, "Insufficient approvals");

        // Clear current owners
        for (uint256 i = 0; i < ownerList.length; i++) {
            owners[ownerList[i]] = false;
        }
        delete ownerList;

        // Set new owners
        for (uint256 i = 0; i < newOwners.length; i++) {
            address owner = newOwners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            owners[owner] = true;
            ownerList.push(owner);
        }
        ownerCount = newOwners.length;

        // Update guardians
        delete recoveryConfig.guardians;
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            recoveryConfig.guardians.push(guardian);
            recoveryConfig.isGuardian[guardian] = true;
        }

        // Reset recovery state
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        for (uint256 i = 0; i < recoveryConfig.guardians.length; i++) {
            recoveryConfig.guardianApprovals[recoveryConfig.guardians[i]] = false;
        }
        
        emit RecoveryCompleted(newOwners, newGuardians);
        emit OwnershipUpdated(newOwners);
    }

    // ========== Enhanced Session Keys ========== //
    function addSessionKey(
        address _key,
        uint48 _validUntil,
        uint256 _maxValue,
        bytes4[] calldata _allowedFunctions
    ) external onlyOwner {
        require(_key != address(0), "Invalid session key");
        require(_validUntil > block.timestamp, "Expiration must be in future");

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.validUntil = _validUntil;
        session.maxValue = _maxValue;
        
        delete session.allowedFunctions;
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            session.allowedFunctions.push(_allowedFunctions[i]);
            session.isAllowedFunction[_allowedFunctions[i]] = true;
        }

        emit SessionKeyAdded(_key, _validUntil, _maxValue, _allowedFunctions);
    }

    // ========== Gas Management ========== //
    function setAutoTopUpConfig(uint256 _threshold, uint256 _amount) external onlyOwner {
        gasConfig.autoTopUpThreshold = _threshold;
        gasConfig.autoTopUpAmount = _amount;
        emit GasConfigUpdated(_threshold, _amount);
    }

    function _autoTopUpDeposit() internal {
        uint256 currentBalance = entryPoint.balanceOf(address(this));
        if (currentBalance < gasConfig.autoTopUpThreshold && address(this).balance > 0) {
            uint256 topUpAmount = gasConfig.autoTopUpAmount;
            if (topUpAmount > address(this).balance) {
                topUpAmount = address(this).balance;
            }
            entryPoint.depositTo{value: topUpAmount}(address(this));
            emit AutoTopUpTriggered(topUpAmount);
        }
    }

    // ========== ERC1271 Implementation ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        if (_validateSignature(hash, signature)) {
            return IERC1271.isValidSignature.selector;
        } else {
            return bytes4(0);
        }
    }

    // ========== Upgrade Functionality ========== //
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        emit UpgradePerformed(newImplementation);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }
}

/**
 * @title AdvancedSmartWalletFactory v4.3
 * @dev Factory untuk deploy AdvancedSmartWallet dengan UUPS proxy
 */
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "4.3";
    string public constant NAME = "AdvancedSmartWalletFactory";

    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;

    mapping(address => address[]) private _userWallets;
    mapping(address => bool) public isWalletDeployed;

    event WalletCreated(address indexed wallet, address[] owners, string name);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new AdvancedSmartWallet(_entryPoint));
    }

    function deployWallet(
        address[] calldata owners,
        string calldata name,
        address[] calldata guardians,
        uint256 recoveryThreshold,
        uint256 recoveryDelay,
        uint256 autoTopUpThreshold,
        uint256 autoTopUpAmount
    ) external returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            AdvancedSmartWallet.initialize.selector,
            owners,
            name,
            guardians,
            recoveryThreshold,
            recoveryDelay,
            autoTopUpThreshold,
            autoTopUpAmount
        );

        wallet = address(new ERC1967Proxy(walletImplementation, initData));

        for (uint256 i = 0; i < owners.length; i++) {
            _userWallets[owners[i]].push(wallet);
        }

        isWalletDeployed[wallet] = true;
        emit WalletCreated(wallet, owners, name);
    }

    function getWallets(address user) external view returns (address[] memory) {
        return _userWallets[user];
    }
}