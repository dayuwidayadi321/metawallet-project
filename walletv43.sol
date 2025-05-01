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
 * @notice Smart wallet with enhanced security features including:
 * - Improved recovery system with guardian approvals
 * - Session key restrictions for critical functions
 * - Maximum owner limit protection
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
    uint256 public constant MAX_OWNERS = 10;

    // Recovery system (Enhanced with guardian approvals)
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian;
        mapping(address => bool) recoveryApprovals;
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
        address pendingNewOwner;
    }
    RecoveryConfig public recoveryConfig;

    // Session keys with function blacklist
    struct SessionKey {
        address key;
        uint48 validUntil;
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction;
    }
    mapping(address => SessionKey) public sessionKeys;

    // Blacklisted functions for session keys
    bytes4[] private _blacklistedFunctions;

    // Constants
    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // Events
    event WalletInitialized(address[] indexed owners, string name);
    event OwnershipUpdated(address[] newOwners);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);
    event RecoveryInitiated(address indexed by, address pendingNewOwner, uint256 timestamp);
    event RecoveryApproved(address indexed guardian);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners, address[] newGuardians);
    event SessionKeyAdded(address indexed key, uint48 validUntil, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);
    event GuardiansUpdated(address[] newGuardians);

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

    modifier onlyRecoveryApproved() {
        require(recoveryConfig.recoveryApprovals[msg.sender], "Not approved guardian");
        _;
        delete recoveryConfig.recoveryApprovals[msg.sender];
    }

    modifier notBlacklisted(bytes4 selector) {
        for (uint i = 0; i < _blacklistedFunctions.length; i++) {
            require(selector != _blacklistedFunctions[i], "Function is blacklisted");
        }
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
        
        // Initialize blacklisted functions
        _blacklistedFunctions.push(this.addOwner.selector);
        _blacklistedFunctions.push(this.removeOwner.selector);
        _blacklistedFunctions.push(this.upgradeTo.selector);
        _blacklistedFunctions.push(this.initiateRecovery.selector);
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
        require(_owners.length <= MAX_OWNERS, "Exceeds maximum owner limit");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "Invalid threshold");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;
        recoveryConfig.initiatedAt = 0;

        // Set owners with duplicate check
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            require(!owners[owner], "AdvancedSmartWallet: duplicate owner");
            owners[owner] = true;
            ownerList.push(owner);
        }
        ownerCount = _owners.length;

        // Set guardians with duplicate check
        recoveryConfig.guardians = _guardians;
        for (uint256 i = 0; i < _guardians.length; i++) {
            address guardian = _guardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            require(!recoveryConfig.isGuardian[guardian], "AdvancedSmartWallet: duplicate guardian");
            recoveryConfig.isGuardian[guardian] = true;
        }

        emit WalletInitialized(_owners, _name);
        emit OwnershipUpdated(_owners);
        emit GuardiansUpdated(_guardians);
    }

    // ========== EIP-4337 & Bundler Functions ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (!_validateSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (missingWalletFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingWalletFunds}("");
            require(success, "Failed to refund gas");
        }

        return 0;
    }

    // ========== Owner Management ========== //
    function addOwner(address newOwner) external onlyOwner {
        require(ownerCount < MAX_OWNERS, "Maximum owners reached");
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

    function getOwners() external view returns (address[] memory) {
        return ownerList;
    }

    // ========== Enhanced Recovery System ========== //
    function initiateRecovery(address _pendingNewOwner) external {
        require(recoveryConfig.isGuardian[msg.sender], "AdvancedSmartWallet: not guardian");
        require(_pendingNewOwner != address(0), "Invalid pending owner");
        
        recoveryConfig.initiatedAt = block.timestamp;
        recoveryConfig.pendingNewOwner = _pendingNewOwner;
        
        emit RecoveryInitiated(msg.sender, _pendingNewOwner, block.timestamp);
    }

    function approveRecovery() external {
        require(recoveryConfig.isGuardian[msg.sender], "AdvancedSmartWallet: not guardian");
        require(recoveryConfig.initiatedAt > 0, "Recovery not initiated");
        
        recoveryConfig.recoveryApprovals[msg.sender] = true;
        emit RecoveryApproved(msg.sender);
    }

    function cancelRecovery() external onlyOwner {
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        
        // Clear all approvals
        for (uint i = 0; i < recoveryConfig.guardians.length; i++) {
            delete recoveryConfig.recoveryApprovals[recoveryConfig.guardians[i]];
        }
        
        emit RecoveryCancelled();
    }

    function completeRecovery(address[] calldata newOwners, address[] calldata newGuardians) 
        external 
        onlyRecovery 
        onlyRecoveryApproved 
    {
        require(newOwners.length > 0 && newOwners.length <= MAX_OWNERS, "Invalid owner count");
        require(newGuardians.length >= recoveryConfig.threshold, "Insufficient guardians");
        require(
            newOwners.length == 1 && newOwners[0] == recoveryConfig.pendingNewOwner,
            "Recovery: Owner change must match pending owner"
        );

        // Clear current owners
        for (uint256 i = 0; i < ownerList.length; i++) {
            owners[ownerList[i]] = false;
        }
        delete ownerList;

        // Set new owner
        owners[newOwners[0]] = true;
        ownerList.push(newOwners[0]);
        ownerCount = 1;

        // Update guardians
        delete recoveryConfig.guardians;
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            require(!recoveryConfig.isGuardian[guardian], "AdvancedSmartWallet: duplicate guardian");
            recoveryConfig.guardians.push(guardian);
            recoveryConfig.isGuardian[guardian] = true;
        }

        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        
        emit RecoveryCompleted(newOwners, newGuardians);
        emit OwnershipUpdated(newOwners);
        emit GuardiansUpdated(newGuardians);
    }

    // ========== Recovery System View Functions ========== //
    function getGuardians() external view returns (address[] memory) {
        return recoveryConfig.guardians;
    }

    function isGuardian(address addr) external view returns (bool) {
        return recoveryConfig.isGuardian[addr];
    }

    function getRecoveryApprovals() external view returns (address[] memory) {
        address[] memory approved = new address[](recoveryConfig.guardians.length);
        uint count = 0;
        
        for (uint i = 0; i < recoveryConfig.guardians.length; i++) {
            if (recoveryConfig.recoveryApprovals[recoveryConfig.guardians[i]]) {
                approved[count] = recoveryConfig.guardians[i];
                count++;
            }
        }
        
        // Resize array to actual length
        address[] memory result = new address[](count);
        for (uint i = 0; i < count; i++) {
            result[i] = approved[i];
        }
        
        return result;
    }

    // ========== Guardian Management ========== //
    function updateGuardians(address[] calldata newGuardians, uint256 newThreshold) external onlyOwner {
        require(newThreshold > 0 && newThreshold <= newGuardians.length, "Invalid threshold");
        
        // Clear old guardians
        for (uint i = 0; i < recoveryConfig.guardians.length; i++) {
            delete recoveryConfig.isGuardian[recoveryConfig.guardians[i]];
        }
        
        // Set new guardians
        recoveryConfig.guardians = newGuardians;
        for (uint i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "Invalid guardian");
            require(!recoveryConfig.isGuardian[guardian], "Duplicate guardian");
            recoveryConfig.isGuardian[guardian] = true;
        }
        
        recoveryConfig.threshold = newThreshold;
        emit GuardiansUpdated(newGuardians);
    }

    // ========== Session Keys ========== //
    function addSessionKey(
        address _key,
        uint48 _validUntil,
        bytes4[] calldata _allowedFunctions
    ) external onlyOwner {
        require(_key != address(0), "Invalid session key");
        require(_validUntil > block.timestamp, "Expiration must be in future");

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.validUntil = _validUntil;
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            bytes4 selector = _allowedFunctions[i];
            require(!_isFunctionBlacklisted(selector), "Cannot allow blacklisted function");
            session.allowedFunctions.push(selector);
            session.isAllowedFunction[selector] = true;
        }

        emit SessionKeyAdded(_key, _validUntil, _allowedFunctions);
    }

    function revokeSessionKey(address _key) external onlyOwner {
        require(sessionKeys[_key].key != address(0), "Session key not found");
        delete sessionKeys[_key];
        emit SessionKeyRevoked(_key);
    }

    // ========== Deposit Management ========== //
    function addDeposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        entryPoint.depositTo{value: msg.value}(address(this));
        emit DepositReceived(msg.sender, msg.value);
    }

    function withdrawDeposit(address payable withdrawAddress, uint256 amount) 
        external 
        onlyOwner 
        nonReentrant 
    {
        uint256 currentBalance = entryPoint.balanceOf(address(this));
        require(currentBalance >= amount, "Insufficient deposit balance");
        
        try entryPoint.withdrawTo(withdrawAddress, amount) {
            emit DepositWithdrawn(withdrawAddress, amount);
        } catch Error(string memory reason) {
            revert(string(abi.encodePacked("Withdraw failed: ", reason)));
        } catch {
            revert("Withdraw failed without reason");
        }
    }

    function getDepositBalance() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    // ========== Internal Functions ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered] || _isValidSessionKey(recovered, hash);
    }

    function _isValidSessionKey(address key, bytes32 hash) internal view returns (bool) {
        SessionKey storage session = sessionKeys[key];
        bytes4 selector = bytes4(hash);
        return session.key != address(0) 
            && block.timestamp <= session.validUntil
            && session.isAllowedFunction[selector]
            && !_isFunctionBlacklisted(selector);
    }
    
    function _isFunctionBlacklisted(bytes4 selector) internal view returns (bool) {
        for (uint i = 0; i < _blacklistedFunctions.length; i++) {
            if (selector == _blacklistedFunctions[i]) {
                return true;
            }
        }
        return false;
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
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner 
    {
        emit UpgradePerformed(newImplementation);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }
}

/**
 * @title AdvancedSmartWalletFactory v4.3
 * @dev Factory for deploying AdvancedSmartWallet with UUPS proxy
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
        uint256 recoveryDelay
    ) external returns (address wallet) {
        require(owners.length <= 10, "Exceeds maximum owner limit");
        
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
        emit WalletCreated(wallet, owners, name);
    }

    function getWallets(address user) external view returns (address[] memory) {
        return _userWallets[user];
    }
}