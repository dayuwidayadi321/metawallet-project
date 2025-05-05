// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@account-abstraction/contracts/interfaces/IStakeManager.sol";

/**
 * @title SecureSmartWallet - EIP-4337 Smart Wallet (v4.47 - Optimized)
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 * @notice Advanced smart wallet with multi-owner control, guardian recovery, and comprehensive security features
 * @dev Key improvements in v4.47:
 * - Fixed duplicate function issue
 * - Added owner duplication check
 * - Optimized gas usage with cached array lengths
 * - Standardized version references
 * - Enhanced event logging consistency
 */
contract SecureSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    // ========== Contract Metadata ========== //
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "4.47";
    string public constant DESCRIPTION = "EIP-4337 Smart Wallet with Emergency Recovery (v4.47)";

    // ========== Core Dependencies ========== //
    IEntryPoint public immutable entryPoint;

    // ========== Ownership Management ========== //
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public ownerCount;
    uint256 public constant MAX_OWNERS = 20;

    // ========== Enhanced Guardian System ========== //
    struct GuardianConfig {
        address[] list;
        mapping(address => bool) isGuardian;
        uint256 threshold;
        uint256 cooldown;
        uint256 nonce;
    }
    GuardianConfig public guardianConfig;

    // ========== Emergency Protection ========== //
    struct EmergencyRequest {
        address[] tokens;
        address[] maliciousContracts;
        uint256 executeAfter;
        bool executed;
    }
    mapping(uint256 => EmergencyRequest) public emergencyRequests;
    uint256 public emergencyRequestCount;

    // ========== Security State ========== //
    bool private _isLocked;
    uint256 public lastSecurityUpdate;
    mapping(address => bool) public isBlacklisted;

    // ========== Signature Management ========== //
    mapping(address => uint256) public depositNonces;
    mapping(address => uint256) public withdrawNonces;

    // ========== Upgrade Management ========== //
    address public pendingImplementation;
    uint256 public upgradeActivationTime;
    uint256 public constant UPGRADE_DELAY = 24 hours;

    // ========== Constants ========== //
    uint256 public constant MAX_GUARDIANS = 20;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // ========== Events ========== //
    event WalletInitialized(address[] owners, address[] guardians, uint256 guardianThreshold);
    event EmergencyRequestCreated(uint256 indexed requestId, address indexed creator);
    event EmergencyRequestExecuted(uint256 indexed requestId);
    event OwnershipTransferred(address[] newOwners);
    event OwnerStatusUpdated(address indexed owner, bool isActive);
    event GuardianStatusUpdated(address indexed guardian, bool isActive);
    event GuardiansUpdated(address[] newGuardians, uint256 newThreshold);
    event WalletLocked(string reason);
    event WalletUnlocked();
    event TokenRevoked(address indexed token, address indexed maliciousContract);
    event SecurityUpdate(uint256 timestamp);
    event InstantRevoke(address indexed token, address indexed spender, address indexed executor);
    event SuspiciousActivityDetected(address indexed target, uint256 value, bytes data);
    event ExecutionSuccess(address indexed to, uint256 value, bytes data, uint256 gasUsed);
    event DepositedWithSignature(address indexed depositor, uint256 amount, uint256 nonce);
    event WithdrawnWithSignature(address indexed recipient, uint256 amount, uint256 nonce);
    event DepositedToEntryPoint(uint256 amount);
    event WithdrawnFromEntryPoint(uint256 amount);
    event ETHReceived(address indexed sender, uint256 amount);
    event GuardianDetectionFixed(address indexed walletAddress);
    event UpgradeScheduled(address indexed newImplementation, uint256 activationTime);
    event UpgradeCompleted(address indexed newImplementation);
    event UpgradeCancelled(address indexed cancelledImplementation);

    // ========== Modifiers ========== //
    modifier onlyOwner() {
        require(isOwner[msg.sender], "SecureSmartWallet: caller is not owner");
        _;
    }

    modifier onlyGuardian() {
        require(
            guardianConfig.isGuardian[msg.sender] && 
            _isActiveGuardian(msg.sender),
            "SecureSmartWallet: caller is not an active guardian"
        );
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "SecureSmartWallet: not from EntryPoint");
        _;
    }

    modifier whenNotLocked() {
        require(!_isLocked, "SecureSmartWallet: wallet is locked");
        _;
    }

    modifier antiDrain(address target) {
        if (isBlacklisted[target]) {
            _isLocked = true;
            emit SuspiciousActivityDetected(target, 0, "");
            revert("Drain attempt detected");
        }
        _;
    }

    // ========== Constructor & Initializer ========== //
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) external initializer {
        require(_owners.length > 0, "SecureSmartWallet: no owners");
        require(_guardians.length > 0, "SecureSmartWallet: no guardians");
        require(_guardians.length <= MAX_GUARDIANS, "SecureSmartWallet: too many guardians");
        require(_guardianThreshold > 0 && _guardianThreshold <= _guardians.length, "SecureSmartWallet: invalid threshold");

        // Initialize owners with duplication check
        owners = _owners;
        ownerCount = _owners.length;
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "SecureSmartWallet: invalid owner");
            require(!isOwner[owner], "SecureSmartWallet: duplicate owner");
            isOwner[owner] = true;
            emit OwnerStatusUpdated(owner, true);
        }

        // Initialize guardians with enhanced validation
        guardianConfig.list = _guardians;
        guardianConfig.threshold = _guardianThreshold;
        guardianConfig.cooldown = 24 hours;
        
        for (uint256 i = 0; i < _guardians.length; i++) {
            address guardian = _guardians[i];
            require(guardian != address(0), "SecureSmartWallet: invalid guardian");
            require(!guardianConfig.isGuardian[guardian], "SecureSmartWallet: duplicate guardian");
            guardianConfig.isGuardian[guardian] = true;
            emit GuardianStatusUpdated(guardian, true);
        }

        lastSecurityUpdate = block.timestamp;
        emit WalletInitialized(_owners, _guardians, _guardianThreshold);
    }

    // ========== UUPS Upgrade Functions ========== //
    function scheduleUpgrade(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
        require(newImplementation != _getImplementation(), "Already at this version");
        require(pendingImplementation == address(0), "Upgrade already scheduled");

        pendingImplementation = newImplementation;
        upgradeActivationTime = block.timestamp + UPGRADE_DELAY;
        
        emit UpgradeScheduled(newImplementation, upgradeActivationTime);
    }

    function executeUpgrade() external onlyOwner {
        require(pendingImplementation != address(0), "No upgrade scheduled");
        require(block.timestamp >= upgradeActivationTime, "Upgrade delay not passed");
        
        address implementation = pendingImplementation;
        _upgradeTo(implementation);
        
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
        
        emit UpgradeCompleted(implementation);
    }

    function cancelUpgrade() external onlyOwner {
        require(pendingImplementation != address(0), "No upgrade scheduled");
        
        address cancelledImplementation = pendingImplementation;
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
        
        emit UpgradeCancelled(cancelledImplementation);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
        require(
            newImplementation == pendingImplementation && 
            block.timestamp >= upgradeActivationTime,
            "Upgrade not authorized or delay not passed"
        );
    }

    // ========== Enhanced Guardian Functions ========== //
    function updateGuardians(
        address[] calldata newGuardians,
        uint256 newThreshold
    ) external onlyOwner {
        require(newGuardians.length > 0, "SecureSmartWallet: no guardians");
        require(newGuardians.length <= MAX_GUARDIANS, "SecureSmartWallet: too many guardians");
        require(newThreshold > 0 && newThreshold <= newGuardians.length, "SecureSmartWallet: invalid threshold");

        // Clear all existing guardians
        uint256 guardiansLength = guardianConfig.list.length;
        for (uint256 i = 0; i < guardiansLength; i++) {
            address oldGuardian = guardianConfig.list[i];
            guardianConfig.isGuardian[oldGuardian] = false;
            emit GuardianStatusUpdated(oldGuardian, false);
        }

        // Set new guardians with validation
        guardianConfig.list = newGuardians;
        guardianConfig.threshold = newThreshold;
        
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "SecureSmartWallet: invalid guardian");
            require(!guardianConfig.isGuardian[guardian], "SecureSmartWallet: duplicate guardian");
            
            guardianConfig.isGuardian[guardian] = true;
            emit GuardianStatusUpdated(guardian, true);
        }

        emit GuardiansUpdated(newGuardians, newThreshold);
    }

    function _isActiveGuardian(address guardian) internal view returns (bool) {
        uint256 guardiansLength = guardianConfig.list.length;
        for (uint256 i = 0; i < guardiansLength; i++) {
            if (guardianConfig.list[i] == guardian) {
                return true;
            }
        }
        return false;
    }

    // ========== EIP-4337 Functions ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (_isLocked) return SIG_VALIDATION_FAILED;
        
        if (!_validateSignature(userOpHash, userOp.signature)) {
            if (!_validateGuardianSignature(userOpHash, userOp.signature)) {
                return SIG_VALIDATION_FAILED;
            }
        }
        
        if (missingWalletFunds > 0) {
            (bool success,) = payable(address(entryPoint)).call{value: missingWalletFunds}("");
            require(success, "SecureSmartWallet: failed to add deposit");
        }
        return 0;
    }

    // ========== Ownership Management ========== //
    function transferOwnership(
        address[] calldata newOwners
    ) external onlyOwner whenNotLocked {
        require(newOwners.length > 0, "No new owners");
        require(newOwners.length <= MAX_OWNERS, "Too many owners");
    
        // Clear old owners
        uint256 ownersLength = owners.length;
        for (uint256 i = 0; i < ownersLength; i++) {
            isOwner[owners[i]] = false;
            emit OwnerStatusUpdated(owners[i], false);
        }
    
        // Set new owners with checks
        owners = newOwners;
        ownerCount = newOwners.length;
        
        for (uint256 i = 0; i < newOwners.length; i++) {
            address newOwner = newOwners[i];
            require(newOwner != address(0), "Invalid owner address");
            require(!isOwner[newOwner], "Duplicate owner detected");
            isOwner[newOwner] = true;
            emit OwnerStatusUpdated(newOwner, true);
        }
    
        lastSecurityUpdate = block.timestamp;
        emit OwnershipTransferred(newOwners);
        emit SecurityUpdate(block.timestamp);
    }

    // ========== Security Functions ========== //
    function fixGuardianDetection() external onlyOwner {
        uint256 guardiansLength = guardianConfig.list.length;
        for (uint256 i = 0; i < guardiansLength; i++) {
            address guardian = guardianConfig.list[i];
            if (!guardianConfig.isGuardian[guardian]) {
                guardianConfig.isGuardian[guardian] = true;
                emit GuardianStatusUpdated(guardian, true);
            }
        }
        emit GuardianDetectionFixed(address(this));
    }

    // ========== Signature-Based Operations ========== //
    function depositWithSignature(
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external payable whenNotLocked {
        require(msg.value == amount, "Incorrect ETH amount");
        require(block.timestamp <= deadline, "Signature expired");
        
        bytes32 messageHash = keccak256(abi.encode(
            block.chainid,
            address(this),
            msg.sender,
            amount,
            depositNonces[msg.sender]++,
            deadline,
            "deposit"
        ));
        
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "Invalid owner signature");
    
        emit DepositedWithSignature(msg.sender, amount, depositNonces[msg.sender] - 1);
    }

    function withdrawWithSignature(
        address payable recipient,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external whenNotLocked {
        require(block.timestamp <= deadline, "Signature expired");
        require(address(this).balance >= amount, "Insufficient balance");
        
        bytes32 messageHash = keccak256(abi.encode(
            block.chainid,
            address(this),
            recipient,
            amount,
            withdrawNonces[msg.sender]++,
            deadline,
            "withdraw"
        ));
        
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "Invalid owner signature");
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit WithdrawnWithSignature(recipient, amount, withdrawNonces[msg.sender] - 1);
    }

    // ========== EntryPoint Management ========== //
    function depositToEntryPoint(uint256 amount) external payable onlyOwner {
        require(msg.value == amount, "Value mismatch");
        entryPoint.depositTo{value: amount}(address(this));
        emit DepositedToEntryPoint(amount);
    }

    function withdrawFromEntryPoint(address payable recipient, uint256 amount) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        entryPoint.withdrawTo(recipient, amount);
        emit WithdrawnFromEntryPoint(amount);
    }

    function getDepositInEntryPoint() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }
    
    // ========== Enhanced Target Validation ========== //
    function executeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner whenNotLocked nonReentrant antiDrain(target) returns (bytes memory) {
        // Layer 1: Null Check (Universal)
        _validateNotZeroAddress(target);
        
        // Layer 2: Security Checks
        _validateTargetSecurity(target);
        
        // Layer 3: Value Validation
        _validateValue(target, value);
        
        // Layer 4: Execution with Protection
        return _executeSafeCall(target, value, data);
    }
    
    // ========== Internal Validation Helpers ========== //
    function _validateNotZeroAddress(address addr) internal pure {
        require(addr != address(0), "SSW: Null address");
    }
    
    function _validateTargetSecurity(address target) internal view {
        require(!isBlacklisted[target], "SSW: Target blacklisted");
        
        // Check contract existence (EVM-specific)
        uint256 size;
        assembly {
            size := extcodesize(target)
        }
        require(size > 0, "SSW: Target has no code");
        
        // Additional chain-specific checks
        if (block.chainid == 137) { // Polygon
            require(!_isPotentialPhishingContract(target), "SSW: Suspicious contract");
        }
    }
    
    function _validateValue(address target, uint256 value) internal view {
        if (value > 0) {
            require(address(this).balance >= value, "SSW: Insufficient balance");
            require(!_isTokenContract(target), "SSW: Native transfers only");
        }
    }
    
    function _executeSafeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) internal returns (bytes memory) {
        (bool success, bytes memory result) = target.call{value: value}(data);
        
        if (!success) {
            _handleCallFailure(result);
        }
        
        emit ExecutionSuccess(target, value, data, gasleft());
        return result;
    }
    
    function _handleCallFailure(bytes memory result) internal pure {
        if (result.length > 0) {
            assembly {
                let returndata_size := mload(result)
                revert(add(32, result), returndata_size)
            }
        }
        revert("SSW: Call failed");
    }
    
    // ========== Security Helpers ========== //
    function _isTokenContract(address addr) internal view returns (bool) {
        // Check ERC20/ERC721 interface support
        bytes memory tokenSig = abi.encodeWithSignature("balanceOf(address)", address(this));
        (bool success,) = addr.staticcall(tokenSig);
        return success;
    }
    
    function _isPotentialPhishingContract(address addr) internal view returns (bool) {
        // Add custom checks for known attack patterns
        bytes memory maliciousSig = abi.encodeWithSignature("maliciousFunction()");
        (bool hasMalicious,) = addr.staticcall(maliciousSig);
        return hasMalicious;
    }

    // ========== Emergency Functions ========== //
    function createEmergencyRequest(
        address[] calldata tokens,
        address[] calldata maliciousContracts
    ) external onlyGuardian {
        require(tokens.length > 0, "No tokens specified");
        require(maliciousContracts.length > 0, "No contracts specified");
        require(tokens.length == maliciousContracts.length, "Array length mismatch");
    
        uint256 requestId = emergencyRequestCount++;
        emergencyRequests[requestId] = EmergencyRequest({
            tokens: tokens,
            maliciousContracts: maliciousContracts,
            executeAfter: block.timestamp + EMERGENCY_DELAY,
            executed: false
        });
    
        emit EmergencyRequestCreated(requestId, msg.sender);
    }

    function executeEmergencyRequest(uint256 requestId) external onlyGuardian {
        EmergencyRequest storage request = emergencyRequests[requestId];
        
        require(!request.executed, "Request already executed");
        require(block.timestamp >= request.executeAfter, "Cooldown not passed");
    
        for (uint256 i = 0; i < request.tokens.length; i++) {
            address token = request.tokens[i];
            address maliciousContract = request.maliciousContracts[i];
            
            try IERC20(token).approve(maliciousContract, 0) {} catch {}
            try IERC721(token).setApprovalForAll(maliciousContract, false) {} catch {}
            
            isBlacklisted[maliciousContract] = true;
            emit TokenRevoked(token, maliciousContract);
        }
    
        request.executed = true;
        emit EmergencyRequestExecuted(requestId);
    }

    // ========== Wallet Lock/Unlock ========== //
    function lockWallet(string calldata reason) external onlyOwner {
        require(!_isLocked, "Wallet already locked");
        _isLocked = true;
        lastSecurityUpdate = block.timestamp;
        emit WalletLocked(reason);
        emit SecurityUpdate(block.timestamp);
    }
    
    function unlockWallet() external onlyOwner {
        require(_isLocked, "Wallet not locked");
        _isLocked = false;
        lastSecurityUpdate = block.timestamp;
        emit WalletUnlocked();
        emit SecurityUpdate(block.timestamp);
    }

    // ========== Security Management ========== //
    function blacklistAddress(address target, bool status) external onlyOwner {
        require(target != address(0), "Invalid target address");
        require(target != address(this), "Cannot blacklist self");
        isBlacklisted[target] = status;
        lastSecurityUpdate = block.timestamp;
        emit SecurityUpdate(block.timestamp);
    }

    // ========== ERC-1271 Compliance ========== //
    function isValidSignature(
        bytes32 hash, 
        bytes memory signature
    ) external view override returns (bytes4) {
        if (_isLocked) return bytes4(0xffffffff);
        return (_validateSignature(hash, signature) || 
                _validateGuardianSignature(hash, signature))
            ? bytes4(0x1626ba7e)
            : bytes4(0xffffffff);
    }

    // ========== Internal Functions ========== //
    function _validateSignature(
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        return isOwner[hash.recover(signature)];
    }

    function _validateGuardianSignature(
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return guardianConfig.isGuardian[recovered] && _isActiveGuardian(recovered);
    }

    // ========== Fallback & Receive ========== //
    receive() external payable {
        emit ETHReceived(msg.sender, msg.value);
    }
}

// ========== Factory Contract ========== //
contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;

    event WalletDeployed(address indexed wallet, address[] owners, address[] guardians, uint256 threshold);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new SecureSmartWallet(_entryPoint));
    }

    function deployWallet(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 guardianThreshold
    ) external returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            SecureSmartWallet.initialize.selector,
            owners,
            guardians,
            guardianThreshold
        );
        wallet = address(new ERC1967Proxy(walletImplementation, initData));
        emit WalletDeployed(wallet, owners, guardians, guardianThreshold);
    }
}