// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/MessageHashUtilsUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title SecureSmartWallet - EIP-4337 Smart Wallet (v4.47 - Optimized)
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 * @notice Advanced smart wallet with multi-owner control, guardian recovery, and comprehensive security features
 */
contract SecureSmartWallet is 
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IERC1271Upgradeable
{
    using ECDSAUpgradeable for bytes32;
    using MessageHashUtilsUpgradeable for bytes32;
    using ERC1967Utils for address;

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
    event ExecutionSuccess(address indexed to, uint256 value, bytes data, uint256 gasUsed);
    event DepositedWithSignature(address indexed depositor, uint256 amount, uint256 nonce);
    event WithdrawnWithSignature(address indexed recipient, uint256 amount, uint256 nonce);
    event DepositedToEntryPoint(uint256 amount);
    event WithdrawnFromEntryPoint(uint256 amount);
    event ETHReceived(address indexed sender, uint256 amount);
    event UpgradeScheduled(address indexed newImplementation, uint256 activationTime);
    event UpgradeCompleted(address indexed newImplementation);
    event UpgradeCancelled(address indexed cancelledImplementation);
    event SuspiciousActivityDetected(address indexed target, uint256 value, bytes data);

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
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
    
        require(_owners.length > 0, "SecureSmartWallet: no owners");
        require(_guardians.length > 0, "SecureSmartWallet: no guardians");
        require(_guardians.length <= MAX_GUARDIANS, "SecureSmartWallet: too many guardians");
        require(_guardianThreshold > 0 && _guardianThreshold <= _guardians.length, "SecureSmartWallet: invalid threshold");
    
        // Initialize owners
        owners = _owners;
        ownerCount = _owners.length;
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "SecureSmartWallet: invalid owner");
            require(!isOwner[owner], "SecureSmartWallet: duplicate owner");
            isOwner[owner] = true;
            emit OwnerStatusUpdated(owner, true);
        }
    }

        // Initialize guardians
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
        require(newImplementation != address(0), "Invalid implementation");
        pendingImplementation = newImplementation;
        upgradeActivationTime = block.timestamp + UPGRADE_DELAY;
        emit UpgradeScheduled(newImplementation, upgradeActivationTime);
    }

    function executeUpgrade() external onlyOwner {
        require(pendingImplementation != address(0), "No upgrade scheduled");
        require(block.timestamp >= upgradeActivationTime, "Upgrade delay not passed");
        
        address implementation = pendingImplementation;
        
        // Perform the upgrade - menggunakan msg.sender sebagai owner
        implementation.upgradeToAndCall(
            abi.encodeWithSignature(
                "initialize(address[],address[],uint256,address)", 
                owners, 
                guardianConfig.list, 
                guardianConfig.threshold, 
                msg.sender  // Menggunakan msg.sender sebagai owner
            )
        );
        
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

    // Fungsi wajib UUPS
    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ========== Enhanced Guardian Functions ========== //
    function updateGuardians(
        address[] calldata newGuardians,
        uint256 newThreshold
    ) external onlyOwner {
        require(newGuardians.length > 0, "SecureSmartWallet: no guardians");
        require(newGuardians.length <= MAX_GUARDIANS, "SecureSmartWallet: too many guardians");
        require(newThreshold > 0 && newThreshold <= newGuardians.length, "SecureSmartWallet: invalid threshold");

        // Clear existing guardians
        for (uint256 i = 0; i < guardianConfig.list.length; i++) {
            address oldGuardian = guardianConfig.list[i];
            guardianConfig.isGuardian[oldGuardian] = false;
            emit GuardianStatusUpdated(oldGuardian, false);
        }

        // Set new guardians
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
        for (uint256 i = 0; i < guardianConfig.list.length; i++) {
            if (guardianConfig.list[i] == guardian) {
                return true;
            }
        }
        return false;
    }

    // ========== Ownership Management ========== //
    function transferOwnership(address[] calldata newOwners) external onlyOwner whenNotLocked {
        require(newOwners.length > 0, "No new owners");
        require(newOwners.length <= MAX_OWNERS, "Too many owners");
    
        // Clear old owners
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]] = false;
            emit OwnerStatusUpdated(owners[i], false);
        }
    
        // Set new owners
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

    function blacklistAddress(address target, bool status) external onlyOwner {
        require(target != address(0), "Invalid target address");
        require(target != address(this), "Cannot blacklist self");
        isBlacklisted[target] = status;
        lastSecurityUpdate = block.timestamp;
        emit SecurityUpdate(block.timestamp);
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
            
            try IERC20Upgradeable(token).approve(maliciousContract, 0) {} catch {}
            try IERC721Upgradeable(token).setApprovalForAll(maliciousContract, false) {} catch {}
            
            isBlacklisted[maliciousContract] = true;
            emit TokenRevoked(token, maliciousContract);
        }
    
        request.executed = true;
        emit EmergencyRequestExecuted(requestId);
    }

    // ========== Execution Functions ========== //
    function executeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner whenNotLocked nonReentrant antiDrain(target) returns (bytes memory) {
        require(target != address(0), "SSW: Null address");
        require(!isBlacklisted[target], "SSW: Target blacklisted");
        
        // Check contract existence
        uint256 size;
        assembly {
            size := extcodesize(target)
        }
        require(size > 0, "SSW: Target has no code");
        
        if (value > 0) {
            require(address(this).balance >= value, "SSW: Insufficient balance");
        }

        (bool success, bytes memory result) = target.call{value: value}(data);
        
        if (!success) {
            if (result.length > 0) {
                assembly {
                    let returndata_size := mload(result)
                    revert(add(32, result), returndata_size)
                }
            }
            revert("SSW: Call failed");
        }
        
        emit ExecutionSuccess(target, value, data, gasleft());
        return result;
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
        
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(messageHash);
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
        
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(messageHash);
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

    // ========== ERC-1271 Compliance ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        if (_isLocked) return bytes4(0xffffffff);
        return (_validateSignature(hash, signature) || _validateGuardianSignature(hash, signature))
            ? bytes4(0x1626ba7e)
            : bytes4(0xffffffff);
    }

    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return isOwner[hash.recover(signature)];
    }

    function _validateGuardianSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
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
        uint256 guardianThreshold,
        address initialOwner
    ) external returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            SecureSmartWallet.initialize.selector,
            owners,
            guardians,
            guardianThreshold,
            initialOwner
        );
        wallet = address(new ERC1967Proxy(walletImplementation, initData));
        emit WalletDeployed(wallet, owners, guardians, guardianThreshold);
    }
}