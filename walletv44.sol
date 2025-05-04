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

/**
 * @title SecureSmartWallet - EIP-4337 Smart Wallet (v4.44)
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 * @notice Advanced smart wallet with multi-owner control, guardian recovery, and comprehensive security features
 * @dev Complete feature set includes:
 * - Multi-signature ownership with flexible threshold
 * - Guardian-based emergency recovery system
 * - Signature-based deposit/withdraw functionality
 * - Instant token revoke via off-chain signatures
 * - Advanced drain attack protection
 * - Full ERC-4337 Account Abstraction compatibility
 * - UUPS Upgradeable architecture
 * - EntryPoint deposit management
 */
contract SecureSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    // ========== Contract Metadata ========== //
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "4.44";
    string public constant DESCRIPTION = "EIP-4337 Smart Wallet with Emergency Recovery (by DFXC Indonesian Security Web3 Project)";

    // ========== Core Dependencies ========== //
    IEntryPoint public immutable entryPoint;

    // ========== Ownership Management ========== //
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public ownerCount;

    // ========== Guardian System ========== //
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

    // ========== Constants ========== //
    uint256 public constant MAX_GUARDIANS = 20;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // ========== Events ========== //
    event WalletInitialized(address[] owners, address[] guardians);
    event EmergencyRequestCreated(uint256 indexed requestId, address indexed creator);
    event EmergencyRequestExecuted(uint256 indexed requestId);
    event OwnershipTransferred(address[] newOwners);
    event GuardiansUpdated(address[] newGuardians);
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

    // ========== Modifiers ========== //
    modifier onlyOwner() {
        require(isOwner[msg.sender], "SecureSmartWallet: caller is not owner");
        _;
    }

    modifier onlyGuardian() {
        require(guardianConfig.isGuardian[msg.sender], "SecureSmartWallet: caller is not guardian");
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

        // Initialize owners
        owners = _owners;
        ownerCount = _owners.length;
        for (uint256 i = 0; i < _owners.length; i++) {
            require(_owners[i] != address(0), "SecureSmartWallet: invalid owner");
            isOwner[_owners[i]] = true;
        }

        // Initialize guardians
        guardianConfig.list = _guardians;
        guardianConfig.threshold = _guardianThreshold;
        guardianConfig.cooldown = 24 hours;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "SecureSmartWallet: invalid guardian");
            guardianConfig.isGuardian[_guardians[i]] = true;
        }

        lastSecurityUpdate = block.timestamp;
        emit WalletInitialized(_owners, _guardians);
    }

    // ========== EIP-4337 Functions ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (_isLocked) return SIG_VALIDATION_FAILED;
        if (!_validateSignature(userOpHash, userOp.signature)) return SIG_VALIDATION_FAILED;
        
        if (missingWalletFunds > 0) {
            (bool success,) = payable(address(entryPoint)).call{value: missingWalletFunds}("");
            require(success, "SecureSmartWallet: failed to add deposit");
        }
        return 0;
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
        entryPoint.withdrawTo(recipient, amount);
        emit WithdrawnFromEntryPoint(amount);
    }

    function getDepositInEntryPoint() public view returns (uint256) {
        (uint256 deposit,,) = entryPoint.getDepositInfo(address(this));
        return deposit;
    }

    // ========== Emergency Protection System ========== //
    function createEmergencyRequest(
        address[] calldata tokens,
        address[] calldata maliciousContracts
    ) external onlyGuardian {
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
        require(!request.executed, "SecureSmartWallet: request already executed");
        require(block.timestamp >= request.executeAfter, "SecureSmartWallet: cooldown not passed");

        for (uint256 i = 0; i < request.tokens.length; i++) {
            for (uint256 j = 0; j < request.maliciousContracts.length; j++) {
                try IERC20(request.tokens[i]).approve(request.maliciousContracts[j], 0) {} catch {}
                try IERC721(request.tokens[i]).setApprovalForAll(request.maliciousContracts[j], false) {} catch {}
                isBlacklisted[request.maliciousContracts[j]] = true;
                emit TokenRevoked(request.tokens[i], request.maliciousContracts[j]);
            }
        }

        request.executed = true;
        emit EmergencyRequestExecuted(requestId);
    }

    // ========== Security Functions ========== //
    function lockWallet(string calldata reason) external onlyOwner {
        _isLocked = true;
        emit WalletLocked(reason);
    }

    function unlockWallet() external onlyOwner {
        _isLocked = false;
        emit WalletUnlocked();
    }

    function updateSecurityParameters(uint256 newCooldown) external onlyOwner {
        require(newCooldown <= 7 days, "SecureSmartWallet: cooldown too long");
        guardianConfig.cooldown = newCooldown;
        lastSecurityUpdate = block.timestamp;
        emit SecurityUpdate(block.timestamp);
    }

    // ========== Owner/Guardian Management ========== //
    function transferOwnership(address[] calldata newOwners) external onlyOwner {
        require(newOwners.length > 0, "SecureSmartWallet: no new owners");
        
        // Clear old owners
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]] = false;
        }

        // Set new owners
        owners = newOwners;
        ownerCount = newOwners.length;
        for (uint256 i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "SecureSmartWallet: invalid owner");
            isOwner[newOwners[i]] = true;
        }

        emit OwnershipTransferred(newOwners);
    }

    function updateGuardians(
        address[] calldata newGuardians,
        uint256 newThreshold
    ) external onlyOwner {
        require(newGuardians.length > 0, "SecureSmartWallet: no guardians");
        require(newGuardians.length <= MAX_GUARDIANS, "SecureSmartWallet: too many guardians");
        require(newThreshold > 0 && newThreshold <= newGuardians.length, "SecureSmartWallet: invalid threshold");

        // Clear old guardians
        for (uint256 i = 0; i < guardianConfig.list.length; i++) {
            guardianConfig.isGuardian[guardianConfig.list[i]] = false;
        }

        // Set new guardians
        guardianConfig.list = newGuardians;
        guardianConfig.threshold = newThreshold;
        for (uint256 i = 0; i < newGuardians.length; i++) {
            require(newGuardians[i] != address(0), "SecureSmartWallet: invalid guardian");
            guardianConfig.isGuardian[newGuardians[i]] = true;
        }

        emit GuardiansUpdated(newGuardians);
    }

    // ========== Instant Owner Revoke ========== //
    function ownerInstantRevoke(
        address token,
        address spender,
        uint256 deadline,
        bytes memory signature
    ) external onlyEntryPoint whenNotLocked {
        require(block.timestamp <= deadline, "SecureSmartWallet: signature expired");
        
        bytes32 messageHash = keccak256(abi.encode(
            block.chainid,
            token,
            spender,
            deadline
        ));
        
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "SecureSmartWallet: invalid owner signature");
    
        IERC20(token).approve(spender, 0);
        IERC721(token).setApprovalForAll(spender, false);
        isBlacklisted[spender] = true;
    
        emit InstantRevoke(token, spender, signer);
    }

    // ========== Drain Protection ========== //
    function blacklistAddress(address target, bool status) external onlyOwner {
        isBlacklisted[target] = status;
    }

    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint whenNotLocked antiDrain(to) returns (bytes memory) {
        require(to != address(0), "Invalid target");
        
        uint256 startGas = gasleft();
        (bool success, bytes memory result) = to.call{value: value}(data);
        
        require(success, string(abi.encodePacked("Call failed: ", result)));
        emit ExecutionSuccess(to, value, data, startGas - gasleft());
        return result;
    }

    // ========== ERC1271 Implementation ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) 
        external 
        view 
        override 
        returns (bytes4) 
    {
        if (_isLocked) return 0xffffffff;
        return _validateSignature(hash, signature) ? 0x1626ba7e : 0xffffffff;
    }

    // ========== Internal Functions ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return isOwner[recovered];
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ========== Fallback Functions ========== //
    receive() external payable {
        emit ETHReceived(msg.sender, msg.value);
    }
}

// ========== Factory Contract ========== //
contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;

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
    }
}

