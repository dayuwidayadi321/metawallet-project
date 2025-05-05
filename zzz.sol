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
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title SecureSmartWallet - EIP-4337 Smart Wallet (v4.48 - Ultimate Edition)
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 * @notice Advanced smart wallet with multi-owner control, guardian recovery, and comprehensive security features
 * @dev Now with enhanced off-chain signing support and delayed execution
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
    string public constant VERSION = "4.48";
    string public constant DESCRIPTION = "EIP-4337 Smart Wallet with Emergency Recovery (v4.48)";

    // ========== Core Dependencies ========== //
    IEntryPoint public immutable entryPoint;
    
    // ========== Multi-Chain Support ========== //
    uint256 public immutable CHAIN_ID;
    mapping(address => uint256) public userNonces;

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

    // ========== Off-Chain Signing Support ========== //
    struct PendingOperation {
        bytes32 opHash;
        address initiator;
        uint256 executeAfter;
        bool executed;
        bytes callData;
    }
    mapping(bytes32 => PendingOperation) public pendingOperations;
    uint256 public operationNonce;
    uint256 public constant DEFAULT_DELAY = 1 hours;

    // ========== Security State ========== //
    bool private _isLocked;
    uint256 public lastSecurityUpdate;
    mapping(address => bool) public isBlacklisted;

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
    event OperationScheduled(bytes32 indexed opHash, address indexed initiator, uint256 executeAfter);
    event OperationExecuted(bytes32 indexed opHash);
    event OperationCancelled(bytes32 indexed opHash);
    event OffChainSigned(bytes32 indexed messageHash, address indexed signer);
    event NonceUsed(address indexed user, uint256 nonce, bytes32 indexed operationHash);
    event TokenRevokeFailed(address indexed token, address indexed contract, string reason);

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
        CHAIN_ID = block.chainid;
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

    // ========== v4.48 NEW FEATURES ========== //

    /**
     * @notice Schedule an operation with off-chain signature and delayed execution
     * @dev Supports both owner and guardian signatures
     * @param messageHash The hash of the operation details
     * @param signature The off-chain signature
     * @param callData The encoded function call
     * @param delay The execution delay in seconds
     */
    function scheduleOperation(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory callData,
        uint256 delay
    ) external onlyEntryPoint returns (bytes32 opHash) {
        require(delay >= 1 hours, "Delay too short");
        
        // Verify the off-chain signature
        address signer = _verifyOffchainSignature(messageHash, signature);
        require(isOwner[signer] || 
               (guardianConfig.isGuardian[signer] && _isActiveGuardian(signer)), 
               "Invalid signer");

        opHash = keccak256(abi.encodePacked(messageHash, operationNonce++));
        pendingOperations[opHash] = PendingOperation({
            opHash: opHash,
            initiator: signer,
            executeAfter: block.timestamp + delay,
            executed: false,
            callData: callData
        });

        emit OperationScheduled(opHash, signer, block.timestamp + delay);
        emit OffChainSigned(messageHash, signer);
    }

    /**
     * @notice Execute a scheduled operation after the delay period
     * @param opHash The hash of the scheduled operation
     */
    function executeScheduledOperation(bytes32 opHash) external nonReentrant {
        PendingOperation storage operation = pendingOperations[opHash];
        require(operation.opHash == opHash, "Operation not found");
        require(!operation.executed, "Operation already executed");
        require(block.timestamp >= operation.executeAfter, "Delay not passed");
    
        operation.executed = true;
        emit OperationExecuted(opHash);
    
        (bool success, ) = address(this).call(operation.callData);
        require(success, "Execution failed");
    }

    /**
     * @notice Cancel a scheduled operation (only owner or initiator)
     * @param opHash The hash of the scheduled operation
     */
    function cancelOperation(bytes32 opHash) external {
        PendingOperation storage operation = pendingOperations[opHash];
        require(operation.opHash == opHash, "Operation not found");
        require(!operation.executed, "Operation already executed");
        require(msg.sender == operation.initiator || isOwner[msg.sender], "Not authorized");

        delete pendingOperations[opHash];
        emit OperationCancelled(opHash);
    }

    // ========== Enhanced Security Functions ========== //

    /**
     * @notice Verify an off-chain signature
     * @dev Supports both EOA and contract signatures (ERC-1271)
     * @param messageHash The hash of the signed message
     * @param signature The signature to verify
     * @return signer The address of the signer
     */
    function _verifyOffchainSignature(
        bytes32 messageHash,
        bytes memory signature
    ) internal view returns (address signer) {
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(messageHash);
        signer = ethSignedMessageHash.recover(signature);
        
        // For contract signatures
        if (signer.code.length > 0) {
            require(
                IERC1271Upgradeable(signer).isValidSignature(messageHash, signature) == 0x1626ba7e,
                "Invalid contract signature"
            );
        }
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
        _upgradeToAndCallUUPS(
            implementation,
            abi.encodeWithSignature(
                "migrate(address[],address[],uint256)", 
                owners, 
                guardianConfig.list, 
                guardianConfig.threshold
            ),
            false
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

    // ========== EIP-4337 Multi Functions v4.48 ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        // 1. Cek status kunci wallet
        if (_isLocked) {
            return SIG_VALIDATION_FAILED;
        }
    
        // 2. Handle deposit gas ke EntryPoint jika diperlukan
        if (missingWalletFunds > 0) {
            (bool success,) = payable(address(entryPoint)).call{value: missingWalletFunds}("");
            require(success, "Failed to deposit gas");
        }
    
        // 3. Validasi khusus untuk operasi terjadwal
        if (bytes4(userOp.callData) == this.executeScheduledOperation.selector) {
            (, bytes32 opHash) = abi.decode(userOp.callData[4:], (bytes32));
            PendingOperation storage op = pendingOperations[opHash];
            
            if (op.executed || block.timestamp < op.executeAfter) {
                return _packValidationData(true, 0, 0);
            }
            return _packValidationData(false, 0, 0);
        }
    
        // 4. Validasi signature utama
        address recovered = userOpHash.recover(userOp.signature);
        bool isValidOwner = isOwner[recovered];
        bool isValidGuardian = guardianConfig.isGuardian[recovered] && _isActiveGuardian(recovered);
    
        // 5. Handle ERC-1271 contract signatures
        if (!isValidOwner && !isValidGuardian && recovered.code.length > 0) {
            try IERC1271Upgradeable(recovered).isValidSignature(userOpHash, userOp.signature) returns (bytes4 magicValue) {
                isValidOwner = (magicValue == 0x1626ba7e);
            } catch {}
        }
    
        // 6. Pack validation data sesuai standar ERC-4337
        if (!isValidOwner && !isValidGuardian) {
            return _packValidationData(true, 0, 0);
        }
    
        // 7. Validasi waktu (validAfter/validUntil)
        uint48 validAfter = 0;
        uint48 validUntil = type(uint48).max;
        
        if (userOp.validAfter > 0) {
            validAfter = uint48(userOp.validAfter);
            require(block.timestamp >= validAfter, "Not valid yet");
        }
        
        if (userOp.validUntil > 0) {
            validUntil = uint48(userOp.validUntil);
            require(block.timestamp <= validUntil, "Expired");
        }
    
        return _packValidationData(false, validAfter, validUntil);
    }
    
    // Helper function untuk pack validation data
    function _packValidationData(bool sigFailed, uint48 validAfter, uint48 validUntil) 
        internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validAfter) << 160) | (uint256(validUntil) << (160 + 48));
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

    // ========== Emergency Functions (v4.48)========== //
    function createEmergencyRequest(
        address[] calldata tokens,
        address[] calldata maliciousContracts
    ) external onlyGuardian {
        // Input validation
        require(tokens.length > 0, "SecureSmartWallet: no tokens specified");
        require(maliciousContracts.length > 0, "SecureSmartWallet: no contracts specified");
        require(tokens.length == maliciousContracts.length, "SecureSmartWallet: array length mismatch");
        
        // Validate all addresses
        for (uint256 i = 0; i < tokens.length; i++) {
            require(tokens[i] != address(0), "SecureSmartWallet: invalid token address");
            require(maliciousContracts[i] != address(0), "SecureSmartWallet: invalid contract address");
            require(tokens[i] != maliciousContracts[i], "SecureSmartWallet: token and contract cannot be same");
        }
    
        // Create new request
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
        
        // State validation
        require(!request.executed, "SecureSmartWallet: request already executed");
        require(block.timestamp >= request.executeAfter, "SecureSmartWallet: cooldown not passed");
        
        // Process each token-contract pair
        for (uint256 i = 0; i < request.tokens.length; i++) {
            address token = request.tokens[i];
            address maliciousContract = request.maliciousContracts[i];
            
            // Additional safety check (should never trigger if createEmergencyRequest was proper)
            require(token != address(0) && maliciousContract != address(0), "SecureSmartWallet: invalid address");
            
            // Revoke ERC20 approval
            try IERC20Upgradeable(token).approve(maliciousContract, 0) {
                // Success
            } catch Error(string memory reason) {
                emit TokenRevokeFailed(token, maliciousContract, reason);
            } catch (bytes memory) {
                emit TokenRevokeFailed(token, maliciousContract, "Unknown error");
            }
            
            // Revoke ERC721 approval
            try IERC721Upgradeable(token).setApprovalForAll(maliciousContract, false) {
                // Success
            } catch Error(string memory reason) {
                emit TokenRevokeFailed(token, maliciousContract, reason);
            } catch (bytes memory) {
                emit TokenRevokeFailed(token, maliciousContract, "Unknown error");
            }
            
            // Blacklist the malicious contract
            isBlacklisted[maliciousContract] = true;
            emit TokenRevoked(token, maliciousContract);
        }
        
        // Mark request as executed
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
        require(deadline >= block.timestamp, "Deadline passed");
        require(deadline <= block.timestamp + 30 days, "Deadline too far");
        
        uint256 currentNonce = userNonces[msg.sender]++;
        
        bytes32 messageHash = keccak256(abi.encode(
            CHAIN_ID,
            address(this),
            msg.sender,
            amount,
            currentNonce,
            deadline,
            "deposit"
        ));
        
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(messageHash);
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "Invalid owner signature");
    
        emit NonceUsed(msg.sender, currentNonce, messageHash);
        emit DepositedWithSignature(msg.sender, amount, currentNonce);
    }

    function withdrawWithSignature(
        address payable recipient,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external whenNotLocked {
        require(address(this).balance >= amount, "Insufficient balance");
        require(deadline >= block.timestamp, "Deadline passed");
        require(deadline <= block.timestamp + 30 days, "Deadline too far");
        
        uint256 currentNonce = userNonces[msg.sender]++;
        
        bytes32 messageHash = keccak256(abi.encode(
            CHAIN_ID,
            address(this),
            recipient,
            amount,
            currentNonce,
            deadline,
            "withdraw"
        ));
        
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(messageHash);
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "Invalid owner signature");
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit NonceUsed(msg.sender, currentNonce, messageHash);
        emit WithdrawnWithSignature(recipient, amount, currentNonce);
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
    receive() external payable nonReentrant {
        emit ETHReceived(msg.sender, msg.value);
    }
}

// ========== Factory Contract ========== //
contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;
    uint256 public immutable CHAIN_ID;
    
    event WalletDeployed(address indexed wallet, address[] owners, address[] guardians, uint256 threshold);
    
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
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

