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
 * @title AdvancedSmartWallet - EIP-4337 Smart Wallet (v4.36)
 * @author BY DFXC INDONESIA WEB3 PROJECT
 * @notice Smart wallet with enhanced security fixes, execution protection, and guardian visibility
 * @dev Major improvements in v4.36:
 * - Fixed guardian registration issues during deployment
 * - Added guardian count tracking
 * - Enhanced guardian validation checks
 * - Improved recovery system robustness
 * - Added guardian management functions
 * - Maintained all v4.35 security features
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    string public constant VERSION = "4.36";
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
        uint256 guardianCount; // New in v4.36
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
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // Events (Updated for v4.36)
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
    event GuardianAdded(address indexed guardian); // New in v4.36
    event GuardianRemoved(address indexed guardian); // New in v4.36

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

    // ========== Initialization (Fixed in v4.36) ========== //
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

        // Initialize guardians (Fixed in v4.36)
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

    // ========== Enhanced Guardian Management (v4.36) ========== //
    function addGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "AdvancedSmartWallet: invalid guardian");
        require(!recoveryConfig.isGuardian[newGuardian], "AdvancedSmartWallet: already guardian");

        recoveryConfig.guardians.push(newGuardian);
        recoveryConfig.isGuardian[newGuardian] = true;
        recoveryConfig.guardianCount++;
        
        emit GuardianAdded(newGuardian);
    }

    function removeGuardian(address guardianToRemove) external onlyOwner {
        require(recoveryConfig.isGuardian[guardianToRemove], "AdvancedSmartWallet: not guardian");
        require(recoveryConfig.guardianCount > recoveryConfig.threshold, "Cannot go below threshold");

        recoveryConfig.isGuardian[guardianToRemove] = false;
        recoveryConfig.guardianCount--;

        uint256 length = recoveryConfig.guardians.length;
        for (uint256 i = 0; i < length; i++) {
            if (recoveryConfig.guardians[i] == guardianToRemove) {
                if (i != length - 1) {
                    recoveryConfig.guardians[i] = recoveryConfig.guardians[length - 1];
                }
                recoveryConfig.guardians.pop();
                break;
            }
        }

        emit GuardianRemoved(guardianToRemove);
    }

    // ========== Enhanced EIP-4337 Functions ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (!_validateSignature(userOpHash, userOp.signature, userOp.callData)) {
            return SIG_VALIDATION_FAILED;
        }

        if (msg.sender != address(entryPoint)) {
            bytes4 selector = bytes4(userOp.callData);
            require(
                selector == this.executeCall.selector ||
                selector == this.addOwner.selector ||
                selector == this.removeOwner.selector,
                "Invalid operation"
            );
        }

        if (missingWalletFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingWalletFunds}("");
            require(success, "Failed to refund gas");
        }

        return 0;
    }

    // ========== Enhanced Execution ========== //
    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint nonReentrant whenNotExecuting returns (bytes memory) {
        require(to != address(0), "Invalid target");
        require(to != address(this), "Self-call forbidden");
        
        _isExecuting = true;
        uint256 startGas = gasleft();
        
        (bool success, bytes memory result) = to.call{
            value: value,
            gas: min(gasleft() - 10_000, EXECUTE_GAS_LIMIT)
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

    // ========== Owner Management ========== //
    function addOwner(address newOwner) external onlyOwner {
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
        ownerCount--;

        uint256 length = ownerList.length;
        for (uint256 i = 0; i < length; i++) {
            if (ownerList[i] == ownerToRemove) {
                if (i != length - 1) {
                    ownerList[i] = ownerList[length - 1];
                }
                ownerList.pop();
                break;
            }
        }

        emit OwnerRemoved(ownerToRemove);
        emit OwnershipUpdated(ownerList);
    }

    // ========== Enhanced Recovery System ========== //
    function initiateRecovery(address _pendingNewOwner) external {
        require(recoveryConfig.isGuardian[msg.sender], "AdvancedSmartWallet: not guardian");
        require(_pendingNewOwner != address(0), "Invalid pending owner");
        
        recoveryConfig.nonce++;
        recoveryConfig.initiatedAt = block.timestamp;
        recoveryConfig.pendingNewOwner = _pendingNewOwner;
        
        emit RecoveryInitiated(msg.sender, _pendingNewOwner, block.timestamp, recoveryConfig.nonce);
    }

    function cancelRecovery() external onlyOwner {
        uint256 currentNonce = recoveryConfig.nonce;
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        emit RecoveryCancelled(currentNonce);
    }

    function completeRecovery(
        address[] calldata newOwners,
        address[] calldata newGuardians,
        bytes[] calldata guardianSignatures
    ) external onlyRecovery nonReentrant {
        require(newOwners.length == 1, "Single owner required");
        require(newGuardians.length >= recoveryConfig.threshold, "Insufficient guardians");
        require(
            newOwners[0] == recoveryConfig.pendingNewOwner,
            "Recovery: Owner change must match pending owner"
        );

        bytes32 recoveryHash = keccak256(abi.encodePacked(
            newOwners,
            newGuardians,
            recoveryConfig.nonce
        ));
        uint256 validSignatures;
        for (uint256 i = 0; i < guardianSignatures.length; i++) {
            if (recoveryConfig.isGuardian[recoveryHash.recover(guardianSignatures[i])]) {
                validSignatures++;
            }
        }
        require(validSignatures >= recoveryConfig.threshold, "Insufficient approvals");

        // Execute recovery
        uint256 currentNonce = recoveryConfig.nonce;
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        
        address[] memory oldOwners = ownerList;
        
        for (uint256 i = 0; i < oldOwners.length; i++) {
            owners[oldOwners[i]] = false;
        }
        delete ownerList;
        ownerCount = 0;
        
        owners[newOwners[0]] = true;
        ownerList.push(newOwners[0]);
        ownerCount = 1;

        for (uint256 i = 0; i < recoveryConfig.guardians.length; i++) {
            recoveryConfig.isGuardian[recoveryConfig.guardians[i]] = false;
        }
        
        delete recoveryConfig.guardians;
        recoveryConfig.guardianCount = newGuardians.length;
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            recoveryConfig.guardians.push(guardian);
            recoveryConfig.isGuardian[guardian] = true;
        }

        emit RecoveryCompleted(newOwners, newGuardians, currentNonce);
        emit OwnershipUpdated(newOwners);
    }

    // ========== Session Keys ========== //
    function addSessionKey(
        address _key,
        uint48 _validUntil,
        bytes4[] calldata _allowedFunctions,
        bytes32[] calldata _allowedCallDataHashes
    ) external onlyOwner {
        require(_key != address(0), "Invalid session key");
        require(_validUntil > block.timestamp, "Expiration must be in future");

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.validUntil = _validUntil;
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            session.allowedFunctions.push(_allowedFunctions[i]);
            session.isAllowedFunction[_allowedFunctions[i]] = true;
        }
        
        for (uint256 i = 0; i < _allowedCallDataHashes.length; i++) {
            session.allowedCallDataHashes[_allowedCallDataHashes[i]] = true;
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

    // ========== Guardian Visibility ========== //
    function getGuardians() external view returns (address[] memory) {
        return recoveryConfig.guardians;
    }

    function getGuardianCount() external view returns (uint256) {
        return recoveryConfig.guardianCount;
    }

    // ========== Internal Functions ========== //
    function _validateSignature(
        bytes32 hash,
        bytes memory signature,
        bytes calldata callData
    ) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered] || _isValidSessionKey(recovered, hash, callData);
    }

    function _isValidSessionKey(
        address key,
        bytes32 userOpHash,
        bytes calldata callData
    ) internal view returns (bool) {
        SessionKey storage session = sessionKeys[key];
        return session.key != address(0) 
            && block.timestamp <= session.validUntil
            && session.isAllowedFunction[bytes4(callData)]
            && session.allowedCallDataHashes[keccak256(callData)];
    }
    
    // ========== ERC1271 Implementation ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        if (_validateSignature(hash, signature, msg.data)) {
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

    // Helper function
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }
}

// Updated Factory contract for v4.36
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "4.36";
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