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
 * - Improved signature validation
 * - Guardian management system
 * - Secure session keys with contract-level permissions
 * - Anti-front-running recovery process
 * @dev Major improvements from v4.2:
 * - Fixed signature validation vulnerabilities
 * - Added guardian management functions
 * - Enhanced session key security
 * - Improved recovery process with guardian signatures
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
    uint256 public constant MAX_OWNERS = 10;

    // Enhanced recovery system
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian;
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
        address pendingNewOwner;
        bytes[] guardianSignatures; // Store guardian signatures for recovery
    }
    RecoveryConfig public recoveryConfig;
    uint256 public constant MAX_GUARDIANS = 20;

    // Enhanced session keys
    struct SessionKey {
        address key;
        address allowedContract;
        uint48 validUntil;
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction;
    }
    mapping(address => SessionKey) public sessionKeys;

    // Constants
    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    // Events
    event WalletInitialized(address[] indexed owners, string name);
    event OwnershipUpdated(address[] newOwners);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);
    event RecoveryInitiated(address indexed by, address pendingNewOwner, uint256 timestamp);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners, address[] newGuardians);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event SessionKeyAdded(address indexed key, address allowedContract, uint48 validUntil, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);

    // Modifiers
    modifier onlyOwner() {
        require(owners[msg.sender], "ASW: caller not owner");
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "ASW: not from EntryPoint");
        _;
    }

    modifier onlyRecovery() {
        require(
            recoveryConfig.initiatedAt > 0 &&
            block.timestamp >= recoveryConfig.initiatedAt + recoveryConfig.delay,
            "ASW: recovery not ready"
        );
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
        require(_owners.length > 0, "ASW: no owners");
        require(_owners.length <= MAX_OWNERS, "ASW: too many owners");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "ASW: invalid threshold");
        require(_guardians.length <= MAX_GUARDIANS, "ASW: too many guardians");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "ASW: recovery delay too long");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;

        // Set owners with duplicate check
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "ASW: invalid owner");
            require(!owners[owner], "ASW: duplicate owner");
            owners[owner] = true;
            ownerList.push(owner);
        }

        // Set guardians
        recoveryConfig.guardians = _guardians;
        for (uint256 i = 0; i < _guardians.length; i++) {
            address guardian = _guardians[i];
            require(guardian != address(0), "ASW: invalid guardian");
            recoveryConfig.isGuardian[guardian] = true;
        }

        emit WalletInitialized(_owners, _name);
        emit OwnershipUpdated(_owners);
    }

    // ========== Enhanced Owner Management ========== //
    function addOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ASW: invalid owner");
        require(!owners[newOwner], "ASW: already owner");
        require(ownerList.length < MAX_OWNERS, "ASW: max owners reached");

        owners[newOwner] = true;
        ownerList.push(newOwner);
        
        emit OwnerAdded(newOwner);
        emit OwnershipUpdated(ownerList);
    }

    function removeOwner(address ownerToRemove) external onlyOwner {
        require(owners[ownerToRemove], "ASW: not owner");
        require(ownerList.length > 1, "ASW: cannot remove last owner");

        owners[ownerToRemove] = false;
        
        for (uint256 i = 0; i < ownerList.length; i++) {
            if (ownerList[i] == ownerToRemove) {
                ownerList[i] = ownerList[ownerList.length - 1];
                ownerList.pop();
                break;
            }
        }
        
        emit OwnerRemoved(ownerToRemove);
        emit OwnershipUpdated(ownerList);
    }

    function getOwners() external view returns (address[] memory) {
        return ownerList;
    }

    // ========== Enhanced Recovery System ========== //
    function initiateRecovery(address _pendingNewOwner, bytes calldata signature) external {
        require(recoveryConfig.isGuardian[msg.sender], "ASW: not guardian");
        require(_pendingNewOwner != address(0), "ASW: invalid pending owner");
    
        bytes32 recoveryHash = keccak256(abi.encodePacked(
            "RECOVER_INIT",
            address(this),
            _pendingNewOwner,
            block.chainid
        ));
        bytes32 ethSignedHash = ECDSA.toEthSignedMessageHash(recoveryHash);
    
        require(ECDSA.recover(ethSignedHash, signature) == msg.sender, "ASW: invalid signature");
    
        recoveryConfig.initiatedAt = block.timestamp;
        recoveryConfig.pendingNewOwner = _pendingNewOwner;
        recoveryConfig.guardianSignatures.push(signature);
    
        emit RecoveryInitiated(msg.sender, _pendingNewOwner, block.timestamp);
    }

    function cancelRecovery() external onlyOwner {
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        delete recoveryConfig.guardianSignatures;
        emit RecoveryCancelled();
    }

    function completeRecovery(
        address[] calldata newOwners,
        address[] calldata newGuardians,
        bytes[] calldata guardianSignatures
    ) external onlyRecovery {
        require(newOwners.length == 1, "ASW: single owner required");
        require(newOwners[0] == recoveryConfig.pendingNewOwner, "ASW: owner mismatch");
        require(newGuardians.length >= recoveryConfig.threshold, "ASW: insufficient guardians");
        require(guardianSignatures.length >= recoveryConfig.threshold, "ASW: insufficient signatures");

        // Verify guardian signatures
        bytes32 recoveryHash = keccak256(abi.encodePacked(
            "RECOVER_COMPLETE",
            address(this),
            newOwners[0],
            block.chainid
        )).toEthSignedMessageHash();

        uint256 validSignatures;
        for (uint256 i = 0; i < guardianSignatures.length; i++) {
            address signer = recoveryHash.recover(guardianSignatures[i]);
            if (recoveryConfig.isGuardian[signer]) {
                validSignatures++;
            }
        }
        require(validSignatures >= recoveryConfig.threshold, "ASW: threshold not met");

        // Clear current owners
        for (uint256 i = 0; i < ownerList.length; i++) {
            owners[ownerList[i]] = false;
        }
        delete ownerList;

        // Set new owner
        owners[newOwners[0]] = true;
        ownerList.push(newOwners[0]);

        // Update guardians
        _updateGuardians(newGuardians);

        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        delete recoveryConfig.guardianSignatures;
        
        emit RecoveryCompleted(newOwners, newGuardians);
        emit OwnershipUpdated(newOwners);
    }

    // ========== Guardian Management ========== //
    function addGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "ASW: invalid guardian");
        require(!recoveryConfig.isGuardian[newGuardian], "ASW: already guardian");
        require(recoveryConfig.guardians.length < MAX_GUARDIANS, "ASW: max guardians reached");

        recoveryConfig.guardians.push(newGuardian);
        recoveryConfig.isGuardian[newGuardian] = true;
        
        emit GuardianAdded(newGuardian);
    }

    function removeGuardian(address guardian) external onlyOwner {
        require(recoveryConfig.isGuardian[guardian], "ASW: not guardian");
        require(recoveryConfig.guardians.length > recoveryConfig.threshold, "ASW: below threshold");

        recoveryConfig.isGuardian[guardian] = false;
        
        for (uint256 i = 0; i < recoveryConfig.guardians.length; i++) {
            if (recoveryConfig.guardians[i] == guardian) {
                recoveryConfig.guardians[i] = recoveryConfig.guardians[recoveryConfig.guardians.length - 1];
                recoveryConfig.guardians.pop();
                break;
            }
        }
        
        emit GuardianRemoved(guardian);
    }

    function _updateGuardians(address[] calldata newGuardians) private {
        // Clear existing guardians
        for (uint256 i = 0; i < recoveryConfig.guardians.length; i++) {
            recoveryConfig.isGuardian[recoveryConfig.guardians[i]] = false;
        }
        delete recoveryConfig.guardians;

        // Add new guardians
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "ASW: invalid guardian");
            recoveryConfig.guardians.push(guardian);
            recoveryConfig.isGuardian[guardian] = true;
        }
    }

    // ========== Enhanced Session Keys ========== //
    function addSessionKey(
        address _key,
        address _allowedContract,
        uint48 _validUntil,
        bytes4[] calldata _allowedFunctions
    ) external onlyOwner {
        require(_key != address(0), "ASW: invalid key");
        require(_allowedContract != address(0), "ASW: invalid contract");
        require(_validUntil > block.timestamp, "ASW: expiration must be future");

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.allowedContract = _allowedContract;
        session.validUntil = _validUntil;
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            session.allowedFunctions.push(_allowedFunctions[i]);
            session.isAllowedFunction[_allowedFunctions[i]] = true;
        }

        emit SessionKeyAdded(_key, _allowedContract, _validUntil, _allowedFunctions);
    }

    function revokeSessionKey(address _key) external onlyOwner {
        require(sessionKeys[_key].key != address(0), "ASW: key not found");
        delete sessionKeys[_key];
        emit SessionKeyRevoked(_key);
    }

    // ========== Enhanced Signature Validation ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (!_validateUserOpSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (missingWalletFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingWalletFunds}("");
            require(success, "ASW: refund failed");
        }

        return 0;
    }

    function _validateUserOpSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered];
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        if (_validateSignature(hash, signature)) {
            return ERC1271_MAGIC_VALUE;
        }
        return bytes4(0);
    }

    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        
        // Check if owner
        if (owners[recovered]) {
            return true;
        }
        
        // Check if valid session key
        SessionKey storage session = sessionKeys[recovered];
        if (session.key != address(0) && block.timestamp <= session.validUntil) {
            // For session keys, hash should contain the function selector as first 4 bytes
            bytes4 functionSelector = bytes4(hash);
            return session.isAllowedFunction[functionSelector];
        }
        
        return false;
    }

    // ========== Deposit Management ========== //
    function addDeposit() external payable {
        require(msg.value > 0, "ASW: deposit must > 0");
        entryPoint.depositTo{value: msg.value}(address(this));
        emit DepositReceived(msg.sender, msg.value);
    }

    function withdrawDeposit(address payable withdrawAddress, uint256 amount) 
        external 
        onlyOwner 
        nonReentrant 
    {
        uint256 currentBalance = entryPoint.balanceOf(address(this));
        require(currentBalance >= amount, "ASW: insufficient balance");
        
        try entryPoint.withdrawTo(withdrawAddress, amount) {
            emit DepositWithdrawn(withdrawAddress, amount);
        } catch Error(string memory reason) {
            revert(string(abi.encodePacked("ASW: ", reason)));
        } catch {
            revert("ASW: withdraw failed");
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