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
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

/**
 * @title AdvancedSmartWallet - EIP-4337 Smart Wallet (v4.34)
 * @author BY DFXC INDONESIA WEB3 PROJECT
 * @notice Next-generation smart wallet with complete security suite and emergency protection
 * @dev Major features:
 * - Multi-chain security system
 * - Emergency asset protection
 * - Advanced session key controls
 * - Gas abstraction and sponsorship
 * - Batch operations
 * - UUPS upgradeable
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    string public constant VERSION = "4.34";
    string public name;

    // EntryPoint EIP-4337
    IEntryPoint public immutable entryPoint;

    // Security modules
    uint256 public emergencyGasReserve;
    mapping(address => bool) public blacklistedContracts;
    mapping(address => uint256) public tokenAllowances;

    // Owner management
    mapping(address => bool) public owners;
    address[] public ownerList;
    uint256 public ownerCount;

    // Recovery system (Guardian-based)
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian;
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
        address pendingNewOwner;
    }
    RecoveryConfig public recoveryConfig;

    // Session keys (limited-time permissions)
    struct SessionKey {
        address key;
        uint48 validUntil;
        uint256 spendingLimit;
        uint256 spentAmount;
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction;
    }
    mapping(address => SessionKey) public sessionKeys;

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
    event BatchExecutionSuccess(uint256 indexed count);
    event BatchExecutionFailure(uint256 indexed count, string reason);
    event RecoveryInitiated(address indexed by, address pendingNewOwner, uint256 timestamp);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners, address[] newGuardians);
    event SessionKeyAdded(address indexed key, uint48 validUntil, uint256 spendingLimit, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event SessionKeySpendingUpdated(address indexed key, uint256 newSpendingLimit);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);
    event EmergencyRevoked(address indexed token, address indexed maliciousContract);
    event GasSponsored(address indexed recipient, uint256 amount);
    event ContractBlacklisted(address indexed maliciousContract);
    event EmergencyGasReserveUpdated(uint256 newAmount);
    event TokenAllowanceUpdated(address indexed token, uint256 newAllowance);

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

    modifier checkBlacklist(address target) {
        require(!blacklistedContracts[target], "Contract blacklisted");
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
        uint256 _recoveryDelay,
        uint256 _initialGasReserve
    ) external payable initializer {
        require(_owners.length > 0, "AdvancedSmartWallet: no owners");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "Invalid threshold");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;
        recoveryConfig.initiatedAt = 0;
        emergencyGasReserve = _initialGasReserve;

        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            require(!owners[owner], "AdvancedSmartWallet: duplicate owner");
            owners[owner] = true;
            ownerList.push(owner);
        }
        ownerCount = _owners.length;

        recoveryConfig.guardians = _guardians;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "AdvancedSmartWallet: invalid guardian");
            recoveryConfig.isGuardian[_guardians[i]] = true;
        }

        if (msg.value > 0) {
            entryPoint.depositTo{value: msg.value}(address(this));
        }

        emit WalletInitialized(_owners, _name);
        emit OwnershipUpdated(_owners);
        emit EmergencyGasReserveUpdated(_initialGasReserve);
    }

    // ========== Core Functionality ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (!_validateSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (msg.sender != address(entryPoint)) {
            bytes4 selector = bytes4(userOp.callData);
            require(
                selector == this.executeCall.selector ||
                selector == this.executeBatch.selector ||
                selector == this.emergencyRevokeApproval.selector ||
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

    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint checkBlacklist(to) returns (bytes memory) {
        require(to != address(0), "Invalid target");
        require(to != address(this), "Self-call forbidden");
        require(gasleft() >= EXECUTE_GAS_LIMIT / 2, "Insufficient gas");

        _checkSessionKeySpendingLimit(value);

        (bool success, bytes memory result) = to.call{value: value}(data);
        
        if (success) {
            emit ExecutionSuccess(to, value, data);
        } else {
            emit ExecutionFailure(to, value, data);
            revert(string(result));
        }
        
        return result;
    }

    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyEntryPoint returns (bytes[] memory results) {
        require(targets.length == values.length && values.length == datas.length, "Invalid array lengths");
        require(targets.length > 0 && targets.length <= 10, "Invalid batch size");

        results = new bytes[](targets.length);
        uint256 totalValue = 0;

        for (uint256 i = 0; i < targets.length; i++) {
            require(targets[i] != address(0), "Invalid target");
            require(targets[i] != address(this), "Self-call forbidden");
            require(!blacklistedContracts[targets[i]], "Contract blacklisted");
            totalValue += values[i];
        }

        _checkSessionKeySpendingLimit(totalValue);

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(datas[i]);
            
            if (success) {
                results[i] = result;
                emit ExecutionSuccess(targets[i], values[i], datas[i]);
            } else {
                emit ExecutionFailure(targets[i], values[i], datas[i]);
                emit BatchExecutionFailure(i, string(result));
                revert(string(result));
            }
        }

        emit BatchExecutionSuccess(targets.length);
    }

    // ========== Emergency Protection System ========== //
    function emergencyRevokeApproval(
        address token,
        address maliciousContract,
        bytes memory ownerSignature
    ) external nonReentrant {
        bytes32 messageHash = keccak256(abi.encodePacked(
            "EMERGENCY_REVOKE",
            token,
            maliciousContract,
            block.chainid
        ));
        messageHash = ECDSA.toEthSignedMessageHash(messageHash);
        
        require(owners[ECDSA.recover(messageHash, ownerSignature)], "Invalid owner signature");
    
        // Revoke ERC20 approval
        (bool success,) = token.call(abi.encodeWithSelector(
            IERC20.approve.selector,
            maliciousContract,
            0
        ));
        require(success, "ERC20 revoke failed");
    
        // Blacklist the contract
        blacklistedContracts[maliciousContract] = true;
        
        emit EmergencyRevoked(token, maliciousContract);
        emit ContractBlacklisted(maliciousContract);
    }

    function sponsorEmergencyGas(
        UserOperation calldata userOp,
        bytes memory ownerSignature
    ) external {
        require(bytes4(userOp.callData) == this.emergencyRevokeApproval.selector, 
            "Only emergency ops");

        bytes32 opHash = entryPoint.getUserOpHash(userOp);
        require(owners[opHash.recover(ownerSignature)], "Invalid signature");

        uint256 requiredGas = userOp.maxFeePerGas * userOp.callGasLimit;
        require(emergencyGasReserve >= requiredGas, "Insufficient gas reserve");
        
        emergencyGasReserve -= requiredGas;
        entryPoint.depositTo{value: requiredGas}(address(this));
        
        emit GasSponsored(msg.sender, requiredGas);
    }

    // ========== Security Management ========== //
    function updateEmergencyGasReserve(uint256 newAmount) external payable onlyOwner {
        emergencyGasReserve = newAmount;
        if (msg.value > 0) {
            entryPoint.depositTo{value: msg.value}(address(this));
        }
        emit EmergencyGasReserveUpdated(newAmount);
    }

    function setTokenAllowance(address token, uint256 amount) external onlyOwner {
        tokenAllowances[token] = amount;
        emit TokenAllowanceUpdated(token, amount);
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

    // ========== Session Key Management ========== //
    function addSessionKey(
        address _key,
        uint48 _validUntil,
        uint256 _spendingLimit,
        bytes4[] calldata _allowedFunctions
    ) external onlyOwner {
        require(_key != address(0), "Invalid session key");
        require(_validUntil > block.timestamp, "Expiration must be in future");

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.validUntil = _validUntil;
        session.spendingLimit = _spendingLimit;
        session.spentAmount = 0;
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            session.allowedFunctions.push(_allowedFunctions[i]);
            session.isAllowedFunction[_allowedFunctions[i]] = true;
        }

        emit SessionKeyAdded(_key, _validUntil, _spendingLimit, _allowedFunctions);
    }

    function updateSessionKeySpendingLimit(address _key, uint256 _newSpendingLimit) external onlyOwner {
        require(sessionKeys[_key].key != address(0), "Session key not found");
        sessionKeys[_key].spendingLimit = _newSpendingLimit;
        emit SessionKeySpendingUpdated(_key, _newSpendingLimit);
    }

    function revokeSessionKey(address _key) external onlyOwner {
        require(sessionKeys[_key].key != address(0), "Session key not found");
        delete sessionKeys[_key];
        emit SessionKeyRevoked(_key);
    }

    // ========== ERC1271 Implementation ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4 magicValue) {
        if (_validateSignature(hash, signature)) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }

    // ========== Internal Functions ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered] || _isValidSessionKey(recovered, bytes4(hash));
    }

    function _isValidSessionKey(address key, bytes4 selector) internal view returns (bool) {
        SessionKey storage session = sessionKeys[key];
        return session.key != address(0) 
            && block.timestamp <= session.validUntil
            && session.isAllowedFunction[selector];
    }

    function _checkSessionKeySpendingLimit(uint256 value) internal {
        if (owners[msg.sender]) return;

        SessionKey storage session = sessionKeys[msg.sender];
        require(session.key != address(0), "Not a valid session key");
        require(session.spentAmount + value <= session.spendingLimit, "Spending limit exceeded");
        session.spentAmount += value;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        emit UpgradePerformed(newImplementation);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }
}

// ========== Factory Contract ========== //
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "4.34";
    string public constant NAME = "AdvancedSmartWalletFactory";

    IEntryPoint public immutable entryPoint;
    address public walletImplementation;

    mapping(address => address[]) private _userWallets;
    mapping(address => bool) public isWalletDeployed;

    event WalletCreated(address indexed wallet, address[] owners, string name);
    event ImplementationUpdated(address newImplementation);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new AdvancedSmartWallet(_entryPoint));
    }

    function updateImplementation(address _newImplementation) external {
        require(msg.sender == address(entryPoint), "Only EntryPoint can update");
        walletImplementation = _newImplementation;
        emit ImplementationUpdated(_newImplementation);
    }

    function deployWallet(
        address[] calldata owners,
        string calldata name,
        address[] calldata guardians,
        uint256 recoveryThreshold,
        uint256 recoveryDelay,
        uint256 initialGasReserve
    ) external payable returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            AdvancedSmartWallet.initialize.selector,
            owners,
            name,
            guardians,
            recoveryThreshold,
            recoveryDelay,
            initialGasReserve
        );

        wallet = address(new ERC1967Proxy(walletImplementation, initData));

        for (uint256 i = 0; i < owners.length; i++) {
            _userWallets[owners[i]].push(wallet);
        }

        isWalletDeployed[wallet] = true;
        emit WalletCreated(wallet, owners, name);

        if (msg.value > 0) {
            AdvancedSmartWallet(payable(wallet)).updateEmergencyGasReserve{value: msg.value}(initialGasReserve);
        }
    }

    function getWallets(address user) external view returns (address[] memory) {
        return _userWallets[user];
    }
}
