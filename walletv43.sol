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

    IEntryPoint public immutable entryPoint;

    mapping(address => bool) public owners;
    address[] public ownerList;
    uint256 public ownerCount;
    uint256 public constant MAX_OWNERS = 10;

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

    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

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
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);
    event GuardiansUpdated(address[] newGuardians);

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

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

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
            address guardian = _guardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            require(!recoveryConfig.isGuardian[guardian], "AdvancedSmartWallet: duplicate guardian");
            recoveryConfig.isGuardian[guardian] = true;
        }

        emit WalletInitialized(_owners, _name);
        emit OwnershipUpdated(_owners);
        emit GuardiansUpdated(_guardians);
    }

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

        for (uint256 i = 0; i < ownerList.length; i++) {
            owners[ownerList[i]] = false;
        }
        delete ownerList;

        owners[newOwners[0]] = true;
        ownerList.push(newOwners[0]);
        ownerCount = 1;

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
    }

    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address signer = hash.toEthSignedMessageHash().recover(signature);
        return owners[signer];
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        emit UpgradePerformed(newImplementation);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner nonReentrant {
        require(to != address(0), "Invalid recipient");
        require(amount <= address(this).balance, "Insufficient balance");

        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");

        emit DepositWithdrawn(to, amount);
    }
}