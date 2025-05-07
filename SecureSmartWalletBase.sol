// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/draft-IERC1822Upgradeable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

abstract contract SecureSmartWalletBase is 
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable 
{
    // ========== Library Usage ========== //
    using AddressUpgradeable for address;
    using ECDSAUpgradeable for bytes32;
    

    // ========== Core Dependencies ========== //
    IEntryPoint public immutable entryPoint;
    uint256 public immutable CHAIN_ID;
    
    // ========== Ownership Management ========== //
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public ownerCount;
    uint256 public constant MAX_OWNERS = 20;

    // ========== Guardian System ========== //
    struct GuardianConfig {
        address[] list;
        mapping(address => bool) isActive;
        uint256 threshold;
        uint256 cooldown;
        uint256 nonce;
    }
    
    // ========== Constant Fixed ========== //
    GuardianConfig public guardianConfig;
    uint256 public constant MAX_GUARDIANS = 20;
    uint256 public constant MAX_THRESHOLD = 10;

    // ========== Security State ========== //
    bool internal _isLocked;
    uint256 public lastSecurityUpdate;
    mapping(address => bool) public isBlacklisted;
    mapping(address => bool) public isActiveGuardian;
    
    // ========== Upgrade Management ========== //
    address public pendingImplementation;
    uint256 public upgradeActivationTime;
    uint256 public constant UPGRADE_DELAY = 24 hours;

    // ========== Events ========== //
    event WalletInitialized(address[] owners, address[] guardians, uint256 guardianThreshold);
    event OwnershipTransferred(address[] indexed newOwners, string reason);
    event OwnerStatusUpdated(address indexed owner, bool isActive);
    event GuardianStatusUpdated(address indexed guardian, bool isActive);
    event GuardiansUpdated(address[] newGuardians, uint256 newThreshold);
    event WalletLocked(string reason);
    event WalletUnlocked();
    event SecurityUpdate(uint256 timestamp);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data, uint256 gasLimit);
    event UpgradeScheduled(address indexed newImplementation, uint256 activationTime);
    event UpgradeCompleted(address indexed newImplementation);
    event UpgradeCancelled(address indexed cancelledImplementation);
    event BlacklistUpdated(address indexed target, bool status);
    event SuspiciousActivityDetected(address indexed target, uint256 value, bytes data);
    event UpgradeVerified(address indexed implementation, bool isCompliant);

    // ========== Errors ========== //
    error InvalidTarget(address target);
    error InsufficientBalance(uint256 available, uint256 required);
    error CallExecutionFailed(address target, bytes4 errorSelector);

    // ========== Modifiers ========== //
    modifier onlyOwner() {
        require(isOwner[msg.sender], "SecureSmartWallet: caller is not owner");
        _;
    }

    modifier onlyGuardian() {
        require(_isActiveGuardian(msg.sender), "SecureSmartWallet: caller is not an active guardian");
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

    // ========== Constructor ========== //
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
        _disableInitializers();
    }

    // ========== Initialization ========== //
    function __SecureSmartWalletBase_init(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) internal onlyInitializing {
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

    // ========== Ownership Management ========== //
    function transferOwnership(address[] calldata newOwners) external onlyOwner whenNotLocked {
        require(newOwners.length > 0, "No new owners");
        require(newOwners.length <= MAX_OWNERS, "Too many owners");
    
        // Clear old owners
    for (uint256 i = 0; i < owners.length; ) {
        address oldOwner = owners[i];
        isOwner[oldOwner] = false;
        emit OwnerStatusUpdated(oldOwner, false);
        unchecked { i++; }
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
    
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    // ========== Guardian Management ========== //
    function updateGuardians(
        address[] calldata newGuardians,
        uint256 newThreshold
    ) external onlyOwner {
        require(newGuardians.length > 0, "No guardians");
        require(newGuardians.length <= MAX_GUARDIANS, "Too many guardians");
        require(newThreshold > 0 && newThreshold <= newGuardians.length, "Invalid threshold");
        
        // Clear existing guardians
        address[] memory oldGuardians = guardianConfig.list;
        for (uint256 i = 0; i < oldGuardians.length; i++) {
            guardianConfig.isActive[oldGuardians[i]] = false;
            emit GuardianStatusUpdated(oldGuardians[i], false);
        }
        
        // Set new guardians
        guardianConfig.list = newGuardians;
        guardianConfig.threshold = newThreshold;
        
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "Invalid guardian: zero address");
            require(!guardianConfig.isActive[guardian], "Duplicate guardian");
            
            guardianConfig.isActive[guardian] = true;
            emit GuardianStatusUpdated(guardian, true);
        }
        
        emit GuardiansUpdated(newGuardians, newThreshold);
    }

        // Guardian Active (fixed):
    function _isActiveGuardian(address guardian) internal view returns (bool) {
        return guardianConfig.isActive[guardian] && guardian != address(0);
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
        emit BlacklistUpdated(target, status);
        emit SecurityUpdate(block.timestamp);
    }

    // ========== Execution Functions ========== //
    function executeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner whenNotLocked nonReentrant antiDrain(target) returns (bytes memory) {
        if (target == address(0)) revert InvalidTarget(address(0));
        if (isBlacklisted[target]) revert InvalidTarget(target);
        
        uint256 size;
        assembly {
            size := extcodesize(target)
        }
        if (size == 0) revert InvalidTarget(target);
    
        if (value > 0 && address(this).balance < value) {
            revert InsufficientBalance(address(this).balance, value);
        }
    
        uint256 gasLimit = gasleft() * 95 / 100; // 5% reserve
        (bool success, bytes memory result) = target.call{value: value, gas: gasLimit}(data);
        
        if (!success) {
            bytes4 errorSelector;
            if (result.length >= 4) {
                assembly {
                    errorSelector := mload(add(result, 0x20))
                }
            }
            revert CallExecutionFailed(target, errorSelector);
        }
        
        emit ExecutionSuccess(target, value, data, gasLimit);
        return result;
    }

    // ========== Upgrade Management ========== //
    <

    function executeUpgrade() external onlyOwner {
        require(pendingImplementation != address(0), "No upgrade scheduled");
        require(block.timestamp >= upgradeActivationTime, "Upgrade delay not passed");
        
        address implementation = pendingImplementation;
        require(implementation.isContract(), "Implementation must be a contract");
        
        address[] memory currentOwners = owners;
        address[] memory currentGuardians = guardianConfig.list;
        uint256 currentThreshold = guardianConfig.threshold;
        
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
        
        ERC1967Utils.upgradeToAndCall(
            implementation,
            abi.encodeWithSignature(
                "migrate(address[],address[],uint256)", 
                currentOwners,
                currentGuardians, 
                currentThreshold
            )
        );
        
        emit UpgradeCompleted(implementation);
    }
    
    function cancelUpgrade() external onlyOwner {
        require(pendingImplementation != address(0), "No upgrade scheduled");
        
        address pendingImpl = pendingImplementation;
        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(pendingImpl)
        }
        
        address cancelledImplementation = pendingImpl;
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
        emit UpgradeCancelled(cancelledImplementation);
    }

    function getUpgradeInfo() external view returns (address, uint256) {
        return (pendingImplementation, upgradeActivationTime);
    }

    // ========== Internal Functions ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return isOwner[hash.recover(signature)];
    }

    function _validateGuardianSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return guardianConfig.isGuardian[recovered] && _isActiveGuardian(recovered);
    }

    // ========== Storage Gap ========== //
    uint256[50] private __gap;    
}

