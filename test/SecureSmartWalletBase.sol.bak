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
    using AddressUpgradeable for address;
    using ECDSAUpgradeable for bytes32;
    
    /* ========== CORE CONSTANTS ========== */
    IEntryPoint public immutable entryPoint;
    uint256 public immutable CHAIN_ID;
    uint256 public constant MAX_OWNERS = 10;
    uint256 public constant MAX_GUARDIANS = 20;
    uint256 public constant MAX_THRESHOLD = 10;
    uint256 public constant UPGRADE_DELAY = 48 hours;
    bytes32 public constant FACTORY_SALT = keccak256("SecureSmartWalletFactory.v4.49");

    /* ========== STATE VARIABLES ========== */
    // Ownership
    address[] public owners;
    mapping(address => bool) public isOwner;
    
    // Guardians
    struct GuardianConfig {
        address[] list;
        uint128 threshold;
        uint64 cooldown;
        uint64 lastUpdate;
        mapping(address => bool) isActive;
    }
    GuardianConfig public guardianConfig;
    
    // Security
    address public factory;
    bool public isLocked;
    uint64 public lastSecurityUpdate;
    mapping(address => bool) public isBlacklisted;
    
    // Upgrade
    address public pendingImplementation;
    uint64 public upgradeActivationTime;

    /* ========== EVENTS ========== */
    event WalletInitialized(address[] owners, address[] guardians, uint256 threshold);
    event OwnershipTransferred(address[] indexed newOwners);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event GuardiansUpdated(address[] newGuardians, uint256 newThreshold);
    event WalletLocked(string reason);
    event WalletUnlocked();
    event SecurityUpdate(uint256 timestamp);
    event ExecutionSuccess(address indexed target, uint256 value, bytes4 selector);
    event UpgradeScheduled(address indexed newImplementation, uint256 activationTime);
    event UpgradeCompleted(address indexed newImplementation);
    event UpgradeCancelled();
    event BlacklistUpdated(address indexed target, bool status);
    event SuspiciousActivityDetected(address indexed target, bytes4 selector);
    event FactoryUpdated(address indexed newFactory);

    /* ========== ERRORS ========== */
    error InvalidTarget(address target);
    error InsufficientBalance(uint256 available, uint256 required);
    error ExecutionFailed(bytes4 errorSelector);
    error Unauthorized();
    error DuplicateAddress(address detected);
    error ZeroAddressNotAllowed();
    error WalletIsLocked();
    error UpgradeNotPending();
    error UpgradeNotReady();
    error InvalidGuardianConfig();

    /* ========== MODIFIERS ========== */
    modifier onlyFactory() virtual {
        if (msg.sender != factory) revert Unauthorized();
        _;
    }
    
    modifier onlyOwner() {
        if (!isOwner[msg.sender]) revert Unauthorized();
        _;
    }

    modifier onlyGuardian() {
        if (!_isActiveGuardian(msg.sender)) revert Unauthorized();
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert Unauthorized();
        _;
    }

    modifier whenNotLocked() {
        if (isLocked) revert WalletIsLocked();
        _;
    }

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
        _disableInitializers();
    }

    /* ========== INITIALIZATION ========== */
    function __SecureSmartWalletBase_init(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) internal onlyInitializing {
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        
        _validateInitialParams(_owners, _guardians, _guardianThreshold);
        _initializeOwners(_owners);
        _initializeGuardians(_guardians, _guardianThreshold);
        
        lastSecurityUpdate = uint64(block.timestamp);
        emit WalletInitialized(_owners, _guardians, _guardianThreshold);
    }

    /* ========== UUPS UPGRADE ========== */
    function _authorizeUpgrade(address newImpl) internal virtual override view {
        if (!isOwner[msg.sender] && !_isActiveGuardian(msg.sender)) {
            revert Unauthorized();
        }
        if (isLocked) revert WalletIsLocked();
        if (newImpl == address(0)) revert InvalidTarget(address(0));
    }

    /* ========== OWNER MANAGEMENT ========== */
    function transferOwnership(address[] calldata newOwners) external onlyOwner whenNotLocked {
        require(newOwners.length > 0 && newOwners.length <= MAX_OWNERS, "Invalid owner count");
        
        // Clear existing owners
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]] = false;
            emit OwnerRemoved(owners[i]);
        }
        
        // Set new owners
        owners = newOwners;
        for (uint256 i = 0; i < newOwners.length; i++) {
            address owner = newOwners[i];
            if (owner == address(0)) revert ZeroAddressNotAllowed();
            if (isOwner[owner]) revert DuplicateAddress(owner);
            isOwner[owner] = true;
            emit OwnerAdded(owner);
        }
        
        _updateSecurity();
    }

    /* ========== GUARDIAN MANAGEMENT ========== */
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
            emit GuardianRemoved(oldGuardians[i]);
        }
        
        // Set new guardians
        guardianConfig.list = newGuardians;
        guardianConfig.threshold = uint128(newThreshold);
        
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            if (guardian == address(0)) revert ZeroAddressNotAllowed();
            if (guardianConfig.isActive[guardian]) revert DuplicateAddress(guardian);
            guardianConfig.isActive[guardian] = true;
            emit GuardianAdded(guardian);
        }
        
        guardianConfig.lastUpdate = uint64(block.timestamp);
        _updateSecurity();
        emit GuardiansUpdated(newGuardians, newThreshold);
    }

    /* ========== SECURITY FUNCTIONS ========== */
    function lockWallet(string calldata reason) external onlyOwner {
        if (isLocked) revert WalletIsLocked();
        isLocked = true;
        _updateSecurity();
        emit WalletLocked(reason);
    }
    
    function unlockWallet() external onlyOwner {
        if (!isLocked) revert WalletIsLocked();
        isLocked = false;
        _updateSecurity();
        emit WalletUnlocked();
    }
    
    function getLockStatus() public view returns (bool) {
        return isLocked;
    }

    function blacklistAddress(address target, bool status) external onlyOwner {
        if (target == address(0) || target == address(this)) revert InvalidTarget(target);
        isBlacklisted[target] = status;
        _updateSecurity();
        emit BlacklistUpdated(target, status);
    }

    /* ========== EXECUTION FUNCTIONS ========== */
    function executeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner whenNotLocked nonReentrant returns (bytes memory) {
        if (target == address(0)) revert InvalidTarget(target);
        if (isBlacklisted[target]) revert InvalidTarget(target);
        if (value > address(this).balance) revert InsufficientBalance(address(this).balance, value);
        
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            if (result.length > 0) {
                assembly {
                    let ptr := mload(add(result, 0x20))
                    revert(ptr, returndatasize())
                }
            }
            revert ExecutionFailed(selector);
        }
        
        emit ExecutionSuccess(target, value, selector);
        return result;
    }

    /* ========== UPGRADE FUNCTIONS ========== */
    function scheduleUpgrade(address newImplementation) external onlyOwner {
        if (!newImplementation.isContract()) revert InvalidTarget(newImplementation);
        pendingImplementation = newImplementation;
        upgradeActivationTime = uint64(block.timestamp + UPGRADE_DELAY);
        emit UpgradeScheduled(newImplementation, upgradeActivationTime);
    }
    
    function cancelUpgrade() external onlyOwner {
        if (pendingImplementation == address(0)) revert UpgradeNotPending();
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
        emit UpgradeCancelled();
    }
    
    function completeUpgrade() external onlyOwner {
        if (pendingImplementation == address(0)) revert UpgradeNotPending();
        if (block.timestamp < upgradeActivationTime) revert UpgradeNotReady();
        
        address impl = pendingImplementation;
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
        
        ERC1967Utils.upgradeToAndCall(impl, "");
        emit UpgradeCompleted(impl);
    }

    /* ========== VIEW FUNCTIONS ========== */
    function getOwners() external view returns (address[] memory) {
        return owners;
    }
    
    function getGuardians() external view returns (address[] memory) {
        return guardianConfig.list;
    }
    
    function getUpgradeInfo() external view returns (address, uint256) {
        return (pendingImplementation, upgradeActivationTime);
    }
    
    function isActiveGuardian(address guardian) external view returns (bool) {
        return _isActiveGuardian(guardian);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    function _isActiveGuardian(address guardian) internal view returns (bool) {
        return guardian != address(0) && guardianConfig.isActive[guardian];
    }
    
    function _validateInitialParams(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) private pure {
        if (_owners.length == 0 || _owners.length > MAX_OWNERS) revert InvalidGuardianConfig();
        if (_guardians.length == 0 || _guardians.length > MAX_GUARDIANS) revert InvalidGuardianConfig();
        if (_guardianThreshold == 0 || _guardianThreshold > _guardians.length) revert InvalidGuardianConfig();
    }
    
    function _initializeOwners(address[] calldata _owners) private {
        owners = _owners;
        for (uint256 i = 0; i < _owners.length; i++) {
            if (_owners[i] == address(0)) revert ZeroAddressNotAllowed();
            if (isOwner[_owners[i]]) revert DuplicateAddress(_owners[i]);
            isOwner[_owners[i]] = true;
            emit OwnerAdded(_owners[i]);
        }
    }
    
    function _initializeGuardians(
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) private {
        guardianConfig.list = _guardians;
        guardianConfig.threshold = uint128(_guardianThreshold);
        guardianConfig.cooldown = uint64(24 hours);
        guardianConfig.lastUpdate = uint64(block.timestamp);
        
        for (uint256 i = 0; i < _guardians.length; i++) {
            if (_guardians[i] == address(0)) revert ZeroAddressNotAllowed();
            if (guardianConfig.isActive[_guardians[i]]) revert DuplicateAddress(_guardians[i]);
            guardianConfig.isActive[_guardians[i]] = true;
            emit GuardianAdded(_guardians[i]);
        }
    }

    function _updateSecurity() private {
        lastSecurityUpdate = uint64(block.timestamp);
        emit SecurityUpdate(block.timestamp);
    }

    /* ========== STORAGE GAP ========== */
    uint256[45] private __gap;
}