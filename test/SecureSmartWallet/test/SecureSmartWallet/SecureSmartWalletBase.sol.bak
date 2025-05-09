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
    uint256 public constant MAX_OWNERS = 20;
    uint256 public constant MAX_GUARDIANS = 20;
    uint256 public constant MAX_THRESHOLD = 10;
    uint256 public constant UPGRADE_DELAY = 24 hours;
    bytes32 public constant FACTORY_SALT = keccak256("SecureSmartWalletFactory.v1");

    /* ========== STATE VARIABLES ========== */
    // Ownership
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public ownerCount;
    
    // Guardians
    struct GuardianConfig {
        address[] list;
        mapping(address => bool) isActive;
        uint256 threshold;
        uint256 cooldown;
        uint256 nonce;
    }
    GuardianConfig public guardianConfig;
    
    // Security
    address public factory;
    bool internal _isLocked;
    uint256 public lastSecurityUpdate;
    mapping(address => bool) public isBlacklisted;
    
    // Upgrade
    address public pendingImplementation;
    uint256 public upgradeActivationTime;

    /* ========== EVENTS ========== */
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
    event FactoryUpdated(address indexed newFactory);

    /* ========== ERRORS ========== */
    error InvalidTarget(address target);
    error InsufficientBalance(uint256 available, uint256 required);
    error CallExecutionFailed(address target, bytes4 errorSelector);
    error Unauthorized();

    /* ========== MODIFIERS ========== */
    modifier onlyFactory() {
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
        if (_isLocked) revert Unauthorized();
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
        
        lastSecurityUpdate = block.timestamp;
        emit WalletInitialized(_owners, _guardians, _guardianThreshold);
    }

    /* ========== UUPS UPGRADE ========== */
    function _authorizeUpgrade(address) internal override view {
        _validateUpgradeAuthorization();
    }

    /* ========== OWNER MANAGEMENT ========== */
    function transferOwnership(address[] calldata newOwners) external onlyOwner whenNotLocked {
        require(newOwners.length > 0 && newOwners.length <= MAX_OWNERS, "Invalid owners");
        
        _clearExistingOwners();
        _setNewOwners(newOwners);
        
        lastSecurityUpdate = block.timestamp;
        emit SecurityUpdate(block.timestamp);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    function _validateUpgradeAuthorization() internal view {
        if (!isOwner[msg.sender] && !_isActiveGuardian(msg.sender)) {
            revert Unauthorized();
        }
        if (_isLocked) revert Unauthorized();
    }

    function _isActiveGuardian(address guardian) internal view returns (bool) {
        return guardianConfig.isActive[guardian] && guardian != address(0);
    }
    
    function _validateInitialParams(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) private pure {
        require(_owners.length > 0, "No owners");
        require(_guardians.length > 0, "No guardians");
        require(_guardians.length <= MAX_GUARDIANS, "Too many guardians");
        require(_guardianThreshold > 0 && _guardianThreshold <= _guardians.length, 
            "Invalid threshold");
    }
    
    function _initializeOwners(address[] calldata _owners) private {
        owners = _owners;
        for (uint256 i = 0; i < _owners.length; i++) {
            require(_owners[i] != address(0), "Invalid owner");
            isOwner[_owners[i]] = true;
            emit OwnerStatusUpdated(_owners[i], true);
        }
        ownerCount = _owners.length;
    }
    
    function _initializeGuardians(
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) private {
        guardianConfig.list = _guardians;
        guardianConfig.threshold = _guardianThreshold;
        guardianConfig.cooldown = 24 hours;
        
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "Invalid guardian");
            guardianConfig.isActive[_guardians[i]] = true;
            emit GuardianStatusUpdated(_guardians[i], true);
        }
    }    


    function updateGuardians(
        address[] calldata newGuardians,
        uint256 newThreshold
    ) external onlyOwner {
        require(newGuardians.length > 0, "No guardians");
        require(newGuardians.length <= MAX_GUARDIANS, "Too many guardians");
        require(newThreshold > 0 && newThreshold <= newGuardians.length, "Invalid threshold");
        
        // Clear existing
        address[] memory oldGuardians = guardianConfig.list;
        for (uint256 i = 0; i < oldGuardians.length; i++) {
            guardianConfig.isActive[oldGuardians[i]] = false;
            emit GuardianStatusUpdated(oldGuardians[i], false);
        }
        
        // Set new
        guardianConfig.list = newGuardians;
        guardianConfig.threshold = newThreshold;
        
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(!guardianConfig.isActive[guardian], "Duplicate guardian");
            guardianConfig.isActive[guardian] = true;
            emit GuardianStatusUpdated(guardian, true);
        }
        
        emit GuardiansUpdated(newGuardians, newThreshold);
    }
    
    function getGuardians() external view returns (address[] memory) {
        return guardianConfig.list;
    }
    
    function lockWallet(string calldata reason) external onlyOwner {
        require(!_isLocked, "Already locked");
        _isLocked = true;
        emit WalletLocked(reason);
    }
    
    function unlockWallet() external onlyOwner {
        require(_isLocked, "Not locked");
        _isLocked = false;
        emit WalletUnlocked();
    }
    
    function blacklistAddress(address target, bool status) external onlyOwner {
        require(target != address(0) && target != address(this), "Invalid target");
        isBlacklisted[target] = status;
        emit BlacklistUpdated(target, status);
    } 
    
    function executeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner whenNotLocked nonReentrant returns (bytes memory) {
        require(target != address(0), "Invalid target");
        require(!isBlacklisted[target], "Target blacklisted");
        require(target.code.length > 0, "Target not contract");
        
        if (value > 0) {
            require(address(this).balance >= value, "Insufficient balance");
        }
        
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            if (result.length > 0) {
                assembly {
                    let ptr := mload(add(result, 0x20))
                    revert(ptr, returndatasize())
                }
            } else {
                revert("Call failed");
            }
        }
        
        emit ExecutionSuccess(target, value, data, gasleft());
        return result;
    }
    
    function scheduleUpgrade(address newImplementation) external onlyOwner {
        require(newImplementation.isContract(), "Not a contract");
        pendingImplementation = newImplementation;
        upgradeActivationTime = block.timestamp + UPGRADE_DELAY;
        emit UpgradeScheduled(newImplementation, upgradeActivationTime);
    }
    
    function cancelUpgrade() external onlyOwner {
        require(pendingImplementation != address(0), "No upgrade scheduled");
        emit UpgradeCancelled(pendingImplementation);
        pendingImplementation = address(0);
        upgradeActivationTime = 0;
    }    
    
    
    function getOwners() external view returns (address[] memory) {
        return owners;
    }
    
    function getUpgradeInfo() external view returns (address, uint256) {
        return (pendingImplementation, upgradeActivationTime);
    }
    
    function setFactory(address _factory) external onlyFactory {
        require(factory == address(0), "Factory already set");
        factory = _factory;
        emit FactoryUpdated(_factory);
    }
    
    function _clearExistingOwners() private {
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]] = false;
            emit OwnerStatusUpdated(owners[i], false);
        }
        delete owners;
    }

    function _setNewOwners(address[] calldata newOwners) private {
        owners = newOwners;
        for (uint256 i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "Invalid owner");
            require(!isOwner[newOwners[i]], "Duplicate owner");
            isOwner[newOwners[i]] = true;
            emit OwnerStatusUpdated(newOwners[i], true);
        }
        ownerCount = newOwners.length;
    }    
    
    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}