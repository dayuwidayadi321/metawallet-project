// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

abstract contract GuardianManager is ReentrancyGuardUpgradeable, OwnableUpgradeable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
    using AddressUpgradeable for address;

    struct GuardianConfig {
        uint64 threshold;
        uint64 cooldown;
        uint64 lastRecoveryTimestamp;
        EnumerableSetUpgradeable.AddressSet guardians;
    }

    GuardianConfig internal _guardianConfig;
    mapping(address => bool) public isBlacklisted;

    // Events
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event GuardianThresholdUpdated(uint64 newThreshold);
    event RecoveryCooldownUpdated(uint64 newCooldown);
    event GuardianBlacklisted(address indexed guardian);
    event GuardianUnblacklisted(address indexed guardian);

    // Errors
    error ZeroAddressNotAllowed();
    error AlreadyAGuardian(address guardian);
    error NotAGuardian(address account);
    error CannotRemoveLastGuardian();
    error ThresholdTooHigh(uint64 threshold, uint64 guardianCount);
    error ThresholdCannotBeZero();
    error CooldownTooLong(uint64 cooldown);
    error BlacklistedGuardian(address guardian);
    error GuardianIsContract(address guardian);

    // Constants
    uint64 public constant MAX_COOLDOWN = 30 days;
    uint64 public constant MIN_GUARDIANS = 1;
    uint64 public constant MAX_GUARDIANS = 10;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function __GuardianManager_init() internal onlyInitializing {
        __ReentrancyGuard_init();
        __Ownable_init();
    }

    /**
     * @dev Add a new guardian to the system
     * @param guardian Address of the guardian to add
     */
    function addGuardian(address guardian) 
        external 
        virtual 
        onlyOwner 
        nonReentrant 
    {
        if (guardian == address(0)) revert ZeroAddressNotAllowed();
        if (_guardianConfig.guardians.contains(guardian)) revert AlreadyAGuardian(guardian);
        if (isBlacklisted[guardian]) revert BlacklistedGuardian(guardian);
        if (guardian.isContract()) revert GuardianIsContract(guardian);

        _guardianConfig.guardians.add(guardian);
        emit GuardianAdded(guardian);
    }
    
    /**
     * @dev Remove a guardian from the system
     * @param guardian Address of the guardian to remove
     */
    function removeGuardian(address guardian) 
        external 
        virtual 
        onlyOwner 
        nonReentrant 
    {
        if (!_guardianConfig.guardians.contains(guardian)) revert NotAGuardian(guardian);
        if (_guardianConfig.guardians.length() <= MIN_GUARDIANS) revert CannotRemoveLastGuardian();

        _guardianConfig.guardians.remove(guardian);
        
        // Adjust threshold if needed
        if (_guardianConfig.threshold > _guardianConfig.guardians.length()) {
            _guardianConfig.threshold = uint64(_guardianConfig.guardians.length());
            emit GuardianThresholdUpdated(_guardianConfig.threshold);
        }
        
        emit GuardianRemoved(guardian);
    }
    
    /**
     * @dev Set the threshold for guardian approvals
     * @param newThreshold New threshold value
     */
    function setGuardianThreshold(uint64 newThreshold) 
        external 
        virtual 
        onlyOwner 
    {
        if (newThreshold == 0) revert ThresholdCannotBeZero();
        if (newThreshold > _guardianConfig.guardians.length()) {
            revert ThresholdTooHigh(newThreshold, uint64(_guardianConfig.guardians.length()));
        }
        
        _guardianConfig.threshold = newThreshold;
        emit GuardianThresholdUpdated(newThreshold);
    }
    
    /**
     * @dev Set the recovery cooldown period
     * @param newCooldown New cooldown period in seconds
     */
    function setRecoveryCooldown(uint64 newCooldown) 
        external 
        virtual 
        onlyOwner 
    {
        if (newCooldown > MAX_COOLDOWN) revert CooldownTooLong(newCooldown);
        
        _guardianConfig.cooldown = newCooldown;
        emit RecoveryCooldownUpdated(newCooldown);
    }
    
    /**
     * @dev Blacklist a guardian address
     * @param guardian Address to blacklist
     */
    function blacklistGuardian(address guardian) external onlyOwner {
        isBlacklisted[guardian] = true;
        emit GuardianBlacklisted(guardian);
        
        // Remove if currently a guardian
        if (_guardianConfig.guardians.contains(guardian)) {
            _guardianConfig.guardians.remove(guardian);
            emit GuardianRemoved(guardian);
        }
    }

    /**
     * @dev Remove guardian from blacklist
     * @param guardian Address to unblacklist
     */
    function unblacklistGuardian(address guardian) external onlyOwner {
        isBlacklisted[guardian] = false;
        emit GuardianUnblacklisted(guardian);
    }

    /**
     * @dev Check if address is a valid guardian
     * @param guardian Address to check
     * @return bool True if valid guardian
     */
    function _isValidGuardian(address guardian) 
        internal 
        view 
        virtual 
        returns (bool) 
    {
        return _guardianConfig.guardians.contains(guardian) && 
               !isBlacklisted[guardian] &&
               !guardian.isContract();
    }

    /**
     * @dev Get all guardian addresses
     * @return address[] Array of guardian addresses
     */
    function getGuardians() 
        external 
        view 
        virtual 
        returns (address[] memory) 
    {
        return _guardianConfig.guardians.values();
    }

    /**
     * @dev Check if address is a guardian
     * @param account Address to check
     * @return bool True if address is a guardian
     */
    function isGuardian(address account) 
        external 
        view 
        virtual 
        returns (bool) 
    {
        return _guardianConfig.guardians.contains(account);
    }

    /**
     * @dev Get current guardian threshold
     * @return uint64 Current threshold value
     */
    function getGuardianThreshold() external view returns (uint64) {
        return _guardianConfig.threshold;
    }

    /**
     * @dev Get current recovery cooldown
     * @return uint64 Current cooldown in seconds
     */
    function getRecoveryCooldown() external view returns (uint64) {
        return _guardianConfig.cooldown;
    }

    // Storage gap for future upgrades
    uint256[50] private __gap;
}