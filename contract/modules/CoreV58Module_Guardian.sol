// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";

/**
 * @title CoreV58Module_Guardian
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Modul 5 dari CoreV58: Sistem Guardian untuk Keamanan Tambahan
 */
abstract contract CoreV58Module_Guardian is Initializable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    /* ========== STRUCTS ========== */
    struct GuardianConfig {
        uint64 threshold;
        uint64 cooldown;
        uint64 lastRecoveryTimestamp;
        EnumerableSetUpgradeable.AddressSet guardians;
    }

    /* ========== SHARED STATE ========== */
    GuardianConfig private _guardianConfig;
    mapping(address => bool) public isBlacklisted;
    mapping(address => uint256) public guardianRecoveryNonces;
    mapping(address => mapping(uint256 => bool)) public usedRecoveryNonces;

    /* ========== CONSTANTS ========== */
    uint256 public constant CONFIRM_WINDOW = 24 hours;
    uint256 internal constant MAX_RECOVERY_COOLDOWN = 30 days;
    uint256 internal constant GUARDIAN_INACTIVITY_THRESHOLD = 180 days;

    /* ========== TYPEHASHES ========== */
    bytes32 public constant RECOVERY_TYPEHASH =
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline,bytes32 ownersHash,address verifyingContract,uint256 chainId)");
    bytes32 public constant EMERGENCY_LOCK_TYPEHASH =
        keccak256("EmergencyLock(uint256 nonce,uint256 deadline)");

    /* ========== EVENTS ========== */
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event GuardianThresholdUpdated(uint64 newThreshold);
    event RecoveryCooldownUpdated(uint64 newCooldown);
    event RecoveryExecuted(address[] newOwners, bytes32 ownersHash, uint256 recoveryNonce, uint256 chainId, address initiator);
    event EmergencyLockVetoed(address indexed vetoer);
    event GuardianInactivityWarning(uint256 lastActiveTimestamp);
    event GuardianActionExecuted(address indexed guardian, bytes4 action, uint256 timestamp);

    /* ========== INITIALIZER ========== */
    /**
     * @dev Initializes the Guardian System module.
     * @param initialGuardian The address of the initial guardian.
     * @param guardianThreshold The number of guardian approvals required for sensitive actions.
     * @param recoveryCooldown The cooldown period after a recovery action.
     */
    function __GuardianModule_init(
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown
    ) internal virtual onlyInitializing {
        require(initialGuardian != address(0), "Invalid guardian address");
        require(guardianThreshold > 0, "Guardian threshold must be greater than zero");

        _guardianConfig.guardians.add(initialGuardian);
        _guardianConfig.threshold = guardianThreshold;
        _guardianConfig.cooldown = recoveryCooldown;
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
    }

    /* ========== EXTERNAL FUNCTIONS (Guardian Management) ========== */
    /**
     * @dev Adds a new guardian. Only owners can call this.
     * @param guardian The address of the new guardian.
     */
    function addGuardian(address guardian) external virtual onlyOwner {
        require(guardian != address(0), "Invalid guardian address");
        require(!_guardianConfig.guardians.contains(guardian), "Guardian already exists");
        _guardianConfig.guardians.add(guardian);
        emit GuardianAdded(guardian);
    }

    /**
     * @dev Removes an existing guardian. Only owners can call this.
     * @param guardian The address of the guardian to remove.
     */
    function removeGuardian(address guardian) external virtual onlyOwner {
        require(_guardianConfig.guardians.contains(guardian), "Guardian does not exist");
        require(_guardianConfig.guardians.length() > 1, "Cannot remove the last guardian");
        _guardianConfig.guardians.remove(guardian);
        emit GuardianRemoved(guardian);
    }

    /**
     * @dev Sets the number of guardian approvals required for sensitive actions. Only owners can call this.
     * @param newThreshold The new guardian threshold.
     */
    function setGuardianThreshold(uint64 newThreshold) external virtual onlyOwner {
        require(newThreshold > 0, "Threshold must be greater than zero");
        require(newThreshold <= _guardianConfig.guardians.length(), "Threshold exceeds the number of guardians");
        _guardianConfig.threshold = newThreshold;
        emit GuardianThresholdUpdated(newThreshold);
    }

    /**
     * @dev Sets the cooldown period after a recovery action. Only owners can call this.
     * @param newCooldown The new recovery cooldown period in seconds.
     */
    function setRecoveryCooldown(uint64 newCooldown) external virtual onlyOwner {
        require(newCooldown <= MAX_RECOVERY_COOLDOWN, "Cooldown period too long");
        _guardianConfig.cooldown = newCooldown;
        emit RecoveryCooldownUpdated(newCooldown);
    }

    /**
     * @dev Blacklists a guardian address, preventing it from participating in guardian actions. Only owners can call this.
     * @param guardian The address of the guardian to blacklist.
     */
    function blacklistGuardian(address guardian) external virtual onlyOwner {
        isBlacklisted[guardian] = true;
    }

    /**
     * @dev Removes a guardian address from the blacklist, allowing it to participate in guardian actions again. Only owners can call this.
     * @param guardian The address of the guardian to remove from the blacklist.
     */
    function unblacklistGuardian(address guardian) external virtual onlyOwner {
        delete isBlacklisted[guardian];
    }

    /* ========== EXTERNAL FUNCTIONS (Guardian Actions) ========== */
    /**
     * @dev Initiates wallet recovery with multi-guardian approval.
     * @param newOwners Array of new owner addresses.
     * @param signatures Array of guardian signatures.
     * @param deadline Timestamp after which the signatures are no longer valid.
     * @param recoveryNonce Unique nonce for this recovery attempt by the initiator.
     */
    function initiateRecovery(
        address[] calldata newOwners,
        bytes[] calldata signatures,
        uint256 deadline,
        uint256 recoveryNonce
    ) external virtual {
        require(block.timestamp <= deadline, "Signature expired");
        require(newOwners.length > 0, "No new owners provided");
        require(!usedRecoveryNonces[msg.sender][recoveryNonce], "Nonce already used by initiator");
        require(block.timestamp >= _guardianConfig.lastRecoveryTimestamp + _guardianConfig.cooldown, "Recovery cooldown active");

        bytes32 ownersHash = keccak256(abi.encodePacked(newOwners));
        for (uint256 i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "Invalid new owner address");
            for (uint256 j = i + 1; j < newOwners.length; j++) {
                require(newOwners[i] != newOwners[j], "Duplicate new owner address");
            }
        }

        bytes32 recoveryHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVERY_TYPEHASH,
                    ownersHash,
                    recoveryNonce,
                    deadline,
                    address(this),
                    block.chainid
                )
            )
        );

        uint256 validSignatures;
        EnumerableSetUpgradeable.AddressSet memory signers;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _verifySignature(recoveryHash, signatures[i]);
            if (_isValidGuardian(signer) && !signers.contains(signer)) {
                signers.add(signer);
                validSignatures++;
                if (validSignatures >= _guardianConfig.threshold) break;
            }
        }

        require(validSignatures >= _guardianConfig.threshold, "Insufficient guardian approvals");

        _replaceOwners(newOwners); // Assuming _replaceOwners function exists in Ownership module
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
        usedRecoveryNonces[msg.sender][recoveryNonce] = true;

        emit RecoveryExecuted(newOwners, ownersHash, recoveryNonce, block.chainid, msg.sender);
    }

    /**
     * @dev Allows a guardian to veto an emergency lock initiated by another guardian. Only owners can call this.
     */
    function vetoEmergencyLock() external virtual onlyOwner whenLocked { // Assuming whenLocked modifier exists in a core module
        _setLockStatus(false); // Assuming _setLockStatus function exists in a core module
        emit EmergencyLockVetoed(msg.sender);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    /**
     * @dev Checks if a given address is a valid and non-blacklisted guardian.
     * @param guardian The address to check.
     * @return True if the address is a valid guardian, false otherwise.
     */
    function _isValidGuardian(address guardian) internal view virtual returns (bool) {
        return _guardianConfig.guardians.contains(guardian) && !isBlacklisted[guardian];
    }

    /**
     * @dev Returns the current number of guardians.
     * @return The number of guardians.
     */
    function _getGuardianCount() internal view virtual returns (uint256) {
        return _guardianConfig.guardians.length();
    }

    /**
     * @dev Returns the required threshold of guardian approvals.
     * @return The guardian threshold.
     */
    function _getGuardianThreshold() internal view virtual returns (uint64) {
        return _guardianConfig.threshold;
    }

    /* ========== VIEW FUNCTIONS ========== */
    /**
     * @dev Returns the list of current guardians.
     * @return An array of guardian addresses.
     */
    function getGuardians() external view virtual returns (address[] memory) {
        return _guardianConfig.guardians.values();
    }

    /**
     * @dev Checks if a given address is a guardian.
     * @param account The address to check.
     * @return True if the address is a guardian, false otherwise.
     */
    function isGuardian(address account) external view virtual returns (bool) {
        return _guardianConfig.guardians.contains(account);
    }

    /**
     * @dev Returns the current guardian threshold.
     * @return The guardian threshold.
     */
    function getGuardianThreshold() external view virtual returns (uint64) {
        return _guardianConfig.threshold;
    }

    /**
     * @dev Returns the recovery cooldown period.
     * @return The recovery cooldown in seconds.
     */
    function getRecoveryCooldown() external view virtual returns (uint64) {
        return _guardianConfig.cooldown;
    }

    /**
     * @dev Returns the timestamp of the last recovery action.
     * @return The last recovery timestamp.
     */
    function getLastRecoveryTimestamp() external view virtual returns (uint64) {
        return _guardianConfig.lastRecoveryTimestamp;
    }

    /**
     * @dev Checks if a guardian address is blacklisted.
     * @param account The address to check.
     * @return True if blacklisted, false otherwise.
     */
    function isGuardianBlacklisted(address account) external view virtual returns (bool) {
        return isBlacklisted[account];
    }

    /**
     * @dev Checks if the wallet needs guardian rotation due to inactivity.
     * @return True if rotation is recommended, false otherwise.
     */
    function guardianActivityCheck() external view virtual returns (bool needsRotation) {
        uint256 inactivePeriod = block.timestamp - _guardianConfig.lastRecoveryTimestamp;
        return inactivePeriod > GUARDIAN_INACTIVITY_THRESHOLD;
    }
}
