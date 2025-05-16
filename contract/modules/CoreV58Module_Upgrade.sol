// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/StorageSlotUpgradeable.sol";
// import "./contract/interface/IUpgradable.sol";
// import "./contract/interface/IStorageCheck.sol";

/**
 * @title CoreV58Module_Upgrade
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Modul 6 dari CoreV58: Mekanisme Upgrade Kontrak (UUPS) dengan Keamanan Tambahan
 */
abstract contract CoreV58Module_Upgrade is Initializable, UUPSUpgradeable {
    using AddressUpgradeable for address;
    using StorageSlotUpgradeable for StorageSlotUpgradeable.AddressSlot;
    using StorageSlotUpgradeable for StorageSlotUpgradeable.Uint256Slot;

    /* ========== STORAGE SLOTS ========== */
    bytes32 internal constant _UPGRADE_TIMELOCK_SLOT = keccak256("corev58.upgrade.timelock");
    bytes32 internal constant _PENDING_IMPLEMENTATION_SLOT = keccak256("corev58.upgrade.pending.implementation");
    bytes32 internal constant _UPGRADE_CONFIRMED_SLOT = keccak256("corev58.upgrade.confirmed");
    bytes32 internal constant _UPGRADE_BLOCK_NUMBER_SLOT = keccak256("corev58.upgrade.block.number");

    /* ========== IMMUTABLES (Set di constructor base contract) ========== */
    address public immutable self;

    /* ========== CONSTANTS ========== */
    uint256 internal constant MIN_UPGRADE_TIMELOCK = 1 days;
    uint256 internal constant MAX_UPGRADE_TIMELOCK = 30 days;

    /* ========== CUSTOM ERRORS ========== */
    error UnauthorizedUpgradeCaller(address caller);
    error InvalidImplementationAddress(address implementation);
    error UpgradeTimelockNotElapsed(uint256 current, uint256 required);
    error UpgradeAlreadyConfirmed();
    error UpgradeNotInitiated();
    error UpgradeCancelled();
    error RollbackFailed(bytes revertReason);
    error InvalidFunctionSelector(bytes4 selector);
    error InvalidFunctionResponse(bytes expected, bytes actual);
    error CriticalFunctionCheckFailed(bytes4 selector, bytes expected, bytes actual);

    /* ========== EVENTS ========== */
    event UpgradeInitiated(address indexed newImplementation, uint256 effectiveAt);
    event UpgradeCancelled(address indexed oldImplementation);
    event UpgradeConfirmed(address indexed newImplementation);
    event UpgradeExecuted(address indexed newImplementation);
    event UpgradeRollbacked(address indexed oldImplementation, address indexed newImplementation);

    /* ========== INITIALIZER ========== */
    /**
     * @dev Initializes the Upgrade module.
     */
    function __UpgradeModule_init() internal virtual onlyInitializing {
        // No specific state to initialize in this module itself, UUPSUpgradeable handles implementation slot
    }

    /* ========== INTERNAL FUNCTIONS (Storage Accessors) ========== */
    function _upgradeTimelock() internal view virtual returns (uint256) {
        return StorageSlotUpgradeable.getUint256Slot(_UPGRADE_TIMELOCK_SLOT).value;
    }

    function _setUpgradeTimelock(uint256 newTimelock) internal virtual {
        StorageSlotUpgradeable.getUint256Slot(_UPGRADE_TIMELOCK_SLOT).value = newTimelock;
    }

    function _pendingImplementation() internal view virtual returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_PENDING_IMPLEMENTATION_SLOT).value;
    }

    function _setPendingImplementation(address newImplementation) internal virtual {
        StorageSlotUpgradeable.getAddressSlot(_PENDING_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function _upgradeConfirmed() internal view virtual returns (bool) {
        return StorageSlotUpgradeable.getBooleanSlot(_UPGRADE_CONFIRMED_SLOT).value;
    }

    function _setUpgradeConfirmed(bool confirmed) internal virtual {
        StorageSlotUpgradeable.getBooleanSlot(_UPGRADE_CONFIRMED_SLOT).value = confirmed;
    }

    function _upgradeBlockNumber() internal view virtual returns (uint256) {
        return StorageSlotUpgradeable.getUint256Slot(_UPGRADE_BLOCK_NUMBER_SLOT).value;
    }

    function _setUpgradeBlockNumber(uint256 blockNumber) internal virtual {
        StorageSlotUpgradeable.getUint256Slot(_UPGRADE_BLOCK_NUMBER_SLOT).value = blockNumber;
    }

    /* ========== OVERRIDE FROM UUPSUpgradeable ========== */
    /**
     * @dev Authorizes the upgrade function call. Inheriting contracts should implement their own
     * authorization logic in this function.
     * @param newImplementation The address of the new implementation.
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {
        if (newImplementation == address(0)) revert InvalidImplementationAddress(newImplementation);
        // Default authorization is only owner, but can be extended in the main contract
    }

    /* ========== EXTERNAL FUNCTIONS (Upgrade Management) ========== */
    /**
     * @dev Sets the timelock duration for contract upgrades. Only owners can call this.
     * @param newTimelock The new timelock duration in seconds.
     */
    function setUpgradeTimelock(uint256 newTimelock) external virtual onlyOwner {
        require(newTimelock >= MIN_UPGRADE_TIMELOCK && newTimelock <= MAX_UPGRADE_TIMELOCK, "Invalid timelock duration");
        _setUpgradeTimelock(newTimelock);
    }

    /**
     * @dev Initiates a contract upgrade to a new implementation. Only authorized callers can call this.
     * @param newImplementation The address of the new implementation contract.
     */
    function initiateUpgrade(address newImplementation) external virtual onlyOwner {
        _authorizeUpgrade(newImplementation);
        require(_pendingImplementation() == address(0), "Upgrade already initiated");
        _validateImplementation(newImplementation);
        _setPendingImplementation(newImplementation);
        _setUpgradeConfirmed(false);
        _setUpgradeBlockNumber(block.number + (_upgradeTimelock() / (block.timestamp - block.timestamp + 1))); // Approximate block number
        emit UpgradeInitiated(newImplementation, block.timestamp + _upgradeTimelock());
    }

    /**
     * @dev Cancels a pending upgrade. Only owners can call this before the timelock elapses.
     */
    function cancelUpgrade() external virtual onlyOwner {
        require(_pendingImplementation() != address(0), "No upgrade initiated");
        require(!_upgradeConfirmed(), "Upgrade already confirmed");
        require(block.number < _upgradeBlockNumber(), "Timelock has elapsed");
        emit UpgradeCancelled(_pendingImplementation());
        _setPendingImplementation(address(0));
    }

    /**
     * @dev Confirms the initiated upgrade after the timelock has elapsed. Only owners can call this.
     */
    function confirmUpgrade() external virtual onlyOwner {
        require(_pendingImplementation() != address(0), "No upgrade initiated");
        require(!_upgradeConfirmed(), "Upgrade already confirmed");
        require(block.number >= _upgradeBlockNumber(), "Upgrade timelock not elapsed");
        _setUpgradeConfirmed(true);
        emit UpgradeConfirmed(_pendingImplementation());
    }

    /**
     * @dev Executes the confirmed upgrade. Only the contract itself can call this.
     */
    function executeUpgrade() external virtual {
        require(msg.sender == self, "Only this contract can execute upgrade");
        require(_pendingImplementation() != address(0), "No upgrade initiated");
        require(_upgradeConfirmed(), "Upgrade not confirmed");
        address newImplementation = _pendingImplementation();
        _setPendingImplementation(address(0));
        _setUpgradeConfirmed(false);
        _upgradeTo(newImplementation);
        emit UpgradeExecuted(newImplementation);
        checkUpgradeHealth(newImplementation);
    }

    /**
     * @dev Attempts to rollback to the previous implementation. Only owners can call this if an upgrade failed.
     * @param previousImplementation The address of the previous implementation.
     */
    function rollbackUpgrade(address previousImplementation) external virtual onlyOwner {
        require(_pendingImplementation() != address(0), "No upgrade initiated");
        _setPendingImplementation(address(0));
        _setUpgradeConfirmed(false);
        try this.upgradeTo(previousImplementation) {
            emit UpgradeRollbacked(previousImplementation, previousImplementation);
        } catch (bytes memory revertReason) {
            revert RollbackFailed(revertReason);
        }
    }

    /* ========== INTERNAL FUNCTIONS (Validation and Checks) ========== */
    /**
     * @dev Validates the new implementation contract before initiating an upgrade.
     * @param newImplementation The address of the new implementation.
     */
    function _validateImplementation(address newImplementation) internal view virtual {
        require(newImplementation.isContract(), "New implementation is not a contract");
        // Add any additional checks here, like interface compliance
    }

    /**
     * @dev Checks the health of the new implementation after an upgrade.
     * @param newImplementation The address of the new implementation.
     */
    function checkUpgradeHealth(address newImplementation) internal virtual {
        _safePostUpgradeCheck(newImplementation);
        _validateCriticalFunctions(newImplementation);
    }

    /**
     * @dev Performs a safe delegatecall to the new implementation to check post-upgrade state.
     * @param newImplementation The address of the new implementation.
     */
    function _safePostUpgradeCheck(address newImplementation) internal virtual {
        (bool success, bytes memory result) = AddressUpgradeable.functionDelegateCall(
            newImplementation,
            abi.encodeWithSignature("postUpgradeCheck()") // Assuming this function exists in new impl
        );
        if (success && result.length > 0) {
            require(abi.decode(result, (bool)), "Post upgrade check failed");
        }
    }

    /**
     * @dev Validates the functionality of critical functions in the new implementation.
     * @param newImplementation The address of the new implementation.
     */
    function _validateCriticalFunctions(address newImplementation) internal virtual {
        _checkCriticalFunction(newImplementation, "VERSION()", abi.encode("5.8")); // Check if version is still correct
        // Add checks for other critical functions as needed
    }

    /**
     * @dev Helper function to check the return value of a critical function.
     * @param target The address of the contract to call.
     * @param selector The function selector.
     * @param expectedReturn The expected return value.
     */
    function _checkCriticalFunction(address target, string memory selector, bytes memory expectedReturn) internal virtual {
        bytes4 sig = bytes4(keccak256(bytes(selector)));
        (bool success, bytes memory actualReturn) = AddressUpgradeable.functionDelegateCall(target, abi.encodeWithSelector(sig));
        if (!success) revert InvalidFunctionSelector(sig);
        if (keccak256(actualReturn) != keccak256(expectedReturn)) revert CriticalFunctionCheckFailed(sig, expectedReturn, actualReturn);
    }

    /* ========== EXTERNAL VIEW FUNCTIONS ========== */
    /**
     * @dev Returns the current upgrade timelock duration.
     * @return The timelock duration in seconds.
     */
    function getUpgradeTimelock() external view virtual returns (uint256) {
        return _upgradeTimelock();
    }

    /**
     * @dev Returns the address of the pending implementation, if any.
     * @return The pending implementation address, or address(0) if no upgrade is pending.
     */
    function getPendingImplementation() external view virtual returns (address) {
        return _pendingImplementation();
    }

    /**
     * @dev Returns the block number when the upgrade timelock will expire.
     * @return The upgrade timelock expiration block number, or 0 if no upgrade is pending.
     */
    function getUpgradeTimelockExpirationBlock() external view virtual returns (uint256) {
        return _upgradeBlockNumber();
    }

    /**
     * @dev Checks if an upgrade has been confirmed.
     * @return True if the upgrade is confirmed, false otherwise.
     */
    function isUpgradeConfirmed() external view virtual returns (bool) {
        return _upgradeConfirmed();
    }
}
