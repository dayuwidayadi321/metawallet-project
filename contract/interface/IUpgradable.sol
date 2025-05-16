// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IUpgradable
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Interface untuk kontrak yang dapat di-upgrade.
 */
interface IUpgradable {
    /**
     * @dev Returns the current upgrade timelock duration.
     * @return The timelock duration in seconds.
     */
    function getUpgradeTimelock() external view returns (uint256);

    /**
     * @dev Returns the address of the pending implementation, if any.
     * @return The pending implementation address, or address(0) if no upgrade is pending.
     */
    function getPendingImplementation() external view returns (address);

    /**
     * @dev Returns the block number when the upgrade timelock will expire.
     * @return The upgrade timelock expiration block number, or 0 if no upgrade is pending.
     */
    function getUpgradeTimelockExpirationBlock() external view returns (uint256);

    /**
     * @dev Checks if an upgrade has been confirmed.
     * @return True if the upgrade is confirmed, false otherwise.
     */
    function isUpgradeConfirmed() external view returns (bool);

    /**
     * @dev Initiates a contract upgrade to a new implementation.
     * @param newImplementation The address of the new implementation contract.
     */
    function initiateUpgrade(address newImplementation) external;

    /**
     * @dev Cancels a pending upgrade.
     */
    function cancelUpgrade() external;

    /**
     * @dev Confirms the initiated upgrade after the timelock has elapsed.
     */
    function confirmUpgrade() external;

    /**
     * @dev Executes the confirmed upgrade.
     */
    function executeUpgrade() external;

    /**
     * @dev Attempts to rollback to the previous implementation.
     * @param previousImplementation The address of the previous implementation.
     */
    function rollbackUpgrade(address previousImplementation) external;
}
