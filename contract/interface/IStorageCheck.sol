// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IStorageCheck
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Interface untuk kontrak yang dapat memeriksa kompatibilitas storage dengan implementasi sebelumnya.
 */
interface IStorageCheck {
    /**
     * @dev Checks if the storage layout of the current implementation is compatible
     * with the storage layout of the old implementation.
     * @param oldImpl The address of the old implementation contract.
     * @return True if the storage is compatible, false otherwise.
     */
    function isStorageCompatible(address oldImpl) external view returns (bool);
}
