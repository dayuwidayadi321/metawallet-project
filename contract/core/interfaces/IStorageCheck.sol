// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IStorageCheck
 * @dev Interface untuk memverifikasi kompatibilitas layout storage
 */
interface IStorageCheck {
    /**
     * @dev Memeriksa kompatibilitas layout storage dengan versi sebelumnya
     * @param oldImpl Alamat implementasi lama
     * @return bool True jika layout storage kompatibel
     */
    function isStorageCompatible(address oldImpl) external view returns (bool);
    
    /**
     * @dev Memeriksa konsistensi storage
     * @return bool True jika semua slot storage valid
     */
    function checkStorageConsistency() external view returns (bool);
}