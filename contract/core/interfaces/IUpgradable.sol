// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IUpgradable
 * @dev Interface untuk kontrak yang mendukung mekanisme upgrade dengan versioning
 */
interface IUpgradable {
    /**
     * @dev Mengembalikan versi kontrak dalam format string
     * @return Versi kontrak (contoh: "5.5")
     */
    function VERSION() external view returns (string memory);
    
    /**
     * @dev Memeriksa kesehatan kontrak setelah upgrade
     * @return bool True jika kontrak berfungsi normal setelah upgrade
     */
    function healthCheck() external returns (bool);
    
    /**
     * @dev Event yang dipancarkan ketika upgrade diotorisasi
     * @param newImplementation Alamat implementasi baru
     */
    event UpgradeAuthorized(address indexed newImplementation);
}