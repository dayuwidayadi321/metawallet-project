// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;  // Hanya admin yang bisa meng-upgrade
    }

    // Modifier untuk memastikan hanya admin yang bisa memperbarui implementasi
    modifier onlyAdmin() {
        require(msg.sender == admin, "Anda bukan admin");
        _;
    }

    // Fungsi untuk memperbarui alamat kontrak implementasi
    function upgrade(address _newImplementation) external onlyAdmin {
        implementation = _newImplementation;
    }

    // Fungsi fallback untuk meneruskan panggilan ke kontrak implementasi
    fallback() external payable {
        address _impl = implementation;
        (bool success, ) = _impl.delegatecall(msg.data);
        require(success, "Delegatecall gagal");
    }
}
