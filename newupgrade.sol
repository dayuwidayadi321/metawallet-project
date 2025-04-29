// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Anda bukan admin");
        _;
    }

    function upgrade(address _newImplementation) external onlyAdmin {
        implementation = _newImplementation;
    }

    fallback() external {  // Tidak ada `payable`
        address _impl = implementation;
        (bool success, ) = _impl.delegatecall(msg.data);
        require(success, "Delegatecall gagal");
    }
}