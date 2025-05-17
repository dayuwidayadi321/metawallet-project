// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract RevokeApprovalV2 is Ownable {
    IEntryPoint public entryPoint;

    /**
     * @dev Konstruktor yang memungkinkan pendeploy menetapkan pemilik awal.
     * @param _entryPoint Alamat EntryPoint EIP-4337.
     * @param _initialOwner Alamat pemilik awal kontrak.
     */
    constructor(IEntryPoint _entryPoint, address _initialOwner) Ownable(_initialOwner) {
        entryPoint = _entryPoint;
    }

    /**
     * @dev Mencabut approval spender untuk token tertentu. Hanya pemilik yang dapat memanggil.
     * @param _token Alamat kontrak token ERC-20.
     * @param _spender Alamat kontrak yang persetujuannya ingin dicabut.
     */
    function revoke(address _token, address _spender) external onlyOwner {
        IERC20(_token).approve(_spender, 0);
        emit ApprovalRevoked(_token, _spender, msg.sender);
    }

    event ApprovalRevoked(address indexed token, address indexed spender, address indexed owner);

    /**
     * @dev Menerima pembayaran (opsional, mungkin berguna untuk biaya UserOp jika diperlukan).
     */
    receive() external payable {}
}
