// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SmartWallet {
    using ECDSA for bytes32;

    address public owner;
    IEntryPoint public entryPoint;

    // Event untuk log eksekusi transaksi
    event TransactionExecuted(address indexed target, uint256 value, bytes data);

    constructor(address _owner, IEntryPoint _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    // Modifier untuk membatasi akses hanya ke EntryPoint
    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "Only EntryPoint can call");
        _;
    }

    // Modifier untuk membatasi akses hanya ke pemilik
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call");
        _;
    }

    /**
     * @dev Validasi UserOperation (dipanggil oleh EntryPoint).
     * Hanya menerima tanda tangan dari pemilik.
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Verifikasi tanda tangan pemilik
        address recovered = userOpHash.recover(userOp.signature);
        require(recovered == owner, "Invalid signature");

        // Jika wallet perlu deposit gas, transfer dana ke EntryPoint
        if (missingWalletFunds > 0) {
            (bool success, ) = payable(address(entryPoint)).call{
                value: missingWalletFunds
            }("");
            success; // Silence warning
        }

        return 0; // Validation successful
    }

    /**
     * @dev Eksekusi panggilan ke kontrak lain (misalnya RevokeApprovalV2).
     * Hanya bisa dipanggil via EntryPoint.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint {
        (bool success, ) = target.call{value: value}(data);
        require(success, "Execution failed");
        emit TransactionExecuted(target, value, data);
    }

    // Menerima pembayaran (untuk deposit gas)
    receive() external payable {}
}

contract SmartWalletFactory {
    IEntryPoint public entryPoint;
    mapping(address => address) public getWalletOfOwner; // Mapping dari owner ke alamat SmartWallet

    event WalletCreated(address indexed owner, address indexed walletAddress);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function createWallet(address _owner) external returns (address) {
        require(getWalletOfOwner[_owner] == address(0), "Wallet already exists for this owner");
        SmartWallet newWallet = new SmartWallet(_owner, entryPoint);
        getWalletOfOwner[_owner] = address(newWallet);
        emit WalletCreated(_owner, address(newWallet));
        return address(newWallet);
    }

    // Fungsi untuk mendapatkan alamat SmartWallet berdasarkan owner
    function getSmartWalletAddress(address _owner) public view returns (address) {
        return getWalletOfOwner[_owner];
    }
}
