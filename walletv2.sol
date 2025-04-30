// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @title AdvancedSmartWallet - EIP-4337 Compliant Smart Wallet (v2.0)
 * @notice Smart wallet dengan multi-owner, nama wallet, dan versioning
 * @dev Implementasi lebih lengkap untuk produksi
 */
contract AdvancedSmartWallet is IERC1271 {
    using ECDSA for bytes32;

    // Informasi versi
    string public constant VERSION = "2.0";
    string public name;
    
    // EIP-4337 EntryPoint address
    address public immutable entryPoint;
    
    // Daftar owner (mapping untuk efisiensi)
    mapping(address => bool) public owners;
    uint256 public ownerCount;
    
    // Event untuk tracking aktivitas wallet
    event WalletDeployed(address indexed wallet, address[] indexed owners, string name);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);

    /**
     * @dev Modifier untuk membatasi akses hanya ke owner
     */
    modifier onlyOwner() {
        require(owners[msg.sender], "Not an owner");
        _;
    }

    /**
     * @dev Constructor untuk inisialisasi wallet
     * @param _entryPoint Alamat EntryPoint EIP-4337
     * @param _owners Daftar alamat owner awal
     * @param _name Nama untuk wallet ini
     */
    constructor(
        address _entryPoint,
        address[] memory _owners,
        string memory _name
    ) {
        require(_owners.length > 0, "At least one owner required");
        entryPoint = _entryPoint;
        name = _name;
        
        for (uint256 i = 0; i < _owners.length; i++) {
            require(_owners[i] != address(0), "Invalid owner address");
            owners[_owners[i]] = true;
            ownerCount++;
        }
        
        emit WalletDeployed(address(this), _owners, _name);
    }

    /**
     * @dev Menambahkan owner baru
     * @param newOwner Alamat owner baru
     */
    function addOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner address");
        require(!owners[newOwner], "Already an owner");
        
        owners[newOwner] = true;
        ownerCount++;
        emit OwnerAdded(newOwner);
    }

    /**
     * @dev Menghapus owner
     * @param ownerToRemove Alamat owner yang akan dihapus
     */
    function removeOwner(address ownerToRemove) external onlyOwner {
        require(owners[ownerToRemove], "Not an owner");
        require(ownerCount > 1, "Cannot remove last owner");
        
        owners[ownerToRemove] = false;
        ownerCount--;
        emit OwnerRemoved(ownerToRemove);
    }

    /**
     * @dev Validasi UserOperation sesuai EIP-4337
     */
    function validateUserOp(
        bytes calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external returns (uint256 validationData) {
        require(msg.sender == entryPoint, "Only EntryPoint");
        
        // 1. Verifikasi signature
        bytes memory signature = extractSignature(userOp);
        require(isValidSignature(userOpHash, signature), "Invalid signature");

        // 2. Bayar fee ke EntryPoint jika diperlukan
        if (missingWalletFunds > 0) {
            (bool success, ) = msg.sender.call{value: missingWalletFunds}("");
            require(success, "Failed to pay fee");
        }

        return 0; // Validation successful
    }

    /**
     * @dev Implementasi ERC-1271 untuk signature validation
     */
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) public view override returns (bytes4 magicValue) {
        address recovered = hash.recover(signature);
        return owners[recovered] ? this.isValidSignature.selector : bytes4(0);
    }

    /**
     * @dev Eksekusi transaksi arbitrary
     * @param target Alamat target
     * @param value Jumlah ETH yang dikirim
     * @param data Data call
     */
    function execute(
        address target,
        uint256 value,
        bytes memory data
    ) external onlyOwner returns (bytes memory) {
        (bool success, bytes memory result) = target.call{value: value}(data);
        
        if (success) {
            emit ExecutionSuccess(target, value, data);
        } else {
            emit ExecutionFailure(target, value, data);
        }
        
        return result;
    }

    /**
     * @dev Ekstrak signature dari UserOp (simplified)
     */
    function extractSignature(bytes calldata userOp) internal pure returns (bytes memory) {
        return userOp[userOp.length - 65:];
    }

    /**
     * @dev Cek saldo ETH wallet
     */
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    // Terima ETH
    receive() external payable {}
}

/**
 * @title AdvancedSmartWalletFactory - Factory untuk deploy Smart Wallets v2.0
 * @notice Factory dengan versioning dan tracking wallet yang lebih baik
 */
contract AdvancedSmartWalletFactory {
    // Informasi versi
    string public constant VERSION = "2.0";
    string public constant NAME = "AdvancedSmartWalletFactory";
    
    address public immutable entryPoint;
    
    // Mapping untuk melacak wallet yang sudah di-deploy
    mapping(address => address[]) public userWallets;
    mapping(address => bool) public isWalletDeployed;

    event WalletCreated(address indexed wallet, address[] owners, string name);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    /**
     * @dev Deploy smart wallet baru
     * @param owners Daftar alamat owner
     * @param name Nama wallet
     */
    function deployWallet(
        address[] memory owners,
        string memory name
    ) external returns (address wallet) {
        wallet = address(new AdvancedSmartWallet(entryPoint, owners, name));
        
        for (uint256 i = 0; i < owners.length; i++) {
            userWallets[owners[i]].push(wallet);
        }
        
        isWalletDeployed[wallet] = true;
        emit WalletCreated(wallet, owners, name);
        return wallet;
    }

    /**
     * @dev Mendapatkan daftar wallet milik user
     * @param user Alamat user
     */
    function getWallets(address user) public view returns (address[] memory) {
        return userWallets[user];
    }

    /**
     * @dev Memeriksa apakah alamat adalah smart wallet
     * @param wallet Alamat yang akan diperiksa
     */
    function isSmartWallet(address wallet) public view returns (bool) {
        return isWalletDeployed[wallet];
    }
}