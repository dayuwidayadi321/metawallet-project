// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "./SecureSmartWallet.sol";

contract SecureSmartWalletFactory {
    using Clones for address;

    address public immutable entryPoint;
    address public immutable gasOracle;
    address public immutable walletImplementation;
    
    // Mapping untuk melacak wallet
    mapping(address => address[]) public walletsByOwner;
    mapping(address => bool) public isWalletFromFactory;
    mapping(bytes32 => bool) public usedSalts;

    event WalletCreated(address indexed creator, address indexed owner, address indexed wallet);
    event WalletInitialized(
        address indexed wallet,
        address[] owners,
        address[] guardians,
        uint256 guardianThreshold,
        address defaultPaymaster
    );

    constructor(address _entryPoint, address _gasOracle) {
        require(_entryPoint != address(0), "Invalid EntryPoint");
        require(_gasOracle != address(0), "Invalid GasOracle");
        
        entryPoint = _entryPoint;
        gasOracle = _gasOracle;
        
        // Deploy implementation wallet sekali saja
        walletImplementation = address(new SecureSmartWallet(IEntryPoint(_entryPoint), _gasOracle));
    }

    /**
     * @notice Membuat wallet baru dengan CREATE2
     * @param _owners Daftar pemilik wallet (minimal 1)
     * @param _salt Salt untuk deterministik address (harus unik)
     */
    function createWallet(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint64 _guardianThreshold,
        uint256[] calldata _supportedChains,
        address _defaultPaymaster,
        SecureSmartWallet.BundlerConfig calldata _bundlerConfig,
        bytes32 _salt
    ) external returns (address wallet) {
        require(_owners.length > 0, "No owners");
        require(!usedSalts[_salt], "Salt already used");
        
        // Clone wallet
        wallet = walletImplementation.cloneDeterministic(_salt);
        usedSalts[_salt] = true;
        
        // Inisialisasi wallet
        SecureSmartWallet(payable(wallet)).initialize(
            _owners,
            _guardians,
            _guardianThreshold,
            address(this), // Factory sebagai referensi
            _supportedChains,
            _defaultPaymaster,
            _bundlerConfig
        );
        
        // Update mappings
        for (uint256 i = 0; i < _owners.length; i++) {
            walletsByOwner[_owners[i]].push(wallet);
        }
        isWalletFromFactory[wallet] = true;
        
        emit WalletCreated(msg.sender, _owners[0], wallet);
        emit WalletInitialized(
            wallet,
            _owners,
            _guardians,
            _guardianThreshold,
            _defaultPaymaster
        );
    }

    /**
     * @notice Memprediksi alamat wallet
     */
    function predictWalletAddress(bytes32 _salt) public view returns (address) {
        return walletImplementation.predictDeterministicAddress(_salt, address(this));
    }

    /**
     * @notice Mendapatkan daftar wallet milik seorang owner
     */
    function getWalletsByOwner(address owner) external view returns (address[] memory) {
        return walletsByOwner[owner];
    }
}
