// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "./SecureSmartWallet.sol";

contract SecureSmartWalletFactory {
    using Clones for address;

    // EntryPoint dan GasOracle (diperlukan untuk inisialisasi wallet)
    address public immutable entryPoint;
    address public immutable gasOracle;

    // Template wallet untuk cloning (menghemat gas)
    address public immutable walletImplementation;

    // Mapping untuk menyimpan daftar wallet yang dibuat
    mapping(address => address[]) public walletsByOwner;
    mapping(address => bool) public isWalletFromFactory;

    event WalletCreated(address indexed owner, address indexed wallet);

    constructor(address _entryPoint, address _gasOracle) {
        entryPoint = _entryPoint;
        gasOracle = _gasOracle;

        // Deploy implementation wallet untuk cloning
        walletImplementation = address(
            new SecureSmartWallet(
                IEntryPoint(_entryPoint),
                _gasOracle
            )
        );
    }

    /**
     * @notice Membuat wallet baru dengan CREATE2 (alamat deterministik)
     * @param _owners Daftar pemilik wallet (minimal 1)
     * @param _guardians Daftar guardian (opsional)
     * @param _guardianThreshold Jumlah guardian yang diperlukan untuk recovery
     * @param _supportedChains Daftar chainId yang didukung (untuk cross-chain)
     * @param _defaultPaymaster Paymaster default (opsional)
     * @param _bundlerConfig Konfigurasi bundler (opsional)
     */
    function createWallet(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold,
        uint256[] calldata _supportedChains,
        address _defaultPaymaster,
        SecureSmartWallet.BundlerConfig calldata _bundlerConfig,
        bytes32 _salt // Untuk CREATE2
    ) external returns (address wallet) {
        require(_owners.length > 0, "No owners provided");

        // Clone wallet menggunakan template
        wallet = walletImplementation.cloneDeterministic(_salt);

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

        // Simpan wallet ke mapping
        for (uint256 i = 0; i < _owners.length; i++) {
            walletsByOwner[_owners[i]].push(wallet);
        }
        isWalletFromFactory[wallet] = true;

        emit WalletCreated(msg.sender, wallet);
    }

    /**
     * @notice Memprediksi alamat wallet sebelum dibuat
     */
    function predictWalletAddress(bytes32 _salt) public view returns (address) {
        return walletImplementation.predictDeterministicAddress(_salt, address(this));
    }
}