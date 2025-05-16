// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Import Modul-Modul yang Akan Dibuat
import "./modules/CoreV58Module_Ownership.sol";
import "./modules/CoreV58Module_AccountAbstraction.sol";
import "./modules/CoreV58Module_CrossChain.sol";
import "./modules/CoreV58Module_PluginSystem.sol";
import "./modules/CoreV58Module_Guardian.sol";
import "./modules/CoreV58Module_Upgrade.sol";
import "./interface/IUpgradable.sol";
import "./interface/IStorageCheck.sol";

abstract contract CoreV58 is
    Initializable,
    UUPSUpgradeable,
    CoreV58Module_Ownership,
    CoreV58Module_AccountAbstraction,
    CoreV58Module_CrossChain,
    CoreV58Module_PluginSystem,
    CoreV58Module_Guardian,
    CoreV58Module_Upgrade,
    IUpgradable,
    IStorageCheck
{
    /* ========== IMMUTABLES (Ditetapkan di constructor) ========== */
    address public immutable self;
    uint256 public immutable CHAIN_ID;
    address public immutable entryPoint;
    address public immutable gasOracle;

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) {
        entryPoint = _entryPoint;
        CHAIN_ID = block.chainid;
        self = address(this);
        gasOracle = _gasOracle;
        _disableInitializers();
    }

    /* ========== INITIALIZER ========== */
    function initialize(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown,
        address _lzEndpoint,
        uint16[] memory _supportedChainIds,
        bytes[] memory _trustedRemotes
    ) public virtual initializer {
        __OwnershipModule_init(initialOwners);
        __AccountAbstractionModule_init(IEntryPoint(entryPoint)); // Gunakan entryPoint immutable
        __CrossChainModule_init(ILayerZeroEndpoint(_lzEndpoint), _supportedChainIds, _trustedRemotes);
        __PluginSystemModule_init();
        __GuardianModule_init(initialGuardian, guardianThreshold, recoveryCooldown);
        __UpgradeModule_init();
        // Tidak perlu inisialisasi ulang state immutable di sini
    }

    /* ========== OVERRIDE FUNCTIONS (Jika diperlukan) ========== */
    function VERSION() external pure override returns (string memory) {
        return "5.8";
    }

    function isStorageCompatible(address oldImpl) external view override returns (bool) {
        // Implementasikan logika kompatibilitas storage di modul Upgrade atau di sini
        // Ini akan bergantung pada bagaimana Anda mengelola perubahan storage antar versi
        return true; // Contoh sederhana, perlu implementasi sesuai kebutuhan
    }

    /* ========== FALLBACK HANDLER (Delegasikan ke Plugin System) ========== */
    fallback() external payable virtual override {
        _executePluginFallback(); // Fungsi dari CoreV58Module_PluginSystem
    }

    /* ========== RECEIVE EXTERNAL (Delegasikan ke Modul yang sesuai jika perlu) ========== */
    receive() external payable virtual override {
        emit ETHReceived(msg.sender, msg.value); // Event mungkin didefinisikan di modul lain
    }

    /* ========== STORAGE GAP (Jika diperlukan) ========== */
    uint256[100] private __gap;
}
