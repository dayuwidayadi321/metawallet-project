// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CoreV55 - Inheritable EIP-4337 Smart Wallet with Multi-Chain Support
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Version 5.5 featuring Enhanced Recovery System & Cross-Chain Security
 * @dev Audit Phase #5 - Critical Security Patches Implemented:
 *      - Fixed critical signature replay vulnerabilities (cross-chain/cross-contract)
 *      - Implemented chain-bound recovery nonces with contract address binding
 *      - Added guardian-specific nonce tracking for recovery requests
 * 
 * Major Features:
 * [NEW] LayerZero Multi-Chain Infrastructure Integration
 * [NEW] Safe Rollback Mechanism for Upgrades
 * [OPTIMIZED] Gas-Efficient Recovery System
 * 
 * Security Model:
 * - EIP-4337 Account Abstraction Compliance
 * - Multi-Signature Guardian Protection
 * - Time-Locked Critical Operations
 */
 
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./modules/EntryPointHandler.sol";
import "./modules/CrossChainHandler.sol";
import "./modules/PluginManager.sol";
import "./modules/RecoveryManager.sol";
import "./modules/GuardianManager.sol";
import "./modules/UpgradeManager.sol";
import "./modules/SecurityManager.sol";

abstract contract CoreV55 is 
    Initializable,
    UUPSUpgradeable,
    EntryPointHandler,
    CrossChainHandler,
    PluginManager,
    RecoveryManager,
    GuardianManager,
    UpgradeManager,
    SecurityManager
{
    /* ========== CONSTANTS ========== */
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 public constant MAX_PLUGIN_UNINSTALL_DELAY = 7 days;
    uint256 public constant CONFIRM_WINDOW = 24 hours;
    uint256 public constant ROLLBACK_WINDOW = 24 hours;
    uint16 public constant LZ_VERSION = 1;

    /* ========== IMMUTABLES ========== */
    address public immutable self;
    IEntryPoint public immutable entryPoint;
    uint256 public immutable CHAIN_ID;

    /* ========== STATE VARIABLES ========== */
    mapping(uint16 => bool) public isChainActive;
    uint256 public lastCrossChainOperation;

    /* ========== EVENTS ========== */
    event ChainStatusChanged(uint16 indexed chainId, bool active);
    event CrossChainOperation(uint16 indexed chainId, bytes payload);

    /* ========== MODIFIERS ========== */
    modifier onlyActiveChain(uint16 chainId) {
        require(isChainActive[chainId], "CoreV55: Chain inactive");
        _;
    }

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        EntryPointHandler(_entryPoint)
        SecurityManager(_gasOracle)
    {
        self = address(this);
        CHAIN_ID = block.chainid;
        _disableInitializers();
    }

    /* ========== INITIALIZER ========== */
    function __CoreV55_init(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown,
        address _lzEndpoint,
        uint16[] memory _supportedChainIds,
        bytes[] memory _trustedRemotes
    ) public virtual onlyInitializing {
        __EIP712_init("CoreV55", "5.5");
        __ReentrancyGuard_init();
        
        _initializeOwners(initialOwners);
        _initializeGuardians(initialGuardian, guardianThreshold, recoveryCooldown);
        _initializeCrossChain(_lzEndpoint, _supportedChainIds, _trustedRemotes);
        
        env.entryPoint = entryPoint;
        env.chainId = CHAIN_ID;
        env.securityDelay = 1 days;
    }

    /* ========== CROSS-CHAIN FUNCTIONS ========== */
    function _initializeCrossChain(
        address _lzEndpoint,
        uint16[] memory _chainIds,
        bytes[] memory _trustedRemotes
    ) internal {
        __CrossChainHandler_init(_lzEndpoint, _chainIds, _trustedRemotes);
        for (uint i = 0; i < _chainIds.length; i++) {
            isChainActive[_chainIds[i]] = true;
        }
    }

    function setChainActive(uint16 chainId, bool active) external onlyOwner {
        isChainActive[chainId] = active;
        emit ChainStatusChanged(chainId, active);
    }

    function _nonblockingLzReceive(
        uint16 _srcChainId,
        bytes calldata,
        bytes calldata _payload
    ) internal override onlyActiveChain(_srcChainId) {
        lastCrossChainOperation = block.timestamp;
        
        (bool success, bytes memory reason) = address(this).call(_payload);
        require(success, string(abi.encodePacked("CC call failed: ", reason)));
        
        emit CrossChainOperation(_srcChainId, _payload);
    }

    /* ========== UPGRADE SAFETY ========== */
    function _authorizeUpgrade(address newImpl) 
        internal 
        override 
        onlyOwner 
        whenNotLocked 
    {
        require(
            block.timestamp > lastCrossChainOperation + ROLLBACK_WINDOW,
            "Upgrade blocked: Recent cross-chain activity"
        );
        _validateUpgrade(newImpl);
    }

    /* ========== VIEW FUNCTIONS ========== */
    function version() external pure virtual returns (string memory) {
        return "5.5";
    }

    function getChainStatus(uint16 chainId) external view returns (bool) {
        return isChainActive[chainId];
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap; // Reduced from 100
}