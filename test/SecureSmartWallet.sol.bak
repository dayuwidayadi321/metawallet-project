// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "./SecureSmartWalletBase.sol";
import "./SecureSmartWalletEmergency.sol";
import "./SecureSmartWalletSignatures.sol";
import "./WalletConfigValidator.sol";

/**
 * @title SecureSmartWallet - EIP-4337 Smart Wallet (Ultimate Edition)
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 * @notice Secure multi-signature wallet with guardian protection and upgradeability
 * @dev Combines all wallet functionality through modular inheritance
 */
contract SecureSmartWallet is 
    Initializable,
    UUPSUpgradeable,
    SecureSmartWalletBase,
    SecureSmartWalletEmergency, 
    SecureSmartWalletSignatures,
    IERC1271Upgradeable
{
    // ===================== Constants =====================
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "4.48.1";
    string public constant UPGRADE_VERSION = "1.0.0";
    
    // ===================== Events =====================
    event ETHReceived(address indexed sender, uint256 amount);
    event SignatureValidated(address indexed signer, bool isOwner, bool isGuardian);
    event UpgradeAttempt(address indexed newImplementation, string version, address indexed caller, uint256 timestamp);

    // ===================== State Variables =====================
    bool private _initialized;
    
    // ===================== Modifiers =====================
    modifier onlyFactory() {
        require(msg.sender == SecureSmartWalletBase.factory, "Not factory");
        _;
    }
    
    modifier onlyOnce() {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _;
    }
    
    // ===================== Constructor =====================
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _entryPoint, address _factory) 
        SecureSmartWalletBase(_entryPoint, _factory) 
    {
        _disableInitializers();
    }
    
    // ===================== Initializer =====================
    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) external onlyFactory onlyOnce initializer {
        // Input validation
        require(_owners.length > 0, "No owners");
        require(_guardianThreshold > 0 && _guardianThreshold <= _guardians.length, "Invalid threshold");
        require(_owners.length <= 10, "Too many owners");
        require(_guardians.length <= 20, "Too many guardians");

        _validateAddressArray(_owners, "owners");
        _validateAddressArray(_guardians, "guardians");

        // Initialize inherited contracts
        __UUPSUpgradeable_init();
        __SecureSmartWalletBase_init(_owners, _guardians, _guardianThreshold);
        __SecureSmartWalletEmergency_init();
    }

    // ===================== Signature Verification =====================
    function isValidSignature(bytes32 hash, bytes memory signature) 
        external 
        view 
        returns (bytes4) 
    {
        if (_isLocked) return bytes4(0xffffffff);
        
        (bool isOwner, address signer) = SecureSmartWalletSignatures._validateOwnerSignature(hash, signature);
        bool isGuardian = SecureSmartWalletSignatures._validateGuardianSignature(hash, signature);
        
        emit SignatureValidated(signer, isOwner, isGuardian);
        
        if (isOwner) return bytes4(0x1626ba7e);
        if (isGuardian && SecureSmartWalletBase.guardianRequired) return bytes4(0x1626ba7e);
        
        return bytes4(0xffffffff);
    }

    // ===================== Upgrade Logic =====================
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override(UUPSUpgradeable, SecureSmartWalletBase)
        view
        onlyOwner
    {
        require(newImplementation != address(0), "Invalid implementation");
        require(newImplementation != address(this), "Cannot upgrade to self");
        
        (bool success, bytes memory data) = newImplementation.staticcall(
            abi.encodeWithSignature("UPGRADE_VERSION()")
        );
        require(success, "Version check failed");
        string memory newVersion = abi.decode(data, (string));
        
        require(
            keccak256(abi.encodePacked(UPGRADE_VERSION)) == 
            keccak256(abi.encodePacked(newVersion)),
            "Version mismatch"
        );
    }

    // ===================== Receive Ether =====================
    receive() external payable nonReentrant {
        emit ETHReceived(msg.sender, msg.value);
    }

    // ===================== Internal Functions =====================
    function _validateAddressArray(address[] calldata addresses, string memory role) private pure {
        for (uint i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), string(abi.encodePacked("Zero address ", role));
            for (uint j = i + 1; j < addresses.length; j++) {
                require(addresses[i] != addresses[j], string(abi.encodePacked("Duplicate ", role)));
            }
        }
    }

    // ===================== Storage Gap =====================
    uint256[50] private __gap;
}

/**
 * @title SecureSmartWalletFactory
 * @notice Factory for deploying SecureSmartWallet proxies
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 */
contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;
    
    event WalletCreated(address indexed wallet, address[] owners, address[] guardians, uint256 guardianThreshold);

    constructor(IEntryPoint _entryPoint) {
        require(address(_entryPoint) != address(0), "Invalid EntryPoint");
        entryPoint = _entryPoint;
        walletImplementation = address(new SecureSmartWallet(_entryPoint, address(this)));
    }
    
    function deployWallet(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 guardianThreshold
    ) external returns (address walletAddress) {
        WalletConfigValidator.validate(owners, guardians, guardianThreshold);
        
        ERC1967Proxy proxy = new ERC1967Proxy(
            walletImplementation,
            abi.encodeWithSelector(
                SecureSmartWallet.initialize.selector,
                owners,
                guardians,
                guardianThreshold
            )
        );
        
        walletAddress = address(proxy);
        emit WalletCreated(walletAddress, owners, guardians, guardianThreshold);
    }
}