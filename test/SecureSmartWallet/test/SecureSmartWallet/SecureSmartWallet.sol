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
 * @title SecureSmartWallet - EIP-4337 Smart Wallet
 * @dev Main contract that combines all wallet functionality through inheritance
 */
contract SecureSmartWallet is 
    Initializable,
    UUPSUpgradeable,
    SecureSmartWalletBase,
    SecureSmartWalletEmergency, 
    SecureSmartWalletSignatures,
    IERC1271Upgradeable
{
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "4.48.1";
    string public constant UPGRADE_VERSION = "1.0.0";
    
    event ETHReceived(address indexed sender, uint256 amount);
    event SignatureValidated(address indexed signer, bool isOwner, bool isGuardian);
    event UpgradeAttempt(address indexed newImplementation, string version, address indexed caller, uint256 timestamp);

    address public factory;
    bool private _initialized;
    
    modifier onlyFactory() {
        require(msg.sender == factory, "Not factory");
        _;
    }
    
    modifier onlyOnce() {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _;
    }
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _entryPoint, address _factory) SecureSmartWalletBase(_entryPoint) {
        require(_factory != address(0), "Invalid factory");
        factory = _factory;
        _disableInitializers();
    }
    
    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) external onlyFactory onlyOnce initializer {
        require(_owners.length > 0, "No owners");
        require(_guardianThreshold > 0 && _guardianThreshold <= _guardians.length, "Invalid threshold");
        require(_owners.length <= 10, "Too many owners");
        require(_guardians.length <= 20, "Too many guardians");

        // Check for duplicates and zero addresses
        for (uint i = 0; i < _owners.length; i++) {
            require(_owners[i] != address(0), "Zero address owner");
            for (uint j = i + 1; j < _owners.length; j++) {
                require(_owners[i] != _owners[j], "Duplicate owner");
            }
        }

        __UUPSUpgradeable_init();
        __SecureSmartWalletBase_init(_owners, _guardians, _guardianThreshold);
        __SecureSmartWalletEmergency_init();
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        if (_isLocked) return bytes4(0xffffffff);
        
        (bool isOwner, address signer) = _validateOwnerSignature(hash, signature);
        bool isGuardian = _validateGuardianSignature(hash, signature);
        
        emit SignatureValidated(signer, isOwner, isGuardian);
        
        if (isOwner) return bytes4(0x1626ba7e);
        if (isGuardian && guardianRequired) return bytes4(0x1626ba7e);
        
        return bytes4(0xffffffff);
    }

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

    receive() external payable nonReentrant {
        emit ETHReceived(msg.sender, msg.value);
    }

    uint256[50] private __gap;
}

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