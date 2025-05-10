// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "./SecureSmartWalletCore.sol";

/*
* @title SecureSmartWallet - EIP-4337 Smart Wallet (v5.1 - Ultimate Edition)
* @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
* @dev Main contract that combines all wallet functionality through Core v5.1
*/

contract SecureSmartWallet is 
    Initializable,
    UUPSUpgradeable,
    SecureSmartWalletCore,
    IERC1271Upgradeable
{
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "5.1";
    string public constant UPGRADE_VERSION = "5.1";

    /// EVENT
    event WalletInitialized(address[] owners, address[] guardians);
    event SignatureValidated(address indexed signer, bool isOwner);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        SecureSmartWalletCore(_entryPoint, _gasOracle) 
    {
        _disableInitializers();
    }

    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) external initializer {
        __UUPSUpgradeable_init();
        
        // Inisialisasi owner
        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
        }
        
        // Inisialisasi guardian
        guardianConfig.threshold = uint64(_guardianThreshold);
        for (uint256 i = 0; i < _guardians.length; i++) {
            guardianConfig.isActive[_guardians[i]] = true;
        }
        
        factory = msg.sender;
        
        emit WalletInitialized(_owners, _guardians);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) 
        external 
        view 
        override 
        returns (bytes4) 
    {
        if (env.isLocked) return bytes4(0xffffffff);
        
        bool isValid = _verifySignature(hash, signature);
        return isValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    function _authorizeUpgrade(address newImplementation) 
        internal 
        override
        onlyOwner
    {
        require(newImplementation != address(0), "Invalid implementation");
        require(newImplementation != address(this), "Cannot upgrade to self");
        
        string memory newVersion = SecureSmartWallet(payable(newImplementation)).UPGRADE_VERSION();
        require(
            keccak256(abi.encodePacked(UPGRADE_VERSION)) == 
            keccak256(abi.encodePacked(newVersion)),
            "Version mismatch"
        );
    }

    uint256[50] private __gap;
}

contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;
    address public immutable gasOracle;
    
    event WalletCreated(address indexed wallet, address[] owners, address[] guardians, uint256 guardianThreshold);

    constructor(IEntryPoint _entryPoint, address _gasOracle) {
        require(address(_entryPoint) != address(0), "Invalid EntryPoint");
        require(_gasOracle != address(0), "Invalid Gas Oracle");
        entryPoint = _entryPoint;
        gasOracle = _gasOracle;
        walletImplementation = address(new SecureSmartWallet(_entryPoint, _gasOracle));
    }
    
    function deployWallet(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 guardianThreshold
    ) external returns (address walletAddress) {
        require(owners.length > 0, "No owners provided");
        require(guardians.length >= guardianThreshold, "Invalid guardian threshold");
        require(guardianThreshold > 0, "Threshold must be > 0");
        
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

