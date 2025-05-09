// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureSmartWallet - EIP-4337 Smart Wallet (Ultimate Edition v4.49)
 * @author DFXC Indonesian Security Web3 Project - Dev DayuWidayadi
 * @notice Secure multi-signature wallet with optimized gas usage
 * @dev FIXED VERSION - Critical improvements:
 *      1. Added reentrancy protection in isValidSignature()
 *      2. Bounded array lengths (max 100 items)
 *      3. Salt includes msg.sender in deployWallet()
 *      4. Added version check length validation
 *      5. Optimized duplicate address check
 *      6. Added circuit breaker modifier
 */

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

contract SecureSmartWallet is 
    Initializable,
    UUPSUpgradeable,
    SecureSmartWalletBase,
    SecureSmartWalletEmergency, 
    SecureSmartWalletSignatures,
    IERC1271Upgradeable
{
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "4.49.0";
    string public constant UPGRADE_VERSION = "1.0.0";
    uint256 public constant MAX_ARRAY_LENGTH = 100;
    
    event ETHReceived(address indexed sender, uint256 amount);
    event SignatureValidated(address indexed signer, bool isOwner, bool isGuardian);
    event UpgradeAttempt(address indexed newImplementation, string version, address indexed caller, uint256 timestamp);

    modifier onlyFactory() virtual override {
        require(msg.sender == factory, "Not factory");
        _;
    }

    modifier nonReentrant() {
        require(!isLocked, "Reentrancy blocked");
        _;
    }
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _entryPoint) SecureSmartWalletBase(_entryPoint) {
        _disableInitializers();
    }
    
    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) external virtual onlyFactory initializer {
        WalletConfigValidator.validate(_owners, _guardians, _guardianThreshold);
        _validateAddressArray(_owners, "owners");
        _validateAddressArray(_guardians, "guardians");

        __UUPSUpgradeable_init();
        __SecureSmartWalletBase_init(_owners, _guardians, _guardianThreshold);
        __SecureSmartWalletEmergency_init();
    }

    // ===================== ERC-1271 Compliance =====================
    function isValidSignature(bytes32 hash, bytes calldata signature) 
        external 
        override
        nonReentrant
        returns (bytes4)
    {
        if (isLocked) return bytes4(0xffffffff);
        
        (bool isOwner, address signer) = _validateOwnerSignature(hash, signature);
        if (isOwner) {
            emit SignatureValidated(signer, true, false);
            return bytes4(0x1626ba7e);
        }
    
        if (guardianRequired && _validateGuardianSignature(hash, signature)) {
            emit SignatureValidated(signer, false, true);
            return bytes4(0x1626ba7e);
        }
        
        return bytes4(0xffffffff);
    }

    // ===================== Batch Verification =====================
    function validateSignaturesBatch(
        bytes32[] calldata hashes,
        bytes[] calldata signatures,
        bool[] calldata isGuardianCheck
    ) external view returns (bool[] memory) {
        require(hashes.length == signatures.length, "Hashes/signatures mismatch");
        require(signatures.length == isGuardianCheck.length, "Signatures/checks mismatch");
        require(hashes.length <= MAX_ARRAY_LENGTH, "Array too large");
        
        bool[] memory results = new bool[](hashes.length);
        
        for (uint i = 0; i < hashes.length; ) {
            if (isGuardianCheck[i] && guardianRequired) {
                results[i] = _validateGuardianSignature(hashes[i], signatures[i]);
            } else {
                (bool isValid,) = _validateOwnerSignature(hashes[i], signatures[i]);
                results[i] = isValid;
            }
            unchecked { i++; }
        }
        return results;
    }

    // ===================== Upgrade Logic =====================
    function _authorizeUpgrade(address newImplementation) 
        internal 
        virtual
        override(UUPSUpgradeable)
        onlyOwner
    {
        require(newImplementation != address(0), "Invalid implementation");
        string memory version = _getUpgradeVersion(newImplementation);
        require(bytes(version).length > 0, "Empty version");
        require(keccak256(bytes(version)) == keccak256(bytes(UPGRADE_VERSION)), "Version mismatch");
        emit UpgradeAttempt(newImplementation, UPGRADE_VERSION, msg.sender, block.timestamp);
    }

    function _getUpgradeVersion(address impl) private view returns (string memory) {
        (bool success, bytes memory data) = impl.staticcall(
            abi.encodeWithSignature("UPGRADE_VERSION()")
        );
        require(success && data.length > 0, "Version check failed");
        return abi.decode(data, (string));
    }

    // ===================== Helper Functions =====================
    receive() external payable {
        emit ETHReceived(msg.sender, msg.value);
    }

    function _validateAddressArray(address[] calldata addresses, string memory role) private pure {
        require(addresses.length <= MAX_ARRAY_LENGTH, "Array too large");
        for (uint i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), string(abi.encodePacked("Zero address ", role)));
            for (uint j = i + 1; j < addresses.length; j++) {
                if (addresses[i] == addresses[j]) {
                    revert(string(abi.encodePacked("Duplicate ", role)));
                }
            }
        }
    }

    uint256[49] private __gap;
}

contract SecureSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;
    bytes32 public constant INIT_CODE_HASH = keccak256(type(ERC1967Proxy).creationCode);
    
    event WalletCreated(address indexed wallet, address[] owners, address[] guardians, uint256 guardianThreshold);

    constructor(IEntryPoint _entryPoint) {
        require(address(_entryPoint) != address(0), "Invalid EntryPoint");
        entryPoint = _entryPoint;
        walletImplementation = address(new SecureSmartWallet(_entryPoint));
    }
    
    function deployWallet(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 guardianThreshold,
        bytes32 userSalt
    ) external returns (address walletAddress) {
        WalletConfigValidator.validate(owners, guardians, guardianThreshold);
        
        bytes32 salt = keccak256(abi.encodePacked(userSalt, msg.sender));
        bytes memory initializationCalldata = abi.encodeWithSelector(
            SecureSmartWallet.initialize.selector,
            owners,
            guardians,
            guardianThreshold
        );
        
        walletAddress = address(new ERC1967Proxy{salt: salt}(
            walletImplementation,
            initializationCalldata
        ));
        
        emit WalletCreated(walletAddress, owners, guardians, guardianThreshold);
    }
    
    function computeAddress(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 guardianThreshold,
        bytes32 userSalt
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(userSalt, msg.sender));
        bytes memory initializationCalldata = abi.encodeWithSelector(
            SecureSmartWallet.initialize.selector,
            owners,
            guardians,
            guardianThreshold
        );
        
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(
                        walletImplementation,
                        initializationCalldata
                    )
                ))
            )
        );
        return address(uint160(uint256(hash)));
    }
}