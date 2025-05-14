// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

abstract contract EntryPointHandler is ReentrancyGuardUpgradeable {
    using ECDSAUpgradeable for bytes32;

    // Constants
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant SIGNATURE_LENGTH = 65;
    uint256 internal constant S_MAX = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // Immutables
    IEntryPoint public immutable entryPoint;
    
    // Structures
    struct ExecutionEnvironment {
        IEntryPoint entryPoint;
        address defaultPaymaster;
        uint256 chainId;
        bool isLocked;
        uint256 upgradeTimelock;
        uint256 securityDelay;
    }

    struct SessionKey {
        uint48 validUntil;
        uint48 validAfter;
        bytes4[] allowedSelectors;
        bool isRevoked;
        address addedBy;
    }

    // State variables
    ExecutionEnvironment public env;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => SessionKey) public sessionKeys;
    mapping(address => uint256) public sessionNonces;

    // Events
    event UserOperationValidated(address indexed sender, bytes32 userOpHash);
    event SessionKeyUsed(address indexed sessionKey, bytes4 selector);
    event SignatureReused(bytes32 sigHash);
    event FundsDeposited(uint256 amount);

    // Errors
    error InvalidSignatureLength(uint256 length);
    error InvalidSignatureSValue();
    error SignatureReused(bytes32 sigHash);
    error CallerNotEntryPoint(address caller);
    error FundTransferFailed();
    error InvalidSessionKey(address sessionKey);
    error SessionKeyRevoked(address sessionKey);
    error SessionKeyExpired(address sessionKey);
    error SelectorNotAllowed(bytes4 selector);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    function __EntryPointHandler_init() internal onlyInitializing {
        __ReentrancyGuard_init();
    }

    /**
     * @dev Validate a user operation
     * @param userOp The user operation to validate
     * @param userOpHash Hash of the user operation
     * @param missingAccountFunds Funds needed to be deposited
     * @return validationData Validation data (see ERC-4337)
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual onlyEntryPoint nonReentrant returns (uint256 validationData) {
        bytes32 sigHash = keccak256(abi.encodePacked(userOpHash, block.chainid));
        
        if (usedSignatures[sigHash]) {
            emit SignatureReused(sigHash);
            revert SignatureReused(sigHash);
        }
        usedSignatures[sigHash] = true;

        // Handle missing funds
        if (missingAccountFunds > 0) {
            _depositFunds(missingAccountFunds);
        }

        address signer = _verifySignature(userOpHash, userOp.signature);
        
        // Owner validation
        if (_owners.contains(signer)) {
            emit UserOperationValidated(userOp.sender, userOpHash);
            return 0;
        }

        // Session key validation
        SessionKey storage sk = sessionKeys[signer];
        return _validateSessionKey(sk, userOp.callData);
    }

    /**
     * @dev Internal function to validate session keys
     */
    function _validateSessionKey(SessionKey storage sk, bytes calldata callData) 
        internal 
        view 
        returns (uint256 validationData) 
    {
        if (sk.isRevoked) {
            revert SessionKeyRevoked(address(this));
        }
        if (block.timestamp > sk.validUntil || block.timestamp < sk.validAfter) {
            revert SessionKeyExpired(address(this));
        }

        bytes4 selector = bytes4(callData[:4]);
        for (uint i = 0; i < sk.allowedSelectors.length; i++) {
            if (sk.allowedSelectors[i] == selector) {
                emit SessionKeyUsed(address(this), selector);
                return 0;
            }
        }
        
        revert SelectorNotAllowed(selector);
    }

    /**
     * @dev Deposit funds to the entry point
     * @param amount Amount to deposit
     */
    function _depositFunds(uint256 amount) internal {
        (bool success,) = payable(address(entryPoint)).call{value: amount}("");
        if (!success) {
            revert FundTransferFailed();
        }
        emit FundsDeposited(amount);
    }

    /**
     * @dev Verify an ECDSA signature
     * @param hash Hash of the signed message
     * @param signature Signature to verify
     * @return signer Address of the signer
     */
    function _verifySignature(bytes32 hash, bytes memory signature) 
        internal 
        view 
        returns (address) 
    {
        if (signature.length != SIGNATURE_LENGTH) {
            revert InvalidSignatureLength(signature.length);
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (uint256(s) > S_MAX) {
            revert InvalidSignatureSValue();
        }

        return hash.recover(v, r, s);
    }

    /**
     * @dev Modifier to restrict access to the entry point
     */
    modifier onlyEntryPoint() virtual {
        if (msg.sender != address(env.entryPoint)) {
            revert CallerNotEntryPoint(msg.sender);
        }
        _;
    }

    // Storage gap for future upgrades
    uint256[50] private __gap;
}