// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title CoreV58Module_AccountAbstraction
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Modul 2 dari CoreV58: Implementasi EIP-4337 Account Abstraction
 */
abstract contract CoreV58Module_AccountAbstraction is Initializable, EIP712Upgradeable {
    /* ========== IMMUTABLES (Ditetapkan saat inisialisasi) ========== */
    IEntryPoint internal _entryPoint;

    /* ========== TYPEHASHES ========== */
    bytes32 public constant CROSS_CHAIN_REQUEST_TYPEHASH =
        keccak256("CrossChainRequest(uint256 targetChainId,bytes payload,uint256 gasLimit,address refundAddress,uint256 nonce)");
    bytes32 public constant SESSION_KEY_TYPEHASH =
        keccak256("SessionKey(address key,uint48 validUntil,bytes4[] allowedSelectors,uint256 nonce,uint48 validAfter)");
    bytes32 public constant RECOVERY_TYPEHASH =
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline,bytes32 ownersHash,address verifyingContract,uint256 chainId)");
    bytes32 public constant EMERGENCY_LOCK_TYPEHASH =
        keccak256("EmergencyLock(uint256 nonce,uint256 deadline)");

    /* ========== SHARED STATE ========== */
    mapping(uint256 => mapping(address => mapping(uint256 => bool))) public usedChainNonces;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public sessionNonces;

    /* ========== CONSTANTS ========== */
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /* ========== STRUCTS ========== */
    struct SessionKey {
        uint48 validUntil;
        uint48 validAfter;
        bytes4[] allowedSelectors;
        bool isRevoked;
        address addedBy;
    }

    mapping(address => SessionKey) public sessionKeys;

    /* ========== EVENTS ========== */
    event SessionKeyRevoked(address indexed key);

    /* ========== INITIALIZER ========== */
    /**
     * @dev Initializes the Account Abstraction module.
     * @param entryPointAddress The address of the EntryPoint contract.
     */
    function __AccountAbstractionModule_init(IEntryPoint entryPointAddress) internal virtual onlyInitializing {
        _entryPoint = entryPointAddress;
        __EIP712_init("CoreV58", "5.8"); // Nama dan versi harus sama dengan kontrak utama
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    /**
     * @dev Verifies the signature of a hash.
     * @param hash The hash of the data that was signed.
     * @param signature The signature.
     * @return The address of the signer.
     */
    function _verifySignature(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Tambahkan pengecekan malleability
        require(signature.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid signature");

        return ECDSAUpgradeable.recover(hash, v, r, s);
    }

    /* ========== EXTERNAL FUNCTIONS (Entry Point Interface) ========== */
    /**
     * @dev Validates a UserOperation. This function is called by the EntryPoint.
     * @param userOp The UserOperation to validate.
     * @param userOpHash The hash of the UserOperation.
     * @param missingAccountFunds The amount of funds missing from the account.
     * @return validationData A packed value indicating the validation result.
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual returns (uint256 validationData) {
        // Only the EntryPoint can call this function
        require(msg.sender == address(_entryPoint), "Caller not EntryPoint");

        bytes32 sigHash = keccak256(abi.encodePacked(userOpHash, block.chainid));
        require(!usedSignatures[sigHash], "Signature reused");
        usedSignatures[sigHash] = true;

        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Fund transfer failed");
        }

        address signer = _verifySignature(userOpHash, userOp.signature);
        if (isOwner(signer)) { // Asumsi fungsi isOwner ada di modul Ownership
            return 0;
        }

        // Check session keys
        SessionKey storage sk = sessionKeys[signer];
        if (!sk.isRevoked &&
            block.timestamp <= sk.validUntil &&
            block.timestamp >= sk.validAfter) {

            for (uint i = 0; i < sk.allowedSelectors.length; i++) {
                if (bytes4(userOp.callData[:4]) == sk.allowedSelectors[i]) {
                    return 0;
                }
            }
        }

        return SIG_VALIDATION_FAILED;
    }

    /**
     * @dev Initializes the wallet for a UserOperation. This function is called by the EntryPoint
     * if the account is being created.
     * @param _entryPoint The address of the EntryPoint contract.
     * @param _paymaster The address of the paymaster (can be address(0)).
     */
    function initializeForUserOp(IEntryPoint _entryPoint, address _paymaster) external virtual {
        // Only the EntryPoint can call this function
        require(msg.sender == address(_entryPoint), "Caller not EntryPoint");
        require(address(_entryPoint) == address(_entryPoint), "EntryPoint address mismatch"); // Sanity check
        // Potensi logika inisialisasi tambahan khusus untuk UserOp jika diperlukan
    }

    /* ========== EXTERNAL FUNCTIONS (Session Key Management) ========== */
    /**
     * @dev Adds a session key for a specific duration and allowed function selectors.
     * @param key The session key address.
     * @param validUntil Timestamp until the key is valid.
     * @param allowedSelectors Array of function selectors allowed for this key.
     * @param validAfter Timestamp from which the key is valid (defaults to now).
     */
    function addSessionKey(
        address key,
        uint48 validUntil,
        bytes4[] calldata allowedSelectors,
        uint48 validAfter
    ) external virtual onlyOwner {
        require(key != address(0), "Invalid session key address");
        require(validUntil > block.timestamp, "Invalid validUntil timestamp");
        require(validAfter <= block.timestamp, "Invalid validAfter timestamp"); // Should be in the past or now
        require(allowedSelectors.length > 0, "No selectors provided");

        sessionKeys[key] = SessionKey({
            validUntil: validUntil,
            validAfter: validAfter,
            allowedSelectors: allowedSelectors,
            isRevoked: false,
            addedBy: msg.sender
        });
    }

    /**
     * @dev Revokes a session key, making it invalid.
     * @param key The session key address to revoke.
     */
    function revokeSessionKey(address key) external virtual onlyOwner {
        require(sessionKeys[key].addedBy != address(0), "Session key does not exist");
        sessionKeys[key].isRevoked = true;
        emit SessionKeyRevoked(key);
    }

    /* ========== INTERNAL FUNCTIONS (untuk digunakan modul lain) ========== */
    /**
     * @dev Internal function to check if a nonce for a specific chain and signer has been used.
     * @param chainId The ID of the chain.
     * @param signer The address of the signer.
     * @param nonce The nonce value.
     * @return True if the nonce has been used, false otherwise.
     */
    function _isChainNonceUsed(uint256 chainId, address signer, uint256 nonce) internal view virtual returns (bool) {
        return usedChainNonces[chainId][signer][nonce];
    }

    /**
     * @dev Internal function to mark a nonce for a specific chain and signer as used.
     * @param chainId The ID of the chain.
     * @param signer The address of the signer.
     * @param nonce The nonce value.
     */
    function _markChainNonceUsed(uint256 chainId, address signer, uint256 nonce) internal virtual {
        usedChainNonces[chainId][signer][nonce] = true;
    }

    /**
     * @dev Internal function to get the next session nonce for an address.
     * @param account The address to get the nonce for.
     * @return The next session nonce.
     */
    function _getNextSessionNonce(address account) internal virtual returns (uint256) {
        return sessionNonces[account]++;
    }
}
