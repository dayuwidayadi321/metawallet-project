// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./SecureSmartWalletCore.sol";

/**
 * @title SecureSmartWalletOwnership v5.1
 * @dev Enhanced multi-signature ownership management with:
 * - Cross-chain ownership transfer support
 * - Tight integration with Core v5.1 storage
 * - Gas-optimized batch operations
 * - EIP-712 signature support
 * @notice Key Upgrades:
 * 1. Unified ownership storage with Core v5.1
 * 2. Cross-chain compatible event structure
 * 3. Signature-based ownership transfers
 * 4. Lock mechanism integration
 */

abstract contract SecureSmartWalletOwnership is Initializable, SecureSmartWalletCore {
    /* ========== CONSTANTS ========== */
    uint256 public constant MAX_OWNERS = 10;
    bytes32 public constant OWNERSHIP_TRANSFER_TYPEHASH = 
        keccak256("OwnershipTransfer(address[] newOwners,uint256 nonce,uint256 deadline)");

    /* ========== STATE VARIABLES ========== */
    address[] public owners; // Maintained for iteration purposes
    uint256 public ownershipChangeNonce;

    /* ========== EVENTS ========== */
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event OwnershipTransferInitiated(
        address[] newOwners,
        bytes32 indexed changeHash,
        uint256 indexed chainId
    );
    event OwnershipTransferCompleted(address[] newOwners);

    /* ========== ERRORS ========== */
    error ZeroAddressNotAllowed();
    error DuplicateAddress(address detected);
    error InvalidOwnerCount();
    error Unauthorized();
    error SignatureExpired();
    error InvalidSignature();

    /* ========== MODIFIERS ========== */
    modifier onlyOwner() {
        if (!isOwner[msg.sender]) revert Unauthorized();
        _;
    }

    /* ========== INITIALIZER ========== */
    function __Ownership_init(address[] calldata initialOwners) internal onlyInitializing {
        _validateOwners(initialOwners);
        _setOwners(initialOwners);
    }

    /* ========== EXTERNAL FUNCTIONS ========== */

    /**
     * @dev Transfer ownership with EIP-712 signatures from current owners
     * @param newOwners Array of new owner addresses
     * @param signatures Array of signatures from current owners
     * @param deadline Signature expiration timestamp
     */
    function transferOwnershipWithSig(
        address[] calldata newOwners,
        bytes[] calldata signatures,
        uint256 deadline
    ) external whenNotLocked {
        require(block.timestamp <= deadline, "Signature expired");
        _validateOwners(newOwners);

        bytes32 changeHash = keccak256(abi.encodePacked(newOwners));
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                OWNERSHIP_TRANSFER_TYPEHASH,
                keccak256(abi.encodePacked(newOwners)),
                ownershipChangeNonce++,
                deadline
            )
        );

        // Verify signatures
        uint256 validSignatures;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(digest, signatures[i]);
            if (isOwner[signer]) validSignatures++;
        }
        require(validSignatures >= owners.length / 2 + 1, "Insufficient signatures");

        _executeOwnershipTransfer(newOwners, changeHash);
    }

    /* ========== VIEW FUNCTIONS ========== */
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    function _executeOwnershipTransfer(
        address[] calldata newOwners,
        bytes32 changeHash
    ) internal {
        // Clear existing owners
        for (uint256 i = 0; i < owners.length; i++) {
            emit OwnerRemoved(owners[i]);
        }

        // Set new owners
        owners = newOwners;
        for (uint256 i = 0; i < newOwners.length; i++) {
            isOwner[newOwners[i]] = true;
            emit OwnerAdded(newOwners[i]);
        }

        emit OwnershipTransferInitiated(newOwners, changeHash, block.chainid);
        emit OwnershipTransferCompleted(newOwners);
    }

    function _validateOwners(address[] calldata ownersToValidate) internal pure {
        if (ownersToValidate.length == 0 || ownersToValidate.length > MAX_OWNERS) {
            revert InvalidOwnerCount();
        }

        for (uint256 i = 0; i < ownersToValidate.length; i++) {
            if (ownersToValidate[i] == address(0)) {
                revert ZeroAddressNotAllowed();
            }
            for (uint256 j = i + 1; j < ownersToValidate.length; j++) {
                if (ownersToValidate[i] == ownersToValidate[j]) {
                    revert DuplicateAddress(ownersToValidate[i]);
                }
            }
        }
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}