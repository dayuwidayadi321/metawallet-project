// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureSmartWalletGuardian v5.1
 * @dev Upgraded guardian system with:
 * - Cross-chain recovery support
 * - Session-based guardian approvals
 * - Gas-optimized batch operations
 * - Tight integration with Core v5.1
 * @notice New Features:
 * 1. Multi-chain guardian management
 * 2. Temporary guardian mandates (time-bound)
 * 3. Optimized storage layout
 * 4. EIP-712 signatures for remote operations
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "./SecureSmartWalletCore.sol";

abstract contract SecureSmartWalletGuardian is Initializable, EIP712Upgradeable, SecureSmartWalletCore {
    using ECDSAUpgradeable for bytes32;

    /* ========== CONSTANTS ========== */
    uint256 public constant MAX_GUARDIANS = 20;
    uint64 public constant DEFAULT_COOLDOWN = 24 hours;
    bytes32 public constant RECOVERY_APPROVAL_TYPEHASH = 
        keccak256("RecoveryApproval(address wallet,address[] newOwners,uint256 nonce,uint256 deadline)");

    /* ========== STRUCTS ========== */
    struct GuardianMandate {
        uint48 validUntil;
        bytes4[] allowedFunctions;
    }

    /* ========== STATE VARIABLES ========== */
    mapping(address => GuardianMandate) public guardianMandates;
    mapping(address => uint256) public recoveryNonces;
    address[] public activeGuardians;

    /* ========== EVENTS ========== */
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event GuardianMandateCreated(address indexed guardian, uint48 expiry);
    event CrossChainRecoveryInitiated(address[] newOwners, uint256 chainId);

    /* ========== ERRORS ========== */
    error InvalidGuardianConfig();
    error InvalidSignature();
    error MandateExpired();
    error UnauthorizedFunction();

    /* ========== MODIFIERS ========== */
    modifier onlyMandatedFunction(bytes4 selector) {
        GuardianMandate memory mandate = guardianMandates[msg.sender];
        if (block.timestamp > mandate.validUntil) revert MandateExpired();
        if (!_isFunctionAllowed(selector, mandate.allowedFunctions)) revert UnauthorizedFunction();
        _;
    }

    /* ========== INITIALIZER ========== */
    function __Guardian_init(
        address[] calldata initialGuardians,
        uint256 initialThreshold
    ) internal onlyInitializing {
        __EIP712_init("SecureSmartWalletGuardian", "5.1");
        _updateGuardians(initialGuardians, initialThreshold);
        guardianConfig.cooldown = uint64(DEFAULT_COOLDOWN);
    }

    /* ========== EXTERNAL FUNCTIONS ========== */
    function updateGuardiansWithSig(
        address[] calldata newGuardians,
        uint256 newThreshold,
        bytes calldata signature
    ) external {
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                keccak256("UpdateGuardians(address[] newGuardians,uint256 newThreshold,uint256 nonce)"),
                keccak256(abi.encodePacked(newGuardians)),
                newThreshold,
                recoveryNonces[msg.sender]++
            )
        );
        _verifyGuardianSignature(digest, signature);
        _updateGuardians(newGuardians, newThreshold);
    }

    function createGuardianMandate(
        uint48 validUntil,
        bytes4[] calldata allowedFunctions
    ) external onlyActiveGuardian {
        guardianMandates[msg.sender] = GuardianMandate(validUntil, allowedFunctions);
        emit GuardianMandateCreated(msg.sender, validUntil);
    }

    /* ========== CROSS-CHAIN FUNCTIONS ========== */
    function approveCrossChainRecovery(
        address[] calldata newOwners,
        uint256 chainId,
        uint256 deadline,
        bytes calldata signature
    ) external onlyActiveGuardian {
        require(block.timestamp <= deadline, "Signature expired");
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                RECOVERY_APPROVAL_TYPEHASH,
                address(this),
                keccak256(abi.encodePacked(newOwners)),
                recoveryNonces[msg.sender]++,
                deadline
            )
        );
        _verifyGuardianSignature(digest, signature);
        emit CrossChainRecoveryInitiated(newOwners, chainId);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    function _updateGuardians(
        address[] calldata newGuardians,
        uint256 newThreshold
    ) internal {
        require(newThreshold <= newGuardians.length, "Invalid threshold");
        require(newGuardians.length <= MAX_GUARDIANS, "Exceeds max guardians");

        // Clear existing guardians
        for (uint256 i = 0; i < activeGuardians.length; i++) {
            guardianConfig.isActive[activeGuardians[i]] = false;
            emit GuardianRemoved(activeGuardians[i]);
        }

        // Set new guardians
        activeGuardians = newGuardians;
        guardianConfig.threshold = uint64(newThreshold);

        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "Zero address");
            require(!guardianConfig.isActive[guardian], "Duplicate guardian");
            
            guardianConfig.isActive[guardian] = true;
            emit GuardianAdded(guardian);
        }
    }

    function _verifyGuardianSignature(bytes32 digest, bytes memory signature) internal view {
        address signer = digest.recover(signature);
        require(_isActiveGuardian(signer), "Invalid guardian signature");
    }

    function _isFunctionAllowed(bytes4 selector, bytes4[] memory allowedFunctions) 
        internal pure returns (bool) 
    {
        for (uint256 i = 0; i < allowedFunctions.length; i++) {
            if (selector == allowedFunctions[i]) return true;
        }
        return false;
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}