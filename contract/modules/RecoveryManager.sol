// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

abstract contract RecoveryManager is EIP712Upgradeable, ReentrancyGuardUpgradeable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
    using ECDSAUpgradeable for bytes32;

    bytes32 public constant RECOVERY_TYPEHASH = 
        keccak256("Recovery(address[] newOwners,uint256 nonce,uint256 deadline,bytes32 ownersHash,address verifyingContract,uint256 chainId)");

    struct GuardianConfig {
        uint64 threshold;
        uint64 cooldown;
        uint64 lastRecoveryTimestamp;
        EnumerableSetUpgradeable.AddressSet guardians;
    }

    GuardianConfig internal _guardianConfig;
    mapping(address => uint256) public guardianRecoveryNonces;
    mapping(address => mapping(uint256 => bool)) public usedRecoveryNonces;
    mapping(bytes32 => bool) public usedSignatures;

    event RecoveryExecuted(address[] newOwners, bytes32 ownersHash, uint256 recoveryNonce, uint256 chainId, address initiator);
    event RecoveryInitiated(address indexed initiator, uint256 indexed nonce);
    event GuardianRecoveryNonceIncremented(address indexed guardian, uint256 newNonce);

    uint256 public constant MAX_RECOVERY_COOLDOWN = 30 days;
    uint256 public constant MIN_NEW_OWNERS = 1;
    uint256 public constant MAX_NEW_OWNERS = 10;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function __RecoveryManager_init() internal onlyInitializing {
        __EIP712_init("CoreV55", "5.5");
        __ReentrancyGuard_init();
    }

    /**
     * @dev Initiate wallet recovery process
     * @param newOwners Array of new owner addresses
     * @param signatures Array of guardian signatures
     * @param deadline Signature expiration timestamp
     * @param recoveryNonce Unique nonce for this recovery attempt
     */
    function initiateRecovery(
        address[] calldata newOwners, 
        bytes[] calldata signatures, 
        uint256 deadline,
        uint256 recoveryNonce
    ) external virtual nonReentrant whenNotPaused {
        // Validate basic parameters
        require(block.timestamp <= deadline, "Recovery: Signature expired");
        require(newOwners.length >= MIN_NEW_OWNERS && newOwners.length <= MAX_NEW_OWNERS, "Recovery: Invalid owner count");
        require(!usedRecoveryNonces[msg.sender][recoveryNonce], "Recovery: Nonce used");
        require(_guardianConfig.guardians.length() > 0, "Recovery: No guardians");
        require(
            block.timestamp >= _guardianConfig.lastRecoveryTimestamp + _guardianConfig.cooldown,
            "Recovery: Cooldown active"
        );

        // Calculate and validate owners hash
        bytes32 ownersHash = keccak256(abi.encodePacked(newOwners));
        usedRecoveryNonces[msg.sender][recoveryNonce] = true;
        emit RecoveryInitiated(msg.sender, recoveryNonce);
        
        // Generate and validate recovery hash
        bytes32 recoveryHash = _hashTypedDataV4(keccak256(abi.encode(
            RECOVERY_TYPEHASH,
            ownersHash,
            recoveryNonce,
            deadline,
            address(this),
            block.chainid
        )));
        
        // Prevent signature replay
        bytes32 recoveryId = keccak256(abi.encodePacked(recoveryHash, block.chainid, address(this)));
        require(!usedSignatures[recoveryId], "Recovery: Signature used");
        usedSignatures[recoveryId] = true;

        // Verify guardian signatures
        uint256 validSignatures = _verifyGuardianSignatures(recoveryHash, signatures);
        require(validSignatures >= _guardianConfig.threshold, "Recovery: Insufficient approvals");

        // Execute recovery
        _replaceOwners(newOwners);
        _guardianConfig.lastRecoveryTimestamp = uint64(block.timestamp);
        
        emit RecoveryExecuted(newOwners, ownersHash, recoveryNonce, block.chainid, msg.sender);
    }

    /**
     * @dev Internal function to verify guardian signatures
     * @param recoveryHash The hash of the recovery request
     * @param signatures Array of guardian signatures
     * @return validSignatures Number of valid signatures
     */
    function _verifyGuardianSignatures(
        bytes32 recoveryHash,
        bytes[] calldata signatures
    ) internal view returns (uint256 validSignatures) {
        address[] memory guardianList = _guardianConfig.guardians.values();
        address[] memory seenGuardians = new address[](guardianList.length);
        
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoveryHash.recover(signatures[i]);
            
            if (_guardianConfig.guardians.contains(signer)) {
                // Check for duplicate signatures
                bool alreadySeen = false;
                for (uint j = 0; j < validSignatures; j++) {
                    if (seenGuardians[j] == signer) {
                        alreadySeen = true;
                        break;
                    }
                }
                
                if (!alreadySeen) {
                    seenGuardians[validSignatures] = signer;
                    validSignatures++;
                    
                    // Early exit if threshold reached
                    if (validSignatures >= _guardianConfig.threshold) break;
                }
            }
        }
    }

    /**
     * @dev Replace current owners with new owners
     * @param newOwners Array of new owner addresses
     */
    function _replaceOwners(address[] calldata newOwners) internal virtual {
        uint256 ownerCount = _owners.length();
        
        // Remove existing owners in reverse order
        for (uint i = ownerCount; i > 0; i--) {
            _owners.remove(_owners.at(i - 1));
        }
        
        // Add new owners with validation
        for (uint i = 0; i < newOwners.length; i++) {
            require(newOwners[i] != address(0), "Recovery: Invalid owner");
            require(!_owners.contains(newOwners[i]), "Recovery: Owner exists");
            require(_owners.add(newOwners[i]), "Recovery: Add failed");
        }
    }

    /**
     * @dev Increment recovery nonce for a guardian
     * @param guardian Address of the guardian
     */
    function incrementRecoveryNonce(address guardian) external onlyOwner {
        uint256 newNonce = ++guardianRecoveryNonces[guardian];
        emit GuardianRecoveryNonceIncremented(guardian, newNonce);
    }

    // Storage gap for future upgrades
    uint256[50] private __gap;
}