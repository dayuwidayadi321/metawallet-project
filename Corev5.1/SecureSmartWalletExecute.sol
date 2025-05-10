// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./SecureSmartWalletCore.sol";

/**
 * @title SecureSmartWalletExecute v5.1
 * @dev Complete upgraded execution module with:
 * - Cross-chain operation support
 * - Gas oracle integration
 * - Plugin execution hooks
 * - Enhanced atomic batch processing
 * - Complete EIP-712 signature support
 * @notice Key Improvements:
 * 1. Full cross-chain execution capability
 * 2. Optimized gas management
 * 3. Complete plugin integration
 * 4. Enhanced security features
 */
abstract contract SecureSmartWalletExecute is SecureSmartWalletCore, ReentrancyGuardUpgradeable {
    using AddressUpgradeable for address;

    /* ========== CONSTANTS ========== */
    uint256 public constant MAX_BATCH_SIZE = 10;
    uint256 public constant GAS_RESERVE = 5000; // Gas buffer for post-hooks
    bytes32 public constant EXECUTION_BATCH_TYPEHASH = 
        keccak256("ExecutionBatch(address[] targets,uint256[] values,bytes[] datas,uint256 nonce,uint256 deadline)");

    /* ========== STRUCTS ========== */
    struct ExecutionResult {
        bool success;
        bytes result;
        uint256 gasUsed;
        bytes4 selector;
    }

    /* ========== STATE VARIABLES ========== */
    uint256 public executionNonce;
    mapping(bytes32 => bool) public executedBatches;

    /* ========== EVENTS ========== */
    event ExecutionSuccess(
        address indexed target,
        uint256 value,
        bytes4 selector,
        uint256 gasUsed,
        address indexed initiator
    );
    event ExecutionFailed(
        address indexed target,
        bytes4 selector,
        bytes reason,
        uint256 gasUsed,
        address indexed initiator
    );
    event CrossChainExecutionPrepared(
        bytes32 indexed batchHash,
        uint256 indexed targetChainId,
        address[] targets,
        uint256[] values
    );
    event PluginPostHookExecuted(
        address indexed plugin,
        address indexed target,
        bool success
    );

    /* ========== ERRORS ========== */
    error BatchLengthMismatch();
    error BatchSizeExceeded();
    error InvalidTarget(address target);
    error InvalidCallData();
    error ExecutionReverted(bytes reason);
    error InsufficientBatchValue(uint256 available, uint256 required);
    error InvalidSignature();
    error ExpiredDeadline();

    /* ========== MODIFIERS ========== */
    modifier onlyOwnerOrPlugin() {
        require(
            isOwner[msg.sender] || selectorToPlugin[msg.sig] != address(0),
            "Unauthorized"
        );
        _;
    }

    /* ========== INITIALIZER ========== */
    function __Execute_init() internal onlyInitializing {
        __ReentrancyGuard_init();
    }

    /* ========== EXTERNAL FUNCTIONS ========== */

    /**
     * @dev Execute batch with EIP-712 signatures for cross-chain requests
     * @param targets Array of target addresses
     * @param values Array of ETH values to send
     * @param datas Array of calldata
     * @param signature EIP-712 signature from wallet owner
     * @param deadline Signature expiration timestamp
     */
    function executeBatchWithSig(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes calldata signature,
        uint256 deadline
    ) external nonReentrant whenNotLocked {
        require(block.chainid == CHAIN_ID, "Invalid chain");
        require(!usedSignatures[digest], "Signature reused");
        
        digest = _hashTypedDataV4(
            keccak256(abi.encode(
                EXECUTION_BATCH_TYPEHASH,
                keccak256(abi.encodePacked(targets)),
                sessionNonces[msg.sender]++,  // Pakai nonce Core
                deadline
            ))
        );
        
        if (!_verifyOwnerSignature(digest, signature)) revert InvalidSignature();
        
        _executeBatch(targets, values, datas, true);
    }
        
        // Increment nonce only after successful signature verification
        executionNonce++;
    
        // Execute batch with gas tracking
        _executeBatch(targets, values, datas, true);
    }

    /**
     * @dev Standard batch execution (for same-chain operations)
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external nonReentrant onlyOwner whenNotLocked {
        _validateBatchInputs(targets, values, datas);
        _executeBatch(targets, values, datas, false);
    }

    /* ========== INTERNAL FUNCTIONS ========== */

    /**
     * @dev Core batch execution logic
     */
    function _executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bool trackGas
    ) internal {
        uint256 totalValue;
        ExecutionResult[] memory results = new ExecutionResult[](targets.length);

        // Validate total value first
        for (uint256 i = 0; i < values.length; i++) {
            totalValue += values[i];
        }
        if (address(this).balance < totalValue) {
            revert InsufficientBatchValue(address(this).balance, totalValue);
        }

        // Execute all operations
        for (uint256 i = 0; i < targets.length; i++) {
            uint256 initialGas = gasleft();
            results[i] = _executeSingleCall(targets[i], values[i], datas[i]);
            if (trackGas) {
                results[i].gasUsed = initialGas - gasleft();
            }
        }

        _emitExecutionResults(targets, values, results);
    }

    /**
     * @dev Single call execution with plugin support
     */
    function _executeSingleCall(
        address target,
        uint256 value,
        bytes calldata data
    ) internal returns (ExecutionResult memory) {
        _validateExecution(target, value, data);
        bytes4 selector = _getSelector(data);
    
        (bool success, bytes memory result) = target.call{value: value}(data);
        
        // Execute plugin post-hook if exists
        bool hookSuccess = false;
        address plugin = selectorToPlugin[selector];
        if (success && plugin != address(0)) {
            (hookSuccess,) = plugin.call{gas: gasleft() - GAS_RESERVE}(
                abi.encodeWithSelector(
                    bytes4(keccak256("postExecutionHook(address,uint256,bytes)")),
                    target,
                    value,
                    data
                )
            );
            emit PluginPostHookExecuted(plugin, target, hookSuccess);
        }
    
        return ExecutionResult(success, result, 0, selector);
    }

    /* ========== SUPPORT FUNCTIONS ========== */

    function _emitExecutionResults(
        address[] calldata targets,
        uint256[] calldata values,
        ExecutionResult[] memory results
    ) internal {
        for (uint256 i = 0; i < targets.length; i++) {
            if (results[i].success) {
                emit ExecutionSuccess(
                    targets[i],
                    values[i],
                    results[i].selector,
                    results[i].gasUsed,
                    msg.sender
                );
            } else {
                emit ExecutionFailed(
                    targets[i],
                    results[i].selector,
                    results[i].result,
                    results[i].gasUsed,
                    msg.sender
                );
                if (results[i].result.length > 0) {
                    revert ExecutionReverted(results[i].result);
                }
                revert("Execution failed");
            }
        }
    }

    function _validateBatchInputs(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) internal pure {
        if (targets.length != values.length || values.length != datas.length) {
            revert BatchLengthMismatch();
        }
        if (targets.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }
    }

    function _validateExecution(
        address target,
        uint256 value,
        bytes calldata data
    ) internal view {
        if (target == address(0)) revert InvalidTarget(target);
        if (data.length < 4) revert InvalidCallData();
    }

    function _getSelector(bytes calldata data) internal pure returns (bytes4) {
        return bytes4(data[:4]);
    }

    function _verifyOwnerSignature() internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(digest, signature);
        return (error == ECDSA.RecoverError.NoError && 
               (isOwner[recovered] || _isActiveGuardian(recovered)));
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}

ParserError: Expected identifier but got '++'
   --> Corev5.1/SecureSmartWalletExecute.sol:129:23:
    |
129 |         executionNonce++;
    |                       ^^
