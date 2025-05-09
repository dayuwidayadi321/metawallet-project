// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SecureSmartWalletBase.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/MessageHashUtilsUpgradeable.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";

/**
 * @title SecureSmartWalletSignatures - Signature verification and operations
 * @dev Handles all signature-based functionality including ERC-1271 compliance
 * @notice This contract manages all signature-related operations including scheduled transactions
 */
abstract contract SecureSmartWalletSignatures is SecureSmartWalletBase {
    using ECDSAUpgradeable for bytes32;
    using MessageHashUtilsUpgradeable for bytes32;
    
    // ========== Struct Definitions ========== //
    struct PendingOperation {
        bytes32 opHash;
        address initiator;
        uint256 executeAfter;
        bool executed;
        bytes callData;
    }

    // ========== Constants ========== //
    uint256 public constant DEFAULT_DELAY = 1 hours;
    uint256 public constant MAX_DELAY = 30 days;
    uint256 public constant CHAIN_ID = block.chainid;

    // ========== State Variables ========== //
    mapping(address => uint256) public userNonces;
    mapping(bytes32 => PendingOperation) public pendingOperations;
    uint256 public operationNonce;

    // ========== Events ========== //
    event DepositedWithSignature(address indexed depositor, uint256 amount, uint256 nonce);
    event WithdrawnWithSignature(address indexed recipient, uint256 amount, uint256 nonce);
    event OffChainSigned(bytes32 indexed messageHash, address indexed signer);
    event NonceUsed(address indexed user, uint256 nonce, bytes32 indexed operationHash);
    event OperationExecuted(bytes32 indexed opHash);
    event OperationCancelled(bytes32 indexed opHash);
    event OperationScheduled(
        bytes32 indexed opHash,
        address indexed initiator,
        uint256 executeAfter,
        bytes callData
    );

    // ========== Modifiers ========== //
    modifier validDeadline(uint256 deadline) {
        require(deadline >= block.timestamp, "Deadline passed");
        require(deadline <= block.timestamp + MAX_DELAY, "Deadline too far");
        _;
    }

    // ========== Signature Operations ========== //
    function depositWithSignature(
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external payable whenNotLocked validDeadline(deadline) {
        require(msg.value == amount, "Incorrect ETH amount");
        
        bytes32 messageHash = keccak256(abi.encode(
            CHAIN_ID,
            address(this),
            msg.sender,
            amount,
            userNonces[msg.sender],
            deadline,
            "deposit"
        ));
        
        _validateSignatureAndIncrementNonce(messageHash, signature);
        emit DepositedWithSignature(msg.sender, amount, userNonces[msg.sender] - 1);
    }

    function withdrawWithSignature(
        address payable recipient,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external whenNotLocked validDeadline(deadline) {
        require(address(this).balance >= amount, "Insufficient balance");
        
        bytes32 messageHash = keccak256(abi.encode(
            CHAIN_ID,
            address(this),
            recipient,
            amount,
            userNonces[msg.sender],
            deadline,
            "withdraw"
        ));
        
        _validateSignatureAndIncrementNonce(messageHash, signature);
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit WithdrawnWithSignature(recipient, amount, userNonces[msg.sender] - 1);
    }

    // ========== Scheduled Operations ========== //
    function scheduleOperation(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory callData,
        uint256 delay
    ) external onlyEntryPoint returns (bytes32 opHash) {
        require(delay >= DEFAULT_DELAY && delay <= MAX_DELAY, "Invalid delay");
        
        address signer = _verifyOffchainSignature(messageHash, signature);
        require(
            isOwner[signer] || _isActiveGuardian(signer), 
            "Invalid signer"
        );

        opHash = keccak256(abi.encodePacked(messageHash, operationNonce++));
        pendingOperations[opHash] = PendingOperation({
            opHash: opHash,
            initiator: signer,
            executeAfter: block.timestamp + delay,
            executed: false,
            callData: callData
        });

        emit OperationScheduled(opHash, signer, block.timestamp + delay, callData);
    }

    function executeScheduledOperation(bytes32 opHash) external nonReentrant whenNotLocked {
        PendingOperation storage operation = pendingOperations[opHash];
        require(operation.opHash == opHash, "Operation not found");
        require(!operation.executed, "Operation already executed");
        require(block.timestamp >= operation.executeAfter, "Delay not passed");
    
        operation.executed = true;
        (bool success, ) = address(this).call(operation.callData);
        require(success, "Execution failed");
        
        emit OperationExecuted(opHash);
    }

    function cancelOperation(bytes32 opHash) external {
        PendingOperation storage operation = pendingOperations[opHash];
        require(operation.opHash == opHash, "Operation not found");
        require(!operation.executed, "Operation already executed");
        require(msg.sender == operation.initiator || isOwner[msg.sender], "Not authorized");

        delete pendingOperations[opHash];
        emit OperationCancelled(opHash);
    }

    // ========== Signature Verification Functions ========== //
    function _validateOwnerSignature(bytes32 hash, bytes memory signature) 
        internal 
        view 
        returns (bool isValid, address signer) 
    {
        if (signature.length == 0) return (false, address(0));
        
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(hash);
        signer = ethSignedMessageHash.recover(signature);
        
        // Check 1: Apakah signer adalah owner
        isValid = isOwner[signer];
        
        // Check 2: Jika signer adalah kontrak (ERC1271)
        if (!isValid && signer.code.length > 0) {
            try IERC1271Upgradeable(signer).isValidSignature(hash, signature) 
                returns (bytes4 magicValue) {
                isValid = (magicValue == 0x1626ba7e);
            } catch {
                isValid = false;
            }
        }
        
        return (isValid, signer);
    }

    function _validateGuardianSignature(bytes32 hash, bytes memory signature) 
        internal 
        view 
        returns (bool) 
    {
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(hash);
        address signer = ethSignedMessageHash.recover(signature);
        return _isActiveGuardian(signer);
    }
    
    function _isActiveGuardian(address guardian) internal view returns (bool) {
        return isGuardian[guardian] && guardian != address(0);
    }

    function _validateSignatureAndIncrementNonce(bytes32 messageHash, bytes memory signature) internal {
        address signer = _verifyOffchainSignature(messageHash, signature);
        require(isOwner[signer], "Invalid owner signature");
        userNonces[msg.sender]++;
        emit NonceUsed(msg.sender, userNonces[msg.sender] - 1, messageHash);
    }

    function _verifyOffchainSignature(
        bytes32 messageHash,
        bytes memory signature
    ) internal view returns (address) {
        bytes32 ethSignedMessageHash = MessageHashUtilsUpgradeable.toEthSignedMessageHash(messageHash);
        address signer = ethSignedMessageHash.recover(signature);
        
        if (signer.code.length > 0) {
            require(
                IERC1271Upgradeable(signer).isValidSignature(messageHash, signature) == 0x1626ba7e,
                "Invalid contract signature"
            );
        }
        return signer;
    }

    // ========== UserOp Validation ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (isLocked) {
            return _packValidationData(true, 0, 0);
        }
        
        if (missingWalletFunds > 0) {
            (bool success,) = payable(address(entryPoint)).call{value: missingWalletFunds}("");
            require(success, "Failed to deposit gas");
        }
        
        if (bytes4(userOp.callData) == this.executeScheduledOperation.selector) {
            return _validateScheduledOp(userOp.callData[4:]);
        }
        
        address recovered = userOpHash.recover(userOp.signature);
        if (!_isValidSigner(recovered, userOpHash, userOp.signature)) {
            return _packValidationData(true, 0, 0);
        }
        
        (uint48 validAfter, uint48 validUntil) = _extractTimestampsFromSignature(userOp.signature);
        return _packValidationData(
            _isOutsideTimeWindow(validAfter, validUntil),
            validAfter,
            validUntil
        );
    }

    function _isValidSigner(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        if (isOwner[signer]) return true;
        if (!_isActiveGuardian(signer)) return false;
        
        if (signer.code.length > 0) {
            try IERC1271Upgradeable(signer).isValidSignature(hash, signature) 
                returns (bytes4 magicValue) {
                return magicValue == 0x1626ba7e;
            } catch {
                return false;
            }
        }
        return true;
    }

    // ========== Helper Functions ========== //
    function _validateScheduledOp(bytes memory opData) internal view returns (uint256) {
        bytes32 opHash = abi.decode(opData, (bytes32));
        PendingOperation storage op = pendingOperations[opHash];
        
        if (op.executed || block.timestamp < op.executeAfter) {
            return _packValidationData(true, 0, 0);
        }
        return _packValidationData(false, 0, 0);
    }

    function _isOutsideTimeWindow(uint48 validAfter, uint48 validUntil) internal view returns (bool) {
        return block.timestamp < validAfter || block.timestamp > validUntil;
    }
    
    function _extractTimestampsFromSignature(bytes memory signature) 
        internal 
        pure 
        returns (uint48 validAfter, uint48 validUntil) 
    {
        require(signature.length >= 77, "Invalid signature length");
        
        assembly {
            let sigPtr := add(signature, 65)
            validAfter := and(mload(sigPtr), 0xFFFFFFFFFFFF)
            validUntil := and(mload(add(sigPtr, 6)), 0xFFFFFFFFFFFF)
        }
    }
    
    function _packValidationData(
        bool sigFailed, 
        uint48 validAfter, 
        uint48 validUntil
    ) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | 
               (uint256(validAfter) << 160) | 
               (uint256(validUntil) << (160 + 48));
    }

    // ========== View Functions ========== //
    function getPendingOperation(bytes32 opHash) public view returns (
        bytes32,
        address,
        uint256,
        bool,
        bytes memory
    ) {
        PendingOperation memory op = pendingOperations[opHash];
        require(op.opHash != 0, "Operation does not exist");
        return (op.opHash, op.initiator, op.executeAfter, op.executed, op.callData);
    }

    // ========== Storage Gap ========== //
    uint256[50] private __gap;
}