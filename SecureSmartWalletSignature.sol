// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SecureSmartWalletBase.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/MessageHashUtilsUpgradeable.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";i

/**
 * @title SecureSmartWalletSignatures - Signature verification and operations
 * @dev Handles all signature-based functionality including ERC-1271 compliance
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

    // ========== Signature State ========== //
    mapping(address => uint256) public userNonces;
    mapping(bytes32 => PendingOperation) public pendingOperations;i
    uint256 public constant DEFAULT_DELAY = 1 hours;
    uint256 public operationNonce;

    // ========== Events ========== //
    event DepositedWithSignature(address indexed depositor, uint256 amount, uint256 nonce);
    event WithdrawnWithSignature(address indexed recipient, uint256 amount, uint256 nonce);
    event OffChainSigned(bytes32 indexed messageHash, address indexed signer);
    event NonceUsed(address indexed user, uint256 nonce, bytes32 indexed operationHash);
    event OperationExecuted(bytes32 indexed opHash);
    event OperationCancelled(bytes32 indexed opHash);
    event OperationScheduled(bytes32 indexed opHash, address indexed initiator, uint256 executeAfter, bytes callData);

    // ========== Signature Operations ========== //

    function depositWithSignature(
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external payable whenNotLocked {
        require(msg.value == amount, "Incorrect ETH amount");
        require(deadline >= block.timestamp, "Deadline passed");
        require(deadline <= block.timestamp + 30 days, "Deadline too far");
        
        uint256 currentNonce = userNonces[msg.sender]++;
        
        bytes32 messageHash = keccak256(abi.encode(
            CHAIN_ID,
            address(this),
            msg.sender,
            amount,
            currentNonce,
            deadline,
            "deposit"
        ));
        
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "Invalid owner signature");
    
        emit NonceUsed(msg.sender, currentNonce, messageHash);
        emit DepositedWithSignature(msg.sender, amount, currentNonce);
    }

    function withdrawWithSignature(
        address payable recipient,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external whenNotLocked {
        require(address(this).balance >= amount, "Insufficient balance");
        require(deadline >= block.timestamp, "Deadline passed");
        require(deadline <= block.timestamp + 30 days, "Deadline too far");
        
        uint256 currentNonce = userNonces[msg.sender]++;
        
        bytes32 messageHash = keccak256(abi.encode(
            CHAIN_ID,
            address(this),
            recipient,
            amount,
            currentNonce,
            deadline,
            "withdraw"
        ));
        
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        require(isOwner[signer], "Invalid owner signature");
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit NonceUsed(msg.sender, currentNonce, messageHash);
        emit WithdrawnWithSignature(recipient, amount, currentNonce);
    }

    // ========== Scheduled Operations ========== //

    function scheduleOperation(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory callData,
        uint256 delay
    ) external onlyEntryPoint returns (bytes32 opHash) {
        require(delay >= 1 hours, "Delay too short");
        
        address signer = _verifyOffchainSignature(messageHash, signature);
        require(isOwner[signer] || 
               (guardianConfig.isGuardian[signer] && _isActiveGuardian(signer)), 
               "Invalid signer");

        opHash = keccak256(abi.encodePacked(messageHash, operationNonce++));
        pendingOperations[opHash] = PendingOperation({
            opHash: opHash,
            initiator: signer,
            executeAfter: block.timestamp + delay,
            executed: false,
            callData: callData
        });

        emit OperationScheduled(opHash, signer, block.timestamp + delay);
        emit OffChainSigned(messageHash, signer);
    }

    function executeScheduledOperation(bytes32 opHash) external nonReentrant {
        PendingOperation storage operation = pendingOperations[opHash];
        require(operation.opHash == opHash, "Operation not found");
        require(!operation.executed, "Operation already executed");
        require(block.timestamp >= operation.executeAfter, "Delay not passed");
    
        operation.executed = true;
        emit OperationExecuted(opHash);
    
        (bool success, ) = address(this).call(operation.callData);
        require(success, "Execution failed");
    }

    function cancelOperation(bytes32 opHash) external {
        PendingOperation storage operation = pendingOperations[opHash];
        require(operation.opHash == opHash, "Operation not found");
        require(!operation.executed, "Operation already executed");
        require(msg.sender == operation.initiator || isOwner[msg.sender], "Not authorized");

        delete pendingOperations[opHash];
        emit OperationCancelled(opHash);
    }

    // ========== Signature Verification ========== //

    function _verifyOffchainSignature(
        bytes32 messageHash,
        bytes memory signature
    ) internal view returns (address signer) {
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        signer = ethSignedMessageHash.recover(signature);
        
        if (signer.code.length > 0) {
            require(
                IERC1271Upgradeable(signer).isValidSignature(messageHash, signature) == 0x1626ba7e,
                "Invalid contract signature"
            );
        }
    }

    // ========== UserOp Validation ========== //

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (_isLocked) {
            return _packValidationData(true, 0, 0);
        }
        
        if (missingWalletFunds > 0) {
            (bool success,) = payable(address(entryPoint)).call{value: missingWalletFunds}("");
            require(success, "Failed to deposit gas");
        }
        
        if (bytes4(userOp.callData) == this.executeScheduledOperation.selector) {
            bytes32 opHash = abi.decode(userOp.callData[4:], (bytes32));
            PendingOperation storage op = pendingOperations[opHash];
            
            if (op.executed || block.timestamp < op.executeAfter) {
                return _packValidationData(true, 0, 0);
            }
            return _packValidationData(false, 0, 0);
        }
        
        address recovered = userOpHash.recover(userOp.signature);
        bool isValidOwner = isOwner[recovered];
        bool isValidGuardian = guardianConfig.isGuardian[recovered] && _isActiveGuardian(recovered);
        
        if (!isValidOwner && !isValidGuardian && recovered.code.length > 0) {
            try IERC1271Upgradeable(recovered).isValidSignature(userOpHash, userOp.signature) 
                returns (bytes4 magicValue) {
                isValidOwner = (magicValue == 0x1626ba7e);
            } catch {}
        }
        
        if (!isValidOwner && !isValidGuardian) {
            return _packValidationData(true, 0, 0);
        }
        
        (uint48 validAfter, uint48 validUntil) = _getValidationTimestamps(userOp);
        
        if (validAfter > 0 && block.timestamp < validAfter) {
            return _packValidationData(true, validAfter, validUntil);
        }
        
        if (validUntil > 0 && block.timestamp > validUntil) {
            return _packValidationData(true, validAfter, validUntil);
        }
        
        return _packValidationData(false, validAfter, validUntil);
    }

    // ========== Internal Helpers ========== //

    function _getValidationTimestamps(UserOperation calldata userOp) 
        internal 
        view 
        returns (uint48 validAfter, uint48 validUntil) 
    {
        try this.tryGetValidationDataLegacy(userOp) returns (uint48 va, uint48 vu) {
            return (va, vu);
        } catch {
            return _extractTimestampsFromSignature(userOp.signature);
        }
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
    
    
        function getPendingOperation(bytes32 opHash) public view returns (
        bytes32,
        address,
        uint256,
        bool,
        bytes memory
    ) {
        PendingOperation memory op = pendingOperations[opHash];
        return (op.opHash, op.initiator, op.executeAfter, op.executed, op.callData);
    }
    
        // ========== Storage Gap ========== //
    uint256[50] private __gap;
}

