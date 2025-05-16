// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CoreV57.sol";  // Ubah import dari CoreV56 ke CoreV57
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title MySmartWallet - Enhanced UserOperation-Compatible Smart Wallet
 * @dev Inherits CoreV57 with full EIP-4337 (Account Abstraction) support
 * @notice Features: Gasless Tx, Session Keys, Plugin System, Multi-Chain, Enhanced Security
 * @version 5.7.1
 */
contract MySmartWallet is CoreV57 {  // Ubah inherit ke CoreV57
    /// @dev Events
    event UserOperationExecuted(
        address indexed target,
        uint256 value,
        bytes data,
        bytes32 userOpHash
    );
    event GasParametersUpdated(uint256 baseFee, uint256 priorityFee, uint256 gasLimitBuffer);

    /// @dev Constants
    uint256 public constant MAX_GAS_LIMIT = 2_000_000; // Maximum gas limit for UserOperations

    /// @dev Initialize wallet with owners & guardian
    function initialize(
        address[] memory initialOwners,
        address initialGuardian,
        uint64 guardianThreshold,
        uint64 recoveryCooldown,
        address _lzEndpoint,
        uint16[] memory _supportedChainIds,
        bytes[] memory _trustedRemotes
    ) public initializer {
        __CoreV57_init(  // Ubah ke __CoreV57_init
            initialOwners,
            initialGuardian,
            guardianThreshold,
            recoveryCooldown,
            _lzEndpoint,
            _supportedChainIds,
            _trustedRemotes
        );
    }

    /// @dev Execute validated UserOperation
    function executeUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external onlyEntryPoint nonReentrant returns (uint256) {
        // Validate signature and permissions
        uint256 validationData = _validateUserOpWithChecks(userOp, userOpHash);
        
        // Execute the call
        (bool success, bytes memory result) = userOp.target.call{value: userOp.value}(userOp.callData);
        
        if (!success) {
            if (result.length > 0) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            revert("UserOp execution failed");
        }

        emit UserOperationExecuted(
            userOp.target,
            userOp.value,
            userOp.callData,
            userOpHash
        );

        return 0;
    }

    /// @dev Enhanced UserOp validation with additional checks
    function _validateUserOpWithChecks(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        // Base validation from CoreV57
        validationData = validateUserOp(userOp, userOpHash, 0);
        require(validationData == 0, "Invalid signature or permissions");

        // Additional security checks
        require(userOp.callGasLimit <= MAX_GAS_LIMIT, "Gas limit too high");
        require(userOp.verificationGasLimit <= MAX_GAS_LIMIT * 2, "Verification gas too high");
        
        // Check if target is blacklisted
        require(!isBlacklisted[userOp.target], "Target contract is blacklisted");

        return validationData;
    }

    /// @dev Override validateUserOp with additional functionality
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) public override onlyEntryPoint returns (uint256 validationData) {
        // Handle missing funds first (CoreV57 sudah memiliki ini, bisa dihapus jika ingin menggunakan implementasi parent)
        if (missingAccountFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Failed to transfer missing funds");
        }

        // Perform base validation
        validationData = super.validateUserOp(userOp, userOpHash, missingAccountFunds);

        return validationData;
    }

    /// @dev Enhanced fallback for plugin execution
    fallback() external payable override nonReentrant {
        bytes4 selector = msg.sig;
        
        // Check registered plugins first
        address plugin = _pluginSystem.selectorToPlugin[selector];
        if (plugin != address(0)) {
            _executePlugin(plugin, msg.data);
            return;
        }

        // Check session keys if no plugin found
        if (_validateSessionKey(msg.sender, selector)) {
            (bool success, bytes memory result) = msg.sender.call{value: msg.value}(msg.data);
            if (!success) {
                if (result.length > 0) {
                    assembly {
                        revert(add(result, 32), mload(result))
                    }
                }
                revert("Direct call failed");
            }
            return;
        }

        revert("Function not registered");
    }

    /// @dev Validate session key permissions
    function _validateSessionKey(address key, bytes4 selector) internal view returns (bool) {
        SessionKey storage sk = sessionKeys[key];
        if (sk.isRevoked || block.timestamp > sk.validUntil || block.timestamp < sk.validAfter) {
            return false;
        }

        for (uint i = 0; i < sk.allowedSelectors.length; i++) {
            if (selector == sk.allowedSelectors[i]) {
                return true;
            }
        }
        return false;
    }

    /// @dev Update gas parameters from oracle
    function updateGasParameters() external {
        (uint256 baseFee, uint256 priorityFee, uint256 gasLimitBuffer) = getOptimalGasParams();
        emit GasParametersUpdated(baseFee, priorityFee, gasLimitBuffer);
    }

    /// @dev Additional wallet functionality
    function batchExecute(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyOwner {
        require(targets.length == values.length && values.length == datas.length, "Length mismatch");
        
        for (uint i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call{value: values[i]}(datas[i]);
            require(success, "Batch call failed");
        }
    }

    /// @dev Receive ETH
    receive() external payable override {
        emit ETHReceived(msg.sender, msg.value);
    }

    /// @dev Version compatibility
    function VERSION() public pure override returns (string memory) {
        return "5.7.1";  // Sesuaikan dengan versi CoreV57
    }
}