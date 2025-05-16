// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CoreV58.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title MySmartWallet - Enhanced UserOperation-Compatible Smart Wallet
 * @dev Inherits CoreV58 with full EIP-4337 (Account Abstraction) support
 * @notice Features: Gasless Tx, Session Keys, Plugin System, Multi-Chain, Enhanced Security
 * @version 5.8.0
 */
contract MySmartWallet is CoreV58 {
    /// @dev Events
    event UserOperationExecuted(
        address indexed target,
        uint256 value,
        bytes data,
        bytes32 userOpHash
    );
    event GasParametersUpdated(uint256 baseFee, uint256 priorityFee, uint256 gasLimitBuffer);

    /// @dev Constants
    uint256 public constant MAX_GAS_LIMIT = 2_000_000;

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
        __CoreV58_init(
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
        uint256 validationData = _validateUserOpWithChecks(userOp, userOpHash);

        (bool success, bytes memory result) = userOp.target.call{value: userOp.value}(userOp.callData);

        if (!success) {
            if (result.length > 0) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            revert("UserOp execution failed");
        }

        emit UserOperationExecuted(userOp.target, userOp.value, userOp.callData, userOpHash);
        return 0;
    }

    /// @dev Enhanced UserOp validation
    function _validateUserOpWithChecks(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        validationData = super.validateUserOp(userOp, userOpHash, 0);
        require(validationData == 0, "Invalid signature or permissions");
        require(userOp.callGasLimit <= MAX_GAS_LIMIT, "Gas limit too high");
        require(userOp.verificationGasLimit <= MAX_GAS_LIMIT * 2, "Verification gas too high");
        require(!isBlacklisted[userOp.target], "Target contract is blacklisted");
        return validationData;
    }

    /// @dev Fallback for plugin execution
    fallback() external payable override nonReentrant {
        bytes4 selector = msg.sig;
        address plugin = _getPluginBySelector(selector); // Menggunakan fungsi getter dari CoreV58

        if (plugin != address(0)) {
            _executePlugin(plugin, msg.data);
            return;
        }

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

    /// @dev Session key validation
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

    /// @dev Internal function to get plugin address by selector (assuming you'll add this to CoreV58)
    function _getPluginBySelector(bytes4 selector) internal view returns (address) {
        return _pluginSystem.selectorToPlugin[selector];
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

    function VERSION() public pure override returns (string memory) {
        return "5.8.0";
    }
}
