// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/ERC1967/ERC1967UpgradeUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/IERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "../Core/interfaces/IUpgradable.sol";
import "../Core/interfaces/IStorageCheck.sol";

abstract contract UpgradeManager is ERC1967UpgradeUpgradeable {
    using AddressUpgradeable for address;

    // Upgrade state variables
    address public pendingImplementation;
    address public previousImplementation;
    uint256 public upgradeFailureTimestamp;
    uint256 public upgradeTimestamp;
    bool public upgradeInProgress;

    // Events
    event UpgradeInitiated(address indexed newImplementation);
    event UpgradeHealthChecked(bool isHealthy);
    event UpgradeRolledBack(address indexed previousImplementation);
    event UpgradeConfirmed(address indexed newImplementation);
    event UpgradeAuthorized(address indexed newImplementation);  
    event UpgradeCompleted(address indexed newImplementation);

    /**
     * @dev Execute pending upgrade after timelock
     * @notice Restricted to owner only and when contract is not locked
     */
    function executeUpgrade() external virtual onlyOwner whenNotLocked nonReentrant {
        require(pendingImplementation != address(0), "No pending upgrade");
        require(block.timestamp >= env.upgradeTimelock, "Timelock not expired");
        
        _validateImplementation(pendingImplementation);
    
        // Snapshot current implementation
        previousImplementation = _getImplementation();
        upgradeInProgress = true;
        upgradeFailureTimestamp = block.timestamp + ROLLBACK_WINDOW;
        
        // Perform upgrade
        _upgradeToAndCall(
            pendingImplementation,
            abi.encodeWithSignature("initializeV2()")
        );
    
        // Verify health
        require(checkUpgradeHealth(), "Upgrade health check failed");
        
        // Finalize
        emit UpgradeCompleted(pendingImplementation);
        pendingImplementation = address(0);
        upgradeInProgress = false;
    }

    /**
     * @dev Comprehensive upgrade health check
     * @return bool True if all checks pass
     */
    function checkUpgradeHealth() public returns (bool) {
        require(_owners.contains(msg.sender) || msg.sender == address(this), "Unauthorized");
        require(upgradeInProgress, "No upgrade in progress");
        
        bool isHealthy = true;
        
        // 1. Version check
        try this.version(){gas: 50_000}() returns (string memory v) {
            isHealthy = keccak256(bytes(v)) == keccak256(bytes("5.5"));
        } catch {
            return false;
        }
        
        // 2. Critical functionality check
        if (isHealthy) {
            isHealthy = _validateCriticalFunctions();
        }
        
        // 3. Invalid function call check
        if (isHealthy) {
            isHealthy = _checkInvalidFunctionResponse();
        }
        
        // 4. Storage consistency check
        if (isHealthy) {
            try this.checkStorageConsistency{gas: 200_000}() returns (bool result) {
                isHealthy = result;
            } catch {
                isHealthy = false;
            }
        }
        
        emit UpgradeHealthChecked(isHealthy);
        return isHealthy;
    }

    /**
     * @dev Validate new implementation contract
     * @param newImpl Address of new implementation
     */
    function _validateImplementation(address newImpl) internal view {
        require(newImpl != address(0), "Invalid implementation");
        require(newImpl.isContract(), "No code at implementation");
        
        // Version compatibility check
        (bool success, bytes memory data) = newImpl.staticcall(
            abi.encodeWithSignature("VERSION()")
        );
        require(success && data.length > 0, "Version check failed");
        string memory versionStr = abi.decode(data, (string));
        require(
            keccak256(bytes(versionStr)) == keccak256(bytes("5.5")), 
            "Version mismatch"
        );
        
        // IUpgradable interface check
        (success, data) = newImpl.staticcall(
            abi.encodeWithSelector(
                IERC165Upgradeable.supportsInterface.selector,
                type(IUpgradable).interfaceId
            )
        );
        require(success && abi.decode(data, (bool)), "IUpgradable not supported");
        
        // Optional storage compatibility check
        if (IERC165Upgradeable(newImpl).supportsInterface(type(IStorageCheck).interfaceId)) {
            (success, data) = newImpl.staticcall(
                abi.encodeWithSelector(
                    IStorageCheck.isStorageCompatible.selector,
                    _getImplementation()
                )
            );
            require(success && abi.decode(data, (bool)), "Storage incompatible");
        }
    }

    /**
     * @dev Validate critical functions after upgrade
     */
    function _validateCriticalFunctions() internal virtual returns (bool) {
        try this.validateUserOp{gas: 200_000}(
            UserOperation({
                sender: address(this),
                nonce: 0,
                initCode: "",
                callData: "",
                callGasLimit: 0,
                verificationGasLimit: 0,
                preVerificationGas: 0,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                paymasterAndData: "",
                signature: ""
            }),
            bytes32(0),
            0
        ) returns (uint256 validationData) {
            return validationData == 0;
        } catch {
            return false;
        }
    }

    /**
     * @dev Check for invalid function responses
     */
    function _checkInvalidFunctionResponse() internal view returns (bool) {
        (bool success, bytes memory data) = address(this).staticcall{gas: 30_000}(
            abi.encodeWithSignature("nonExistentABC123XYZ()")
        );
        return !success && data.length == 0;
    }
}