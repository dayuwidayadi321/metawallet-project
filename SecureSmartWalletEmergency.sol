// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SecureSmartWalletBase.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title SecureSmartWalletEmergency - Emergency recovery functionality
 * @dev Handles emergency token revocation and security measures
 */
abstract contract SecureSmartWalletEmergency is SecureSmartWalletBase {
    using AddressUpgradeable for address;

    // ========== Emergency State ========== //
    struct EmergencyRequest {
        address[] tokens;
        address[] maliciousContracts;
        uint256 executeAfter;
        bool executed;
        uint256 processedCount;
    }
    
    mapping(uint256 => EmergencyRequest) public emergencyRequests;
    uint256 public emergencyRequestCount;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 public constant MAX_BATCH_SIZE = 20;

    // ========== Events ========== //
    event EmergencyRequestCreated(uint256 indexed requestId, address indexed guardian);
    event EmergencyRequestExecuted(uint256 indexed requestId);
    event EmergencyRequestCancelled(uint256 indexed requestId);
    event TokenRevoked(address indexed token, address indexed maliciousContract, string tokenStandard);
    event TokenRevokeFailed(address indexed token, address indexed maliciousContract, string reason);
    event SuspiciousActivityDetected(address indexed target, uint256 value, bytes data);

    // ========== Modified Emergency Functions ========== //
    function createEmergencyRequest(
        address[] calldata tokens,
        address[] calldata maliciousContracts
    ) external onlyGuardian {
        require(tokens.length == maliciousContracts.length, "Array length mismatch");
        require(tokens.length <= 50, "Max 50 tokens per request");

        for (uint256 i = 0; i < tokens.length; i++) {
            require(tokens[i].isContract(), "Token must be contract");
            require(
                maliciousContracts[i] != address(this) &&
                maliciousContracts[i] != address(entryPoint),
                "Protected contract"
            );
        }

        uint256 requestId = emergencyRequestCount++;
        emergencyRequests[requestId] = EmergencyRequest({
            tokens: tokens,
            maliciousContracts: maliciousContracts,
            executeAfter: block.timestamp + EMERGENCY_DELAY,
            executed: false,
            processedCount: 0
        });
        
        emit EmergencyRequestCreated(requestId, msg.sender);

    /**
     * @dev Executes an emergency request in batches
     */
    function executeEmergencyRequest(
        uint256 requestId, 
        uint256 batchSize
    ) external onlyGuardian whenNotLocked nonReentrant {
        require(requestId < emergencyRequestCount, "SecureSmartWallet: invalid request ID");
        require(batchSize > 0 && batchSize <= 50, "SecureSmartWallet: invalid batch size");
        
        EmergencyRequest storage request = emergencyRequests[requestId];
        
        require(!request.executed, "SecureSmartWallet: request already executed");
        require(block.timestamp >= request.executeAfter, "SecureSmartWallet: cooldown not passed");
    
        uint256 totalTokens = request.tokens.length;
        uint256 processedCount = request.processedCount;
        uint256 endIndex = processedCount + batchSize;
        
        if (endIndex > totalTokens) {
            endIndex = totalTokens;
        }
    
        address[] memory tokens = request.tokens;
        address[] memory maliciousContracts = request.maliciousContracts;
        
        for (uint256 i = processedCount; i < endIndex; ) {
            address token = tokens[i];
            address maliciousContract = maliciousContracts[i];
            
            require(token != address(0), "SecureSmartWallet: invalid token address");
            require(maliciousContract != address(0), "SecureSmartWallet: invalid contract address");
    
            if (isBlacklisted[maliciousContract]) {
                unchecked { i++; }
                continue;
            }
    
            bool isTokenERC20 = isERC20(token);
            bool isTokenERC721 = !isTokenERC20 && isERC721(token);
            bool isTokenERC1155 = !isTokenERC20 && !isTokenERC721 && isERC1155(token);
            
            if (isTokenERC20) {
                _safeRevokeERC20(token, maliciousContract);
                emit TokenRevoked(token, maliciousContract, "ERC20");
            } else if (isTokenERC721) {
                _safeRevokeERC721(token, maliciousContract);
                emit TokenRevoked(token, maliciousContract, "ERC721");
            } else if (isTokenERC1155) {
                _safeRevokeERC1155(token, maliciousContract);
                emit TokenRevoked(token, maliciousContract, "ERC1155");
            } else {
                emit TokenRevokeFailed(token, maliciousContract, "Unknown token standard");
            }
    
            isBlacklisted[maliciousContract] = true;
            emit BlacklistUpdated(maliciousContract, true);
    
            unchecked { i++; }
        }
    
        request.processedCount = endIndex;
    
        if (endIndex == totalTokens) {
            request.executed = true;
            emit EmergencyRequestExecuted(requestId);
        }
    }

    // ========== Enhanced Token Detection ========== //
    function isERC20(address token) internal view returns (bool) {
        if (token.code.length == 0) return false;
        try IERC165(token).supportsInterface(type(IERC20).interfaceId) returns (bool supported) {
            return supported;
        } catch {
            return false;
        }
    }
    
    function isERC721(address token) internal view returns (bool) {
        bytes4 erc721Interface = 0x80ac58cd;
        try IERC165(token).supportsInterface(erc721Interface) returns (bool supported) {
            return supported;
        } catch {
            return false;
        }
    }
    
    function isERC1155(address token) internal view returns (bool) {
        bytes4 erc1155Interface = 0xd9b67a26;
        try IERC165(token).supportsInterface(erc1155Interface) returns (bool supported) {
            return supported;
        } catch {
            return false;
        }
    }

    // ========== Revocation Helpers ========== //
    
    function _safeRevokeERC20(address token, address spender) private {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20Upgradeable.approve.selector, spender, 0)
        );
        
        if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
            emit TokenRevokeFailed(token, spender, "ERC20 revoke failed");
            revert("ERC20 revoke failed");
        }
    }
    
    function _safeRevokeERC721(address token, address operator) private {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC721Upgradeable.setApprovalForAll.selector, operator, false)
        );
        
        if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
            emit TokenRevokeFailed(token, operator, "ERC721 revoke failed");
            revert("ERC721 revoke failed");
        }
    }
    
    function _safeRevokeERC1155(address token, address operator) private {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC1155.setApprovalForAll.selector, operator, false)
        );
        
        if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
            emit TokenRevokeFailed(token, operator, "ERC1155 revoke failed");
            revert("ERC1155 revoke failed");
        }
    }
    
        // ========== Storage Gap ========== //
    uint256[50] private __gap;
    }
}
