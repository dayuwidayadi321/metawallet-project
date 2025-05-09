// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SecureSmartWalletBase.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";

/**
 * @title SecureSmartWalletEmergency - Emergency Recovery Module v4.49
 * @dev Enhanced with batch processing, gas optimizations, and improved token detection
 */
abstract contract SecureSmartWalletEmergency is SecureSmartWalletBase {
    using AddressUpgradeable for address;
    
    /* ========== STRUCTS & CONSTANTS ========== */
    struct EmergencyRequest {
        address[] tokens;
        address[] maliciousContracts;
        uint64 executeAfter;
        uint64 processedCount;
        bool executed;
    }
    
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 public constant MAX_BATCH_SIZE = 20;
    bytes4 private constant ERC20_INTERFACE = type(IERC20Upgradeable).interfaceId;
    bytes4 private constant ERC721_INTERFACE = type(IERC721Upgradeable).interfaceId;
    bytes4 private constant ERC1155_INTERFACE = type(IERC1155).interfaceId;

    /* ========== STATE VARIABLES ========== */
    mapping(uint256 => EmergencyRequest) public emergencyRequests;
    uint256 public emergencyRequestCount;
    mapping(address => uint256) public lastGuardianRequest;

    /* ========== EVENTS ========== */
    event EmergencyRequestCreated(uint256 indexed requestId, address indexed guardian);
    event EmergencyRequestExecuted(uint256 indexed requestId, address indexed executor);
    event EmergencyRequestCancelled(uint256 indexed requestId);
    event TokenRevoked(address indexed token, address indexed maliciousContract, string tokenStandard);
    event TokenRevokeFailed(address indexed token, address indexed maliciousContract, string reason);
    event EmergencyCooldownUpdated(uint256 newCooldown);

    /* ========== ERRORS ========== */
    error InvalidRequestId();
    error RequestAlreadyExecuted();
    error CooldownNotPassed();
    error InvalidBatchSize();
    error ProtectedContract();
    error InvalidTokenAddress();
    error InvalidMaliciousAddress();
    error ArrayLengthMismatch();
    error MaxBatchSizeExceeded();
    error GuardianCooldownActive();

    /* ========== INITIALIZER ========== */
    function __SecureSmartWalletEmergency_init() internal onlyInitializing {
        // No initialization needed currently
    }

    /* ========== MODIFIERS ========== */
    modifier onlyActiveGuardian() {
        if (!_isActiveGuardian(msg.sender)) revert Unauthorized();
        _;
    }

    /* ========== EMERGENCY FUNCTIONS ========== */
    function createEmergencyRequest(
        address[] calldata tokens,
        address[] calldata maliciousContracts
    ) external onlyActiveGuardian {
        if (tokens.length != maliciousContracts.length) revert ArrayLengthMismatch();
        if (tokens.length > MAX_BATCH_SIZE) revert MaxBatchSizeExceeded();
        if (block.timestamp < lastGuardianRequest[msg.sender] + guardianConfig.cooldown) {
            revert GuardianCooldownActive();
        }

        for (uint256 i = 0; i < tokens.length; ) {
            if (!tokens[i].isContract()) revert InvalidTokenAddress();
            if (maliciousContracts[i] == address(this) || 
                maliciousContracts[i] == address(entryPoint)) {
                revert ProtectedContract();
            }
            unchecked { ++i; }
        }

        uint256 requestId = emergencyRequestCount++;
        emergencyRequests[requestId] = EmergencyRequest({
            tokens: tokens,
            maliciousContracts: maliciousContracts,
            executeAfter: uint64(block.timestamp + EMERGENCY_DELAY),
            processedCount: 0,
            executed: false
        });

        lastGuardianRequest[msg.sender] = block.timestamp;
        emit EmergencyRequestCreated(requestId, msg.sender);
    }

    function executeEmergencyRequest(
        uint256 requestId, 
        uint256 batchSize
    ) external onlyActiveGuardian whenNotLocked nonReentrant {
        if (requestId >= emergencyRequestCount) revert InvalidRequestId();
        if (batchSize == 0 || batchSize > MAX_BATCH_SIZE) revert InvalidBatchSize();

        EmergencyRequest storage request = emergencyRequests[requestId];
        
        if (request.executed) revert RequestAlreadyExecuted();
        if (block.timestamp < request.executeAfter) revert CooldownNotPassed();

        uint256 startIndex = request.processedCount;
        uint256 endIndex = startIndex + batchSize;
        if (endIndex > request.tokens.length) {
            endIndex = request.tokens.length;
        }

        for (uint256 i = startIndex; i < endIndex; ) {
            _processTokenRevocation(
                request.tokens[i], 
                request.maliciousContracts[i]
            );
            unchecked { ++i; }
        }

        request.processedCount = uint64(endIndex);
        
        if (endIndex == request.tokens.length) {
            request.executed = true;
            emit EmergencyRequestExecuted(requestId, msg.sender);
        }
    }

    function cancelEmergencyRequest(uint256 requestId) external onlyOwner {
        if (requestId >= emergencyRequestCount) revert InvalidRequestId();
        if (emergencyRequests[requestId].executed) revert RequestAlreadyExecuted();

        delete emergencyRequests[requestId];
        emit EmergencyRequestCancelled(requestId);
    }

    /* ========== TOKEN DETECTION & REVOCATION ========== */
    function _processTokenRevocation(address token, address maliciousContract) private {
        if (token == address(0)) revert InvalidTokenAddress();
        if (maliciousContract == address(0)) revert InvalidMaliciousAddress();
        if (isBlacklisted[maliciousContract]) return;

        bool success;
        string memory tokenStandard;
        
        if (_supportsInterface(token, ERC20_INTERFACE)) {
            (success, ) = token.call(
                abi.encodeWithSelector(IERC20Upgradeable.approve.selector, maliciousContract, 0)
            );
            tokenStandard = "ERC20";
        } else if (_supportsInterface(token, ERC721_INTERFACE)) {
            (success, ) = token.call(
                abi.encodeWithSelector(IERC721Upgradeable.setApprovalForAll.selector, maliciousContract, false)
            );
            tokenStandard = "ERC721";
        } else if (_supportsInterface(token, ERC1155_INTERFACE)) {
            (success, ) = token.call(
                abi.encodeWithSelector(IERC1155.setApprovalForAll.selector, maliciousContract, false)
            );
            tokenStandard = "ERC1155";
        } else {
            emit TokenRevokeFailed(token, maliciousContract, "Unknown token standard");
            return;
        }

        if (success) {
            isBlacklisted[maliciousContract] = true;
            emit TokenRevoked(token, maliciousContract, tokenStandard);
            emit BlacklistUpdated(maliciousContract, true);
        } else {
            emit TokenRevokeFailed(token, maliciousContract, "Revocation failed");
        }
    }

    function _supportsInterface(address token, bytes4 interfaceId) private view returns (bool) {
        try IERC165(token).supportsInterface(interfaceId) returns (bool supported) {
            return supported;
        } catch {
            return false;
        }
    }

    /* ========== VIEW FUNCTIONS ========== */
    function getEmergencyRequest(uint256 requestId) 
        external 
        view 
        returns (
            address[] memory tokens,
            address[] memory maliciousContracts,
            uint256 executeAfter,
            uint256 processedCount,
            bool executed
        ) 
    {
        EmergencyRequest storage request = emergencyRequests[requestId];
        return (
            request.tokens,
            request.maliciousContracts,
            request.executeAfter,
            request.processedCount,
            request.executed
        );
    }

    function isTokenSupported(address token) external view returns (bool) {
        return _supportsInterface(token, ERC20_INTERFACE) ||
               _supportsInterface(token, ERC721_INTERFACE) ||
               _supportsInterface(token, ERC1155_INTERFACE);
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}