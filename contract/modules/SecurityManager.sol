// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

abstract contract SecurityManager is 
    EIP712Upgradeable, 
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    OwnableUpgradeable 
{
    using ECDSAUpgradeable for bytes32;
    using AddressUpgradeable for address;

    bytes32 public constant EMERGENCY_LOCK_TYPEHASH =
        keccak256("EmergencyLock(uint256 nonce,uint256 deadline)");

    struct Environment {
        bool isLocked;
        uint256 securityDelay;
    }

    struct GuardianConfig {
        uint64 threshold;
        uint64 cooldown;
        uint64 lastRecoveryTimestamp;
        EnumerableSetUpgradeable.AddressSet guardians;
    }

    address public gasOracle;
    mapping(address => bool) public isBlacklisted;
    mapping(address => uint256) public recoveryNonces;
    Environment internal env;
    GuardianConfig internal _guardianConfig;

    uint256 public constant MAX_SECURITY_DELAY = 30 days;

    event LockStatusChanged(bool locked, address initiatedBy);
    event SecurityDelayUpdated(uint256 newDelay);
    event EmergencyLockVetoed(address indexed vetoer);
    event GuardianInactivityWarning(uint256 lastActiveTimestamp);
    event GasOracleUpdated(address indexed oldOracle, address indexed newOracle);
    event AddressBlacklisted(address indexed account);
    event AddressWhitelisted(address indexed account);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function __SecurityManager_init(address initialGasOracle) internal onlyInitializing {
        __EIP712_init("CoreV55", "5.5");
        __ReentrancyGuard_init();
        __Pausable_init();
        __Ownable_init();
        gasOracle = initialGasOracle;
    }

    modifier whenNotLocked() {
        require(!env.isLocked, "Core: Contract locked");
        _;
    }

    modifier whenLocked() {
        require(env.isLocked, "Core: Contract not locked");
        _;
    }

    /**
     * @dev Initiate emergency lock with guardian signatures
     * @param guardianSignature Signature from guardian for verification
     */
    function emergencyLock(bytes calldata guardianSignature) 
        external 
        virtual 
        nonReentrant
        whenNotPaused
    {
        uint256 deadline = block.timestamp + 1 hours;
        
        bytes32 lockHash = _hashTypedDataV4(keccak256(abi.encode(
            EMERGENCY_LOCK_TYPEHASH,
            recoveryNonces[msg.sender]++,
            deadline
        )));
    
        require(block.timestamp <= deadline, "Core: Signature expired");
        address signer = lockHash.recover(guardianSignature);
        require(_isValidGuardian(signer), "Core: Not guardian");
        _setLockStatus(true);
    }
    
    /**
     * @dev Internal function to set lock status
     * @param locked Boolean indicating desired lock state
     */
    function _setLockStatus(bool locked) internal virtual {
        require(env.isLocked != locked, "Core: Already in state");
        env.isLocked = locked;
        emit LockStatusChanged(locked, msg.sender);
    }

    /**
     * @dev Set security delay for critical operations
     * @param delay New delay in seconds
     */
    function setSecurityDelay(uint256 delay) 
        external 
        onlyOwner 
        whenNotLocked
    {
        require(delay <= MAX_SECURITY_DELAY, "Core: Delay too long");
        env.securityDelay = delay;
        emit SecurityDelayUpdated(delay); 
    }
    
    /**
     * @dev Allow owner to veto emergency lock
     */
    function vetoEmergencyLock() 
        external 
        onlyOwner 
        whenLocked
        nonReentrant
    {
        _setLockStatus(false);
        emit EmergencyLockVetoed(msg.sender);
    }
    
    /**
     * @dev Check guardian activity status
     * @return needsRotation True if guardians need rotation
     */
    function guardianActivityCheck() 
        external 
        view 
        returns (bool needsRotation) 
    {
        uint256 inactivePeriod = block.timestamp - _guardianConfig.lastRecoveryTimestamp;
        if (inactivePeriod > 180 days) {
            emit GuardianInactivityWarning(_guardianConfig.lastRecoveryTimestamp);
            return true;
        }
        return false;
    }

    /**
     * @dev Update gas oracle address
     * @param newOracle Address of new gas oracle
     */
    function setGasOracle(address newOracle) 
        external 
        onlyOwner 
        whenNotLocked
    {
        require(newOracle != address(0), "Core: Zero address");
        require(newOracle.isContract(), "Core: Not contract");
        
        address oldOracle = gasOracle;
        gasOracle = newOracle;
        emit GasOracleUpdated(oldOracle, newOracle);
    }

    /**
     * @dev Blacklist an address
     * @param account Address to blacklist
     */
    function blacklistAddress(address account) external onlyOwner {
        require(!isBlacklisted[account], "Core: Already blacklisted");
        isBlacklisted[account] = true;
        emit AddressBlacklisted(account);
    }

    /**
     * @dev Remove address from blacklist
     * @param account Address to whitelist
     */
    function whitelistAddress(address account) external onlyOwner {
        require(isBlacklisted[account], "Core: Not blacklisted");
        isBlacklisted[account] = false;
        emit AddressWhitelisted(account);
    }

    /**
     * @dev Get optimal gas parameters from oracle
     * @return baseFee Recommended base fee
     * @return priorityFee Recommended priority fee
     * @return gasLimitBuffer Recommended gas limit buffer
     */
    function getOptimalGasParams() 
        public 
        view 
        returns (
            uint256 baseFee,
            uint256 priorityFee,
            uint256 gasLimitBuffer
        ) 
    {
        require(gasOracle != address(0), "Core: Oracle not set");
        
        // Fallback values if oracle call fails
        if (!gasOracle.isContract()) {
            return (0.01 ether, 0.001 ether, 200_000);
        }
        
        (bool success, bytes memory data) = gasOracle.staticcall(
            abi.encodeWithSignature("getGasParameters()")
        );
        
        return success ? abi.decode(data, (uint256, uint256, uint256)) 
                      : (0.01 ether, 0.001 ether, 200_000);
    }

    /**
     * @dev Verify if address is valid guardian
     * @param guardian Address to verify
     * @return bool True if valid guardian
     */
    function _isValidGuardian(address guardian) 
        internal 
        view 
        virtual 
        returns (bool) 
    {
        return _guardianConfig.guardians.contains(guardian) && 
               !isBlacklisted[guardian] &&
               guardian.code.length == 0;
    }

    // Storage gap for future upgrades
    uint256[50] private __gap;
}