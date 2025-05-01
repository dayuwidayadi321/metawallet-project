// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title AdvancedSmartWallet - EIP-4337 Smart Wallet (v4.31)
 * @author BY DFXC INDONESIA WEB3 PROJECT
 * @notice Smart wallet with enhanced guardian management and gas control
 * @dev Major improvements:
 * - Dynamic guardian management (add/remove guardians)
 * - Configurable gas limits for executions
 * - Improved recovery authorization checks
 * - Better error handling and revert reasons
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    string public constant VERSION = "4.31";
    string public name;

    // EntryPoint EIP-4337
    IEntryPoint public immutable entryPoint;

    // Owner management
    mapping(address => bool) public owners;
    address[] public ownerList;
    uint256 public ownerCount;

    // Enhanced Recovery system
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian;
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
        address pendingNewOwner;
        address initiatedBy; // Track who initiated recovery
    }
    RecoveryConfig public recoveryConfig;

    // Session keys with function blacklist
    struct SessionKey {
        address key;
        uint48 validUntil;
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction;
    }
    mapping(address => SessionKey) public sessionKeys;

    // Execution configuration
    struct ExecutionConfig {
        uint256 gasLimit;
        bool allowCustomGas;
    }
    ExecutionConfig public executionConfig;

    // Constants
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 public constant MAX_GAS_LIMIT = 5_000_000;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // Events
    event WalletInitialized(address[] indexed owners, string name);
    event OwnershipUpdated(address[] newOwners);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data, uint256 gasUsed);
    event ExecutionFailure(address indexed target, uint256 value, bytes data, string reason);
    event RecoveryInitiated(address indexed by, address pendingNewOwner, uint256 timestamp);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners, address[] newGuardians);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event SessionKeyAdded(address indexed key, uint48 validUntil, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);
    event UpgradePerformed(address indexed newImplementation);
    event GasConfigUpdated(uint256 gasLimit, bool allowCustomGas);

    // Modifiers
    modifier onlyOwner() {
        require(owners[msg.sender], "AdvancedSmartWallet: caller is not owner");
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "AdvancedSmartWallet: not from EntryPoint");
        _;
    }

    modifier onlyRecovery() {
        require(
            recoveryConfig.initiatedAt > 0 &&
            block.timestamp >= recoveryConfig.initiatedAt + recoveryConfig.delay,
            "AdvancedSmartWallet: recovery not ready"
        );
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    // ========== Initialization ========== //
    function initialize(
        address[] calldata _owners,
        string calldata _name,
        address[] calldata _guardians,
        uint256 _recoveryThreshold,
        uint256 _recoveryDelay,
        uint256 _initialGasLimit,
        bool _allowCustomGas
    ) external initializer {
        require(_owners.length > 0, "AdvancedSmartWallet: no owners");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "Invalid threshold");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "Recovery delay too long");
        require(_initialGasLimit <= MAX_GAS_LIMIT, "Gas limit too high");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;
        executionConfig.gasLimit = _initialGasLimit;
        executionConfig.allowCustomGas = _allowCustomGas;

        // Set owners
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            require(!owners[owner], "AdvancedSmartWallet: duplicate owner");
            owners[owner] = true;
            ownerList.push(owner);
        }
        ownerCount = _owners.length;

        // Set guardians
        _setGuardians(_guardians);

        emit WalletInitialized(_owners, _name);
        emit OwnershipUpdated(_owners);
        emit GasConfigUpdated(_initialGasLimit, _allowCustomGas);
    }

    // ========== Enhanced Guardian Management ========== //
    function addGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "Invalid guardian");
        require(!recoveryConfig.isGuardian[newGuardian], "Already guardian");

        recoveryConfig.guardians.push(newGuardian);
        recoveryConfig.isGuardian[newGuardian] = true;
        
        emit GuardianAdded(newGuardian);
    }

    function removeGuardian(address guardianToRemove) external onlyOwner {
        require(recoveryConfig.isGuardian[guardianToRemove], "Not guardian");
        require(recoveryConfig.guardians.length > recoveryConfig.threshold, "Cannot go below threshold");

        // Remove from guardians array
        uint256 length = recoveryConfig.guardians.length;
        for (uint256 i = 0; i < length; i++) {
            if (recoveryConfig.guardians[i] == guardianToRemove) {
                if (i != length - 1) {
                    recoveryConfig.guardians[i] = recoveryConfig.guardians[length - 1];
                }
                recoveryConfig.guardians.pop();
                break;
            }
        }

        recoveryConfig.isGuardian[guardianToRemove] = false;
        emit GuardianRemoved(guardianToRemove);
    }

    function _setGuardians(address[] memory _guardians) internal {
        delete recoveryConfig.guardians;
        for (uint256 i = 0; i < _guardians.length; i++) {
            address guardian = _guardians[i];
            require(guardian != address(0), "Invalid guardian");
            recoveryConfig.guardians.push(guardian);
            recoveryConfig.isGuardian[guardian] = true;
        }
    }

    // ========== Improved Recovery System ========== //
    function initiateRecovery(address _pendingNewOwner) external {
        require(recoveryConfig.isGuardian[msg.sender], "Not guardian");
        require(_pendingNewOwner != address(0), "Invalid pending owner");
        
        recoveryConfig.initiatedAt = block.timestamp;
        recoveryConfig.pendingNewOwner = _pendingNewOwner;
        recoveryConfig.initiatedBy = msg.sender;
        
        emit RecoveryInitiated(msg.sender, _pendingNewOwner, block.timestamp);
    }

    function cancelRecovery() external onlyOwner {
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        recoveryConfig.initiatedBy = address(0);
        emit RecoveryCancelled();
    }

    function completeRecovery(address[] calldata newOwners, address[] calldata newGuardians) external onlyRecovery {
        require(
            msg.sender == recoveryConfig.initiatedBy || owners[msg.sender],
            "Not authorized to complete"
        );
        require(newOwners.length > 0, "No new owners");
        require(newGuardians.length >= recoveryConfig.threshold, "Insufficient guardians");
        require(
            newOwners.length == 1 && newOwners[0] == recoveryConfig.pendingNewOwner,
            "Owner change must match pending owner"
        );

        // Clear current owners
        for (uint256 i = 0; i < ownerList.length; i++) {
            owners[ownerList[i]] = false;
        }
        delete ownerList;

        // Set new owner
        owners[newOwners[0]] = true;
        ownerList.push(newOwners[0]);
        ownerCount = 1;

        // Update guardians
        _setGuardians(newGuardians);

        // Reset recovery state
        recoveryConfig.initiatedAt = 0;
        recoveryConfig.pendingNewOwner = address(0);
        recoveryConfig.initiatedBy = address(0);
        
        emit RecoveryCompleted(newOwners, newGuardians);
        emit OwnershipUpdated(newOwners);
    }

    // ========== Enhanced Execution with Gas Control ========== //
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 customGasLimit
    ) external onlyOwner nonReentrant returns (bytes memory) {
        uint256 gasToUse = executionConfig.allowCustomGas 
            ? (customGasLimit > 0 ? customGasLimit : executionConfig.gasLimit)
            : executionConfig.gasLimit;
            
        require(gasToUse <= MAX_GAS_LIMIT, "Gas limit too high");

        bool success;
        bytes memory result;
        uint256 gasBefore = gasleft();
        
        (success, result) = target.call{value: value, gas: gasToUse}(data);
        
        if (success) {
            emit ExecutionSuccess(target, value, data, gasBefore - gasleft());
        } else {
            string memory reason = _getRevertReason(result);
            emit ExecutionFailure(target, value, data, reason);
            revert(reason);
        }
        return result;
    }

    function setExecutionConfig(uint256 newGasLimit, bool allowCustomGas) external onlyOwner {
        require(newGasLimit <= MAX_GAS_LIMIT, "Gas limit too high");
        executionConfig.gasLimit = newGasLimit;
        executionConfig.allowCustomGas = allowCustomGas;
        emit GasConfigUpdated(newGasLimit, allowCustomGas);
    }

    // ========== Utility Functions ========== //
    function _getRevertReason(bytes memory _returnData) internal pure returns (string memory) {
        if (_returnData.length < 68) return "Unknown error";
        assembly {
            _returnData := add(_returnData, 0x04)
        }
        return abi.decode(_returnData, (string));
    }

    // ========== Owner Management ========== //
    function addOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AdvancedSmartWallet: invalid owner");
        require(!owners[newOwner], "AdvancedSmartWallet: already owner");

        owners[newOwner] = true;
        ownerList.push(newOwner);
        ownerCount++;
        
        emit OwnerAdded(newOwner);
        emit OwnershipUpdated(ownerList);
    }

    function removeOwner(address ownerToRemove) external onlyOwner {
        require(owners[ownerToRemove], "AdvancedSmartWallet: not owner");
        require(ownerCount > 1, "AdvancedSmartWallet: cannot remove last owner");

        owners[ownerToRemove] = false;
        ownerCount--;

        // Remove from ownerList with swap and pop
        uint256 length = ownerList.length;
        bool found;
        for (uint256 i = 0; i < length; i++) {
            if (ownerList[i] == ownerToRemove) {
                if (i != length - 1) {
                    ownerList[i] = ownerList[length - 1];
                }
                ownerList.pop();
                found = true;
                break;
            }
        }
        require(found, "Owner not found in list");

        emit OwnerRemoved(ownerToRemove);
        emit OwnershipUpdated(ownerList);
    }

    function getOwners() external view returns (address[] memory) {
        return ownerList;
    }

    // ========== Session Keys ========== //
    function addSessionKey(
        address _key,
        uint48 _validUntil,
        bytes4[] calldata _allowedFunctions
    ) external onlyOwner {
        require(_key != address(0), "Invalid session key");
        require(_validUntil > block.timestamp, "Expiration must be in future");

        // Blacklist critical functions
        bytes4[] memory forbiddenFunctions = new bytes4[](4);
        forbiddenFunctions[0] = this.addOwner.selector;
        forbiddenFunctions[1] = this.removeOwner.selector;
        forbiddenFunctions[2] = this.completeRecovery.selector;
        forbiddenFunctions[3] = bytes4(keccak256("_authorizeUpgrade(address)"));
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            for (uint256 j = 0; j < forbiddenFunctions.length; j++) {
                require(_allowedFunctions[i] != forbiddenFunctions[j], "Cannot allow critical function");
            }
        }

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.validUntil = _validUntil;
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            session.allowedFunctions.push(_allowedFunctions[i]);
            session.isAllowedFunction[_allowedFunctions[i]] = true;
        }

        emit SessionKeyAdded(_key, _validUntil, _allowedFunctions);
    }

    function revokeSessionKey(address _key) external onlyOwner {
        require(sessionKeys[_key].key != address(0), "Session key not found");
        delete sessionKeys[_key];
        emit SessionKeyRevoked(_key);
    }

    // ========== Deposit Management ========== //
    function addDeposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        entryPoint.depositTo{value: msg.value}(address(this));
        emit DepositReceived(msg.sender, msg.value);
    }

    function withdrawDeposit(address payable withdrawAddress, uint256 amount) 
        external 
        onlyOwner 
        nonReentrant 
    {
        uint256 currentBalance = entryPoint.balanceOf(address(this));
        require(currentBalance >= amount, "Insufficient deposit balance");
        
        try entryPoint.withdrawTo(withdrawAddress, amount) {
            emit DepositWithdrawn(withdrawAddress, amount);
        } catch Error(string memory reason) {
            revert(string(abi.encodePacked("Withdraw failed: ", reason)));
        } catch {
            revert("Withdraw failed without reason");
        }
    }

    function getDepositBalance() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    // ========== Internal Functions ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered] || _isValidSessionKey(recovered, hash);
    }

    function _isValidSessionKey(address key, bytes32 hash) internal view returns (bool) {
        SessionKey storage session = sessionKeys[key];
        return session.key != address(0) 
            && block.timestamp <= session.validUntil
            && session.isAllowedFunction[bytes4(hash)];
    }
    
    // ========== ERC1271 Implementation ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        if (_validateSignature(hash, signature)) {
            return IERC1271.isValidSignature.selector;
        } else {
            return bytes4(0);
        }
    }

    // ========== Upgrade Functionality ========== //
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner 
    {
        emit UpgradePerformed(newImplementation);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }
}

/**
 * @title AdvancedSmartWalletFactory v4.31
 * @dev Factory for deploying AdvancedSmartWallet with UUPS proxy
 */
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "4.31";
    string public constant NAME = "AdvancedSmartWalletFactory";

    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;

    mapping(address => address[]) private _userWallets;
    mapping(address => bool) public isWalletDeployed;

    event WalletCreated(address indexed wallet, address[] owners, string name);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new AdvancedSmartWallet(_entryPoint));
    }

    function deployWallet(
        address[] calldata owners,
        string calldata name,
        address[] calldata guardians,
        uint256 recoveryThreshold,
        uint256 recoveryDelay,
        uint256 initialGasLimit,
        bool allowCustomGas
    ) external returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            AdvancedSmartWallet.initialize.selector,
            owners,
            name,
            guardians,
            recoveryThreshold,
            recoveryDelay,
            initialGasLimit,
            allowCustomGas
        );

        wallet = address(new ERC1967Proxy(walletImplementation, initData));

        for (uint256 i = 0; i < owners.length; i++) {
            _userWallets[owners[i]].push(wallet);
        }

        isWalletDeployed[wallet] = true;
        emit WalletCreated(wallet, owners, name);
    }

    function getWallets(address user) external view returns (address[] memory) {
        return _userWallets[user];
    }
}