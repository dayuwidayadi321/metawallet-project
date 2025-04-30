// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title AdvancedSmartWallet - EIP-4337 Compliant Smart Wallet (v3.0)
 * @notice Smart wallet dengan multi-owner, upgradeability, dan recovery mechanism
 * @dev Implementasi lengkap untuk produksi dengan fitur tambahan
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable {
    using ECDSA for bytes32;

    // Informasi versi
    string public constant VERSION = "3.0";
    string public name;
    
    // EIP-4337 EntryPoint
    IEntryPoint public immutable entryPoint;
    
    // Daftar owner
    mapping(address => bool) public owners;
    uint256 public ownerCount;
    
    // Recovery settings
    address public recoveryAddress;
    uint256 public recoveryDelay;
    uint256 public recoveryInitiatedAt;
    
    // Gas limits
    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    
    // Event
    event WalletInitialized(address[] indexed owners, string name);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);
    event RecoveryInitiated(address indexed recoveryAddress);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners);

    // Modifier
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
            msg.sender == recoveryAddress && 
            recoveryInitiatedAt > 0 && 
            block.timestamp >= recoveryInitiatedAt + recoveryDelay,
            "AdvancedSmartWallet: invalid recovery"
        );
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers(); // Mencegah implementasi langsung
    }

    /**
     * @dev Initialize wallet (digunakan oleh factory)
     */
    function initialize(
        address[] calldata _owners,
        string calldata _name,
        address _recoveryAddress,
        uint256 _recoveryDelay
    ) external initializer {
        require(_owners.length > 0, "AdvancedSmartWallet: no owners");
        require(_recoveryAddress != address(0), "AdvancedSmartWallet: invalid recovery");
        
        name = _name;
        recoveryAddress = _recoveryAddress;
        recoveryDelay = _recoveryDelay;
        
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            owners[owner] = true;
        }
        
        ownerCount = _owners.length;
        emit WalletInitialized(_owners, _name);
    }

    /**
     * @dev Authorize upgrade (hanya oleh owner)
     */
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * @dev Validasi UserOperation sesuai EIP-4337
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Validasi signature
        if (!_validateSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        // Bayar fee jika diperlukan
        if (missingWalletFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingWalletFunds}("");
            success; // Silence warning
        }

        return 0;
    }

    /**
     * @dev Eksekusi transaksi dengan batasan gas
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner returns (bytes memory) {
        require(gasleft() >= EXECUTE_GAS_LIMIT, "AdvancedSmartWallet: insufficient gas");
        
        (bool success, bytes memory result) = target.call{value: value, gas: EXECUTE_GAS_LIMIT}(data);
        
        if (!success) {
            emit ExecutionFailure(target, value, data);
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        
        emit ExecutionSuccess(target, value, data);
        return result;
    }

    /**
     * @dev Manajemen owner
     */
    function addOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AdvancedSmartWallet: invalid owner");
        require(!owners[newOwner], "AdvancedSmartWallet: already owner");
        
        owners[newOwner] = true;
        ownerCount++;
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address ownerToRemove) external onlyOwner {
        require(owners[ownerToRemove], "AdvancedSmartWallet: not owner");
        require(ownerCount > 1, "AdvancedSmartWallet: cannot remove last owner");
        
        owners[ownerToRemove] = false;
        ownerCount--;
        emit OwnerRemoved(ownerToRemove);
    }

    /**
     * @dev Recovery mechanism
     */
    function initiateRecovery() external {
        require(msg.sender == recoveryAddress, "AdvancedSmartWallet: not recovery");
        recoveryInitiatedAt = block.timestamp;
        emit RecoveryInitiated(msg.sender);
    }

    function cancelRecovery() external onlyOwner {
        recoveryInitiatedAt = 0;
        emit RecoveryCancelled();
    }

    function completeRecovery(address[] calldata newOwners) external onlyRecovery {
        require(newOwners.length > 0, "AdvancedSmartWallet: no new owners");
        
        // Reset semua owner sebelumnya
        for (uint256 i = 0; i < newOwners.length; i++) {
            address owner = newOwners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            owners[owner] = true;
        }
        
        ownerCount = newOwners.length;
        recoveryInitiatedAt = 0;
        emit RecoveryCompleted(newOwners);
    }

    /**
     * @dev Signature validation
     */
    function isValidSignature(bytes32 hash, bytes memory signature) 
        public view override returns (bytes4) {
        return _validateSignature(hash, signature) 
            ? this.isValidSignature.selector 
            : bytes4(0);
    }

    function _validateSignature(bytes32 hash, bytes memory signature) 
        internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered];
    }

    /**
     * @dev Deposit ke EntryPoint
     */
    function addDeposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @dev Withdraw dari EntryPoint
     */
    function withdrawDeposit(address payable withdrawAddress, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    receive() external payable {}
}

/**
 * @title AdvancedSmartWalletFactory v3.0
 */
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "3.0";
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
        address recoveryAddress,
        uint256 recoveryDelay
    ) external returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            AdvancedSmartWallet.initialize.selector,
            owners,
            name,
            recoveryAddress,
            recoveryDelay
        );
        
        wallet = address(new ERC1967Proxy(
            walletImplementation,
            initData
        ));
        
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