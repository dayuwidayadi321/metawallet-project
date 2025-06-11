// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Import OpenZeppelin untuk upgradeability dan utilitas
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// Import standar ERC-4337
import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

// SmartWalletFactory
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./SmartWalletV1.sol";

contract SmartWalletV1 is UUPSUpgradeable, ReentrancyGuardUpgradeable, IAccount {
    using ECDSA for bytes32;

    // --- State Variables ---
    address public immutable entryPoint;
    
    // Multi-owner management
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public requiredConfirmations;
    
    // Guardian management
    address[] public guardians;
    mapping(address => bool) public isGuardian;
    
    // Transaction management
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
    }
    mapping(bytes32 => Transaction) public transactions;
    mapping(bytes32 => mapping(address => bool)) public confirmations;
    mapping(bytes32 => uint256) public confirmationCounts;
    
    // Constants
    uint256 public constant MAX_OWNERS = 10;
    uint256 public constant MAX_GUARDIANS = 10;
    
    // --- Events ---
    event Deposit(address indexed sender, uint256 amount);
    event Withdrawal(address indexed recipient, uint256 amount);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed oldOwner);
    event GuardianAdded(address indexed newGuardian);
    event GuardianRemoved(address indexed oldGuardian);
    event TransactionSubmitted(bytes32 indexed txHash, address indexed initiator);
    event TransactionConfirmed(bytes32 indexed txHash, address indexed confirmer);
    event TransactionExecuted(bytes32 indexed txHash, address indexed executor);
    event SmartRevokeExecuted(address indexed token, address indexed spender);
    event BatchExecuted(uint256 numTransactions);

    // --- Modifiers ---
    modifier onlyOwner() {
        require(isOwner[msg.sender], "SmartWallet: caller is not an owner");
        _;
    }
    
    modifier onlyGuardian() {
        require(isGuardian[msg.sender], "SmartWallet: caller is not a guardian");
        _;
    }
    
    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "SmartWallet: caller is not entry point");
        _;
    }

    // --- Constructor ---
    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    // --- Initializer ---
    function initialize(
        address[] memory _initialOwners,
        uint256 _requiredConfirmations
    ) public initializer {
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        
        require(_initialOwners.length > 0, "SmartWallet: at least one owner required");
        require(_initialOwners.length <= MAX_OWNERS, "SmartWallet: too many owners");
        require(_requiredConfirmations > 0 && _requiredConfirmations <= _initialOwners.length, 
            "SmartWallet: invalid required confirmations");
        
        for (uint256 i = 0; i < _initialOwners.length; i++) {
            address owner = _initialOwners[i];
            require(owner != address(0), "SmartWallet: zero address not allowed");
            require(!isOwner[owner], "SmartWallet: duplicate owner");
            
            owners.push(owner);
            isOwner[owner] = true;
        }
        
        requiredConfirmations = _requiredConfirmations;
    }

    // --- ERC-4337 Implementation ---
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        require(msg.sender == entryPoint, "SmartWallet: only entry point");
        
        // Validate signatures
        bytes memory signature = userOp.signature;
        require(signature.length >= 65 * requiredConfirmations, "SmartWallet: insufficient signatures");
        
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address lastSigner = address(0);
        
        for (uint i = 0; i < requiredConfirmations; i++) {
            bytes memory currentSig = new bytes(65);
            for (uint j = 0; j < 65; j++) {
                currentSig[j] = signature[i*65 + j];
            }
            
            address signer = hash.recover(currentSig);
            require(isOwner[signer], "SmartWallet: invalid signer");
            require(signer > lastSigner, "SmartWallet: signatures not in order");
            lastSigner = signer;
        }
        
        // Pay missing funds if needed
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            success; // ignore failure (EntryPoint will handle it)
        }
        
        return 0;
    }

    // --- Core Functions ---
    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external override onlyEntryPoint {
        _call(dest, value, func);
    }

    function executeBatch(
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external override onlyEntryPoint {
        require(dest.length == values.length && dest.length == funcs.length, "SmartWallet: array length mismatch");
        
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], funcs[i]);
        }
        
        emit BatchExecuted(dest.length);
    }

    // --- Owner Management ---
    function addOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "SmartWallet: zero address");
        require(!isOwner[newOwner], "SmartWallet: already owner");
        require(owners.length < MAX_OWNERS, "SmartWallet: max owners reached");
        
        owners.push(newOwner);
        isOwner[newOwner] = true;
        
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address ownerToRemove) external onlyOwner {
        require(ownerToRemove != address(0), "SmartWallet: zero address");
        require(isOwner[ownerToRemove], "SmartWallet: not owner");
        require(owners.length > requiredConfirmations, "SmartWallet: cannot go below required confirmations");
        
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == ownerToRemove) {
                owners[i] = owners[owners.length - 1];
                owners.pop();
                isOwner[ownerToRemove] = false;
                break;
            }
        }
        
        emit OwnerRemoved(ownerToRemove);
    }

    function setRequiredConfirmations(uint256 newRequiredConfirmations) external onlyOwner {
        require(newRequiredConfirmations > 0 && newRequiredConfirmations <= owners.length, 
            "SmartWallet: invalid confirmations");
        requiredConfirmations = newRequiredConfirmations;
    }

    // --- Guardian Management ---
    function addGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "SmartWallet: zero address");
        require(!isGuardian[newGuardian], "SmartWallet: already guardian");
        require(guardians.length < MAX_GUARDIANS, "SmartWallet: max guardians reached");
        
        guardians.push(newGuardian);
        isGuardian[newGuardian] = true;
        
        emit GuardianAdded(newGuardian);
    }

    function removeGuardian(address guardianToRemove) external onlyOwner {
        require(guardianToRemove != address(0), "SmartWallet: zero address");
        require(isGuardian[guardianToRemove], "SmartWallet: not guardian");
        
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == guardianToRemove) {
                guardians[i] = guardians[guardians.length - 1];
                guardians.pop();
                isGuardian[guardianToRemove] = false;
                break;
            }
        }
        
        emit GuardianRemoved(guardianToRemove);
    }

    // --- Transaction Management ---
    function submitTransaction(
        address to,
        uint256 value,
        bytes memory data
    ) external onlyOwner returns (bytes32) {
        bytes32 txHash = keccak256(abi.encodePacked(to, value, data, block.timestamp));
        require(transactions[txHash].to == address(0), "SmartWallet: transaction exists");
        
        transactions[txHash] = Transaction({
            to: to,
            value: value,
            data: data,
            executed: false
        });
        
        emit TransactionSubmitted(txHash, msg.sender);
        return txHash;
    }

    function confirmTransaction(bytes32 txHash) external onlyOwner {
        require(transactions[txHash].to != address(0), "SmartWallet: transaction not found");
        require(!transactions[txHash].executed, "SmartWallet: transaction already executed");
        require(!confirmations[txHash][msg.sender], "SmartWallet: already confirmed");
        
        confirmations[txHash][msg.sender] = true;
        confirmationCounts[txHash] += 1;
        
        emit TransactionConfirmed(txHash, msg.sender);
    }

    function executeTransaction(bytes32 txHash) external onlyOwner nonReentrant {
        Transaction storage transaction = transactions[txHash];
        require(transaction.to != address(0), "SmartWallet: transaction not found");
        require(!transaction.executed, "SmartWallet: transaction already executed");
        require(confirmationCounts[txHash] >= requiredConfirmations, "SmartWallet: insufficient confirmations");
        
        transaction.executed = true;
        _call(transaction.to, transaction.value, transaction.data);
        
        emit TransactionExecuted(txHash, msg.sender);
    }

    // --- Emergency Features ---
    function smartRevoke(address token, address spender) external onlyOwner {
        IERC20(token).approve(spender, 0);
        emit SmartRevokeExecuted(token, spender);
    }

    function emergencyWithdraw(address token, address to, uint256 amount) external onlyGuardian {
        require(isGuardian[msg.sender], "SmartWallet: only guardian");
        require(owners.length == 0, "SmartWallet: owners still exist");
        
        if (token == address(0)) {
            (bool success,) = to.call{value: amount}("");
            require(success, "SmartWallet: ETH transfer failed");
        } else {
            require(IERC20(token).transfer(to, amount), "SmartWallet: token transfer failed");
        }
        
        emit Withdrawal(to, amount);
    }

    // --- View Functions ---
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getGuardians() external view returns (address[] memory) {
        return guardians;
    }

    function getTransaction(bytes32 txHash) external view returns (Transaction memory) {
        return transactions[txHash];
    }

    function getConfirmationCount(bytes32 txHash) external view returns (uint256) {
        return confirmationCounts[txHash];
    }

    function hasConfirmed(bytes32 txHash, address owner) external view returns (bool) {
        return confirmations[txHash][owner];
    }

    // --- Internal Functions ---
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}


contract SmartWalletFactory {
    address public immutable entryPoint;
    address public immutable walletImplementation;
    
    event WalletCreated(address indexed wallet, address[] owners, uint256 requiredConfirmations);
    
    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new SmartWalletV1(_entryPoint));
    }
    
    function createWallet(
        address[] memory owners,
        uint256 requiredConfirmations,
        bytes32 salt
    ) external returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(
            walletImplementation,
            abi.encodeWithSelector(
                SmartWalletV1.initialize.selector,
                owners,
                requiredConfirmations
            )
        );
        
        emit WalletCreated(address(proxy), owners, requiredConfirmations);
        return address(proxy);
    }
    
    function getWalletAddress(
        address[] memory owners,
        uint256 requiredConfirmations,
        bytes32 salt
    ) external view returns (address) {
        bytes memory initializationData = abi.encodeWithSelector(
            SmartWalletV1.initialize.selector,
            owners,
            requiredConfirmations
        );
        
        bytes memory creationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(walletImplementation, initializationData)
        );
        
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(creationCode)
            )
        );
        
        return address(uint160(uint256(hash)));
    }
}