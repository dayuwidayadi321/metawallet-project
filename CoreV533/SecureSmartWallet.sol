// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "./CoreV533.sol";

contract SecureSmartWallet is Initializable, CoreV533, IERC1271Upgradeable, EIP712Upgradeable {
    /* ========== CONSTANTS ========== */
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "5.3.3";
    bytes4 private constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
    bytes32 private constant WITHDRAW_TYPEHASH = 
        keccak256("WithdrawETH(address receiver,uint256 amount,uint256 nonce)");
    bytes32 private constant USER_OP_TYPEHASH = 
        keccak256("SubmitUserOp(UserOperation userOp,uint256 nonce)");

    /* ========== STRUCTS ========== */
    struct BundlerConfig {
        address bundler;
        uint256 maxFeePerGas;
        uint256 maxPriorityFee;
    }

    /* ========== STATE VARIABLES ========== */
    BundlerConfig public bundlerConfig;
    mapping(address => uint256) public withdrawalAllowance;
    mapping(address => uint256) public withdrawalNonce;
    mapping(address => uint256) public bundlerNonce;

    /* ========== EVENTS ========== */
    event ETHWithdrawn(address indexed receiver, uint256 amount);
    event BundlerConfigured(address indexed bundler, uint256 maxFee, uint256 maxPriorityFee);
    event WithdrawalAllowanceSet(address indexed delegate, uint256 amount);

    /* ========== ERRORS ========== */
    error InsufficientBalance();
    error InvalidSignature();
    error ExceedsAllowance();
    error TransferFailed();
    error InvalidBundler();
    error NotAuthorizedBundler();
    error BundlerSubmissionFailed();
    error FunctionNotFound();

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        CoreV533(_entryPoint, _gasOracle)
    {
        _disableInitializers();
    }

    /* ========== INITIALIZER ========== */
    function initialize(
        address[] calldata _owners,
        address[] calldata _guardians,
        uint64 _guardianThreshold,
        address _factory,
        uint256[] calldata _supportedChains,
        address _defaultPaymaster,
        BundlerConfig calldata _bundlerConfig
    ) external initializer {
        // Initialize EIP-712
        __EIP712_init(NAME, VERSION);
        
        // Initialize Core v5.3.3
        __CoreV533_init(
            _owners,
            _guardians.length > 0 ? _guardians[0] : address(0),
            _guardianThreshold,
            1 days // Default cooldown
        );

        // Set execution environment
        env.defaultPaymaster = _defaultPaymaster;
        factory = _factory;

        // Add additional guardians (if any)
        for (uint i = 1; i < _guardians.length; i++) {
            this.addGuardian(_guardians[i]);
        }

        // Set cross-chain support
        for (uint i = 0; i < _supportedChains.length; i++) {
            supportedChains[_supportedChains[i]] = true;
        }

        // Configure bundler
        _setBundlerConfig(_bundlerConfig.bundler, _bundlerConfig.maxFeePerGas, _bundlerConfig.maxPriorityFee);
    }

    /* ========== CUSTOM: ETH WITHDRAWAL ========== */
    function withdrawETH(
        address payable receiver,
        uint256 amount,
        bytes calldata signature
    ) external nonReentrant whenNotLocked {
        if (amount > address(this).balance) revert InsufficientBalance();
        
        if (!this.isOwner(msg.sender)) {
            bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
                WITHDRAW_TYPEHASH,
                receiver,
                amount,
                withdrawalNonce[receiver]++
            )));
            
            if (!_verifySignature(hash, signature)) revert InvalidSignature();
            if (amount > withdrawalAllowance[receiver]) revert ExceedsAllowance();
            
            withdrawalAllowance[receiver] -= amount;
        }

        (bool success, ) = receiver.call{value: amount}("");
        if (!success) revert TransferFailed();
        
        emit ETHWithdrawn(receiver, amount);
    }

    function setWithdrawalAllowance(address delegate, uint256 amount) external onlyOwner {
        withdrawalAllowance[delegate] = amount;
        emit WithdrawalAllowanceSet(delegate, amount);
    }

    /* ========== CUSTOM: BUNDLER SUPPORT ========== */
    function _setBundlerConfig(
        address bundler,
        uint256 maxFeePerGas,
        uint256 maxPriorityFee
    ) internal onlyOwner {
        if (bundler == address(0)) revert InvalidBundler();
        
        bundlerConfig = BundlerConfig(bundler, maxFeePerGas, maxPriorityFee);
        emit BundlerConfigured(bundler, maxFeePerGas, maxPriorityFee);
    }

    function submitUserOpToBundler(
        UserOperation calldata userOp,
        bytes calldata bundlerSignature
    ) external payable nonReentrant onlyOwner returns (bytes memory) {
        if (msg.sender != bundlerConfig.bundler) revert NotAuthorizedBundler();
        
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            USER_OP_TYPEHASH,
            keccak256(abi.encode(userOp)),
            bundlerNonce[msg.sender]++
        )));
        
        if (ECDSA.recover(hash, bundlerSignature) != msg.sender) revert InvalidSignature();

        (bool success, bytes memory result) = address(env.entryPoint).call{value: msg.value}(
            abi.encodeWithSignature("handleOps(UserOperation[],address)", [userOp], msg.sender)
        );
        
        if (!success) revert BundlerSubmissionFailed();
        return result;
    }

    /* ========== OVERRIDES ========== */
    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        override
        returns (bytes4)
    {
        if (env.isLocked) return bytes4(0xffffffff);
        
        address signer = ECDSA.recover(hash, signature);
        return (_verifySignature(hash, signature) || this.isGuardian(signer))
            ? EIP1271_MAGIC_VALUE 
            : bytes4(0xffffffff);
    }

    /* ========== FALLBACKS ========== */
    fallback() external payable override {
        address plugin = selectorToPlugin[msg.sig];
        if (plugin != address(0)) {
            require(installedPlugins[plugin].isWhitelisted, "Plugin not whitelisted");
            
            (bool success, bytes memory result) = plugin.delegatecall(msg.data);
            if (!success) {
                assembly { revert(add(result, 32), mload(result)) }
            }
            assembly { return(add(result, 32), mload(result)) }
        }
        revert FunctionNotFound();
    }

    receive() external payable override {
        emit ETHReceived(msg.sender, msg.value);
    }

    /* ========== VIEW FUNCTIONS ========== */
    function isOwner(address account) public view override returns (bool) {
        address[] memory owners = this.getOwners();
        for (uint i = 0; i < owners.length; i++) {
            if (owners[i] == account) {
                return true;
            }
        }
        return false;
    }

    function isGuardian(address account) public view returns (bool) {
        address[] memory guardians = this.getGuardians();
        for (uint i = 0; i < guardians.length; i++) {
            if (guardians[i] == account) {
                return true;
            }
        }
        return false;
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}