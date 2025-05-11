// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "./CoreV533.sol"; // <-- Perubahan import ke CoreV533

/**
 * @title SecureSmartWallet v5.3.3 - Enterprise Smart Wallet with ETH Withdrawal & Bundler Support
 * @author DFXC IndonesiaSecurity (Upgraded to Core v5.3.3)
 * @dev Key Features:
 * - Inherits Core v5.3.3 (Enhanced Security & EIP-4337)
 * - Native ETH Withdrawal & Bundler Integration
 * - Modular Design with Plugin Support
 * - Guardian Emergency Recovery
 */
contract SecureSmartWallet is Initializable, CoreV533, IERC1271Upgradeable, EIP712Upgradeable {
    /* ========== CONSTANTS ========== */
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "5.3.3"; // <-- Update versi
    bytes4 private constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

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

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        CoreV533(_entryPoint, _gasOracle) // <-- Perubahan constructor ke CoreV533
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
        __EIP712_init("SecureSmartWallet", "5.3.3"); // <-- Update versi
        
        // Initialize Core v5.3.3
        __CoreV533_init( // <-- Perubahan nama fungsi initializer
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
            addGuardian(_guardians[i]); // <-- Menggunakan fungsi addGuardian yang tersedia
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
        require(amount <= address(this).balance, "Insufficient balance");
        
        if (!isOwner(msg.sender)) { // <-- Menggunakan fungsi isOwner
            bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
                keccak256("WithdrawETH(address receiver,uint256 amount,uint256 nonce)"),
                receiver,
                amount,
                withdrawalNonce[receiver]++
            )));
            require(_verifySignature(hash, signature), "Invalid signature");
            require(amount <= withdrawalAllowance[receiver], "Exceeds allowance");
            withdrawalAllowance[receiver] -= amount;
        }

        (bool success, ) = receiver.call{value: amount}("");
        require(success, "Transfer failed");
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
        require(bundler != address(0), "Invalid bundler");
        bundlerConfig = BundlerConfig(bundler, maxFeePerGas, maxPriorityFee);
        emit BundlerConfigured(bundler, maxFeePerGas, maxPriorityFee);
    }

    function submitUserOpToBundler(
        UserOperation calldata userOp,
        bytes calldata bundlerSignature
    ) external payable nonReentrant onlyOwner returns (bytes memory) {
        require(msg.sender == bundlerConfig.bundler, "Not authorized bundler");
        
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("SubmitUserOp(UserOperation userOp,uint256 nonce)"),
            keccak256(abi.encode(userOp)),
            bundlerNonce[msg.sender]++
        )));
        require(ECDSA.recover(hash, bundlerSignature) == msg.sender, "Invalid bundler sig");

        (bool success, bytes memory result) = address(env.entryPoint).call{value: msg.value}(
            abi.encodeWithSignature("handleOps(UserOperation[],address)", [userOp], msg.sender)
        );
        require(success, "Bundler submission failed");
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
        return (_verifySignature(hash, signature) || isGuardian(ECDSA.recover(hash, signature))) // <-- Menggunakan fungsi isGuardian
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
        revert("Function not found");
    }

    receive() external payable override {
        emit ETHReceived(msg.sender, msg.value);
    }

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}