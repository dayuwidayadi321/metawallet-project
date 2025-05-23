// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "./SecureSmartWalletCore.sol";

/**
 * @title SecureSmartWallet v5.2 - Enterprise Smart Wallet with ETH Withdrawal & Bundler Support
 * @author DFXC IndonesiaSecurity (Original Core v5.2 by Dayu Widayadi)
 * @dev Key Features:
 * - Inherits SecureSmartWalletCore v5.2 (EIP-4337, Plugin System, Session Keys)
 * - Custom: Native ETH Withdrawal & Bundler Integration
 * - Modular Design for Easy Extensions
 */
contract SecureSmartWallet is Initializable, SecureSmartWalletCore, IERC1271Upgradeable, EIP712Upgradeable {
    /* ========== CONSTANTS ========== */
    string public constant NAME = "SecureSmartWallet";
    string public constant VERSION = "5.2.1";
    bytes4 private constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

    /* ========== STRUCTS ========== */
    struct BundlerConfig {
        address bundler;
        uint256 maxFeePerGas;
        uint256 maxPriorityFee;
    }

    /* ========== STATE VARIABLES ========== */
    BundlerConfig public bundlerConfig;
    mapping(address => uint256) public withdrawalAllowance; // Withdrawal limits per address
    mapping(address => uint256) public withdrawalNonce; // Nonce for withdrawal signatures
    mapping(address => uint256) public bundlerNonce; // Nonce for bundler operations

    /* ========== EVENTS ========== */
    event ETHWithdrawn(address indexed receiver, uint256 amount);
    event BundlerConfigured(address indexed bundler, uint256 maxFee, uint256 maxPriorityFee);
    event WithdrawalAllowanceSet(address indexed delegate, uint256 amount);
    event WalletInitialized(address[] owners, address[] guardians);

    /* ========== CONSTRUCTOR ========== */
    constructor(IEntryPoint _entryPoint, address _gasOracle) 
        SecureSmartWalletCore(_entryPoint, _gasOracle) 
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
        // Initialize Core v5.2
        __EIP712_init("SecureSmartWallet", "5.2");
        
        // Set execution environment
        env = ExecutionEnvironment({
            entryPoint: IEntryPoint(entryPoint),
            defaultPaymaster: _defaultPaymaster,
            chainId: CHAIN_ID,
            isLocked: false,
            upgradeTimelock: 0,
            securityDelay: 1 days
        });
        
        factory = _factory;

        // Set owners
        for (uint i = 0; i < _owners.length; i++) {
            _owners.add(_owners[i]);
        }

        // Initialize guardians
        for (uint i = 0; i < _guardians.length; i++) {
            _guardianConfig.guardians.add(_guardians[i]);
        }
        _guardianConfig.threshold = _guardianThreshold;
        _guardianConfig.cooldown = 1 days;

        // Set cross-chain support
        for (uint i = 0; i < _supportedChains.length; i++) {
            supportedChains[_supportedChains[i]] = true;
        }

        // Configure bundler
        _setBundlerConfig(_bundlerConfig.bundler, _bundlerConfig.maxFeePerGas, _bundlerConfig.maxPriorityFee);

        emit WalletInitialized(_owners, _guardians);
    }

    /* ========== CUSTOM: ETH WITHDRAWAL ========== */
    function withdrawETH(
        address payable receiver,
        uint256 amount,
        bytes calldata signature
    ) external whenNotLocked {
        require(amount <= address(this).balance, "Insufficient balance");
        
        // Validate signature if not owner
        if (!_owners.contains(msg.sender)) {
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
    ) external payable onlyOwner returns (bytes memory) {
        require(msg.sender == bundlerConfig.bundler, "Not authorized bundler");
        
        // Verify bundler's signature
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("SubmitUserOp(UserOperation userOp,uint256 nonce)"),
            keccak256(abi.encode(userOp)),
            bundlerNonce[msg.sender]++
        )));
        require(ECDSA.recover(hash, bundlerSignature) == msg.sender, "Invalid bundler sig");

        // Forward to EntryPoint
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
        return (_verifySignature(hash, signature) || _guardianConfig.guardians.contains(ECDSA.recover(hash, signature))) 
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


DeclarationError: Undeclared identifier.
   --> Core-52/SecureSmartWalletCore.sol:142:9:
    |
142 |         __EIP712_init("SecureSmartWallet", "5.2");
    |         ^^^^^^^^^^^^^
