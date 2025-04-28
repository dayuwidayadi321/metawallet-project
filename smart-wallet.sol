// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @title SmartWalletV3
 * @dev Upgradeable Smart Contract Wallet supporting meta-transactions, signature-based operations, and UUPS upgradeability.
 */
contract SmartWalletV3 is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, EIP712, IERC1271 {
    using ECDSA for bytes32;

    // --- Constants ---
    string private constant _EIP712_NAME = "SmartWalletV3";
    string private constant _EIP712_VERSION = "3.0";

    bytes32 private constant _DEPOSIT_TYPEHASH = keccak256("Deposit(address sender,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 private constant _WITHDRAW_TYPEHASH = keccak256("Withdraw(address recipient,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 private constant _UPGRADE_TYPEHASH = keccak256("Upgrade(address newImplementation,uint256 nonce,uint256 deadline)");

    // --- Storage ---
    address public relayer;
    mapping(address => uint256) public nonces;

    // --- Events ---
    event Deposited(address indexed sender, uint256 amount, uint256 timestamp);
    event Withdrawn(address indexed recipient, uint256 amount, uint256 timestamp);
    event SubWalletCreated(address indexed relayer, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Upgraded(address indexed newImplementation, uint256 timestamp);

    // --- Initializer ---
    /**
     * @dev Initializes the smart wallet with the given initial owner.
     */
    function initialize(address initialOwner) public initializer {
        __Ownable2Step_init();
        __Ownable_init(initialOwner);
        __EIP712_init(_EIP712_NAME, _EIP712_VERSION);

        relayer = initialOwner;
        emit SubWalletCreated(relayer, block.timestamp);
        emit OwnershipTransferred(address(0), initialOwner);
    }

    // --- Modifiers ---
    modifier checkDeadline(uint256 deadline) {
        require(block.timestamp <= deadline, "SmartWalletV3: transaction expired");
        _;
    }

    modifier onlyRelayerOrOwner() {
        require(msg.sender == relayer || msg.sender == owner(), "SmartWalletV3: not authorized");
        _;
    }

    // --- Receive Ether ---
    receive() external payable {
        emit Deposited(msg.sender, msg.value, block.timestamp);
    }

    // --- SubWallet (Relayer) Management ---
    /**
     * @dev Sets a new relayer address.
     */
    function setRelayer(address newRelayer) external onlyOwner {
        require(newRelayer != address(0), "SmartWalletV3: invalid relayer");
        relayer = newRelayer;
        emit SubWalletCreated(newRelayer, block.timestamp);
    }

    // --- Deposit / Withdrawal via Signature ---
    /**
     * @dev Allows deposit by verifying sender's signature.
     */
    function depositWithSignature(
        address sender,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external checkDeadline(deadline) {
        bytes32 structHash = keccak256(
            abi.encode(
                _DEPOSIT_TYPEHASH,
                sender,
                amount,
                nonces[sender]++,
                deadline
            )
        );

        _verifySignature(sender, structHash, signature);
        emit Deposited(sender, amount, block.timestamp);
    }

    /**
     * @dev Allows withdrawal to a recipient by verifying owner's signature.
     */
    function withdrawWithSignature(
        address payable recipient,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external checkDeadline(deadline) {
        bytes32 structHash = keccak256(
            abi.encode(
                _WITHDRAW_TYPEHASH,
                recipient,
                amount,
                nonces[owner()]++,
                deadline
            )
        );

        _verifySignature(owner(), structHash, signature);
        require(address(this).balance >= amount, "SmartWalletV3: insufficient balance");

        recipient.transfer(amount);
        emit Withdrawn(recipient, amount, block.timestamp);
    }

    // --- Upgradeability via Signature ---
    /**
     * @dev Allows contract upgrade via owner's signature.
     */
    function upgradeToWithSignature(
        address newImplementation,
        uint256 deadline,
        bytes calldata signature
    ) external checkDeadline(deadline) {
        bytes32 structHash = keccak256(
            abi.encode(
                _UPGRADE_TYPEHASH,
                newImplementation,
                nonces[owner()]++,
                deadline
            )
        );

        _verifySignature(owner(), structHash, signature);
        _upgradeTo(newImplementation);
        emit Upgraded(newImplementation, block.timestamp);
    }

    /**
     * @dev Authorizes an upgrade. Only the owner can perform upgrades.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // --- Helpers ---
    function _verifySignature(
        address signer,
        bytes32 structHash,
        bytes memory signature
    ) internal view {
        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = digest.recover(signature);
        require(recovered == signer, "SmartWalletV3: invalid signature");
    }

    // --- ERC1271 Support (Smart Wallet Signature Verification) ---
    /**
     * @dev Implements ERC1271 signature verification.
     */
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view override returns (bytes4 magicValue) {
        address recovered = hash.recover(signature);
        if (recovered == owner() || recovered == relayer) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }

    // --- Views ---
    /**
     * @dev Returns the EIP712 domain separator.
     */
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Returns the current ETH balance of the wallet.
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}