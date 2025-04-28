// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract SmartWalletV2 is EIP712 {
    using ECDSA for bytes32;

    // Struct untuk data meta-transaction
    struct MetaTx {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 deadline;
    }

    // EIP-712 typehash
    bytes32 private constant META_TX_TYPEHASH = 
        keccak256("MetaTx(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)");

    address public owner;
    IEntryPoint public immutable entryPoint;
    
    mapping(address => bool) public subWallets;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public tokenAllowances;
    mapping(address => bool) public authorizedDepositors; // Pembatasan untuk deposit ETH

    event SubWalletCreated(address indexed subWallet, address indexed owner);
    event SubWalletRemoved(address indexed subWallet, address indexed owner);
    event EthTransferred(address indexed from, address indexed to, uint256 value);
    event TokenTransferred(address indexed token, address indexed from, address indexed to, uint256 value);
    event Approval(address indexed token, address indexed spender, uint256 value);
    event ApprovalRevoked(address indexed token, address indexed spender);
    event Deposit(address indexed from, uint256 amount);

    constructor(address _entryPoint) EIP712("SmartWalletV2", "1") {
        owner = msg.sender;
        entryPoint = IEntryPoint(_entryPoint);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlySubWallet() {
        require(subWallets[msg.sender], "Not sub-wallet");
        _;
    }

    modifier onlyAuthorizedDepositor() {
        require(authorizedDepositors[msg.sender], "Not authorized depositor");
        _;
    }

    // Fungsi untuk membuat sub-wallet baru
    function createSubWallet(bytes calldata signature, uint256 deadline) external {
        require(block.timestamp <= deadline, "Signature expired");

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                address(this),
                msg.sender,
                0,
                keccak256(bytes("createSubWallet")),
                nonces[msg.sender],
                deadline
            ))
        );

        address signer = digest.recover(signature);
        require(signer == owner, "Invalid signature");
        require(!subWallets[msg.sender], "Sub-wallet exists");

        nonces[msg.sender]++;
        subWallets[msg.sender] = true;
        emit SubWalletCreated(msg.sender, owner);
    }

    // Fungsi untuk menghapus sub-wallet
    function removeSubWallet(address subWallet) external onlyOwner {
        require(subWallets[subWallet], "Not a sub-wallet");
        subWallets[subWallet] = false;
        emit SubWalletRemoved(subWallet, owner);
    }

    // Fungsi untuk mengirim ETH (meta-transaction)
    function sendEth(
        address to,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) external onlySubWallet {
        require(block.timestamp <= deadline, "Transaction expired");
        
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                msg.sender,
                to,
                value,
                keccak256(bytes("sendEth")),
                nonces[msg.sender]++,
                deadline
            ))
        );

        address signer = digest.recover(signature);
        require(signer == owner, "Invalid signature");
        
        require(address(this).balance >= value, "Insufficient balance for transfer");

        (bool success, ) = to.call{value: value}("");
        require(success, "ETH transfer failed");
        emit EthTransferred(msg.sender, to, value);
    }

    // Fungsi untuk mengirim ERC-20 (meta-transaction)
    function sendToken(
        address token,
        address to,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) external onlySubWallet {
        require(block.timestamp <= deadline, "Transaction expired");
        
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                msg.sender,
                to,
                value,
                keccak256(abi.encodePacked("sendToken", token)),
                nonces[msg.sender]++,
                deadline
            ))
        );

        address signer = digest.recover(signature);
        require(signer == owner, "Invalid signature");
        
        bool success = IERC20(token).transferFrom(msg.sender, to, value);
        require(success, "Token transfer failed");
        emit TokenTransferred(token, msg.sender, to, value);
    }

    // Fungsi untuk approve ERC-20 (meta-transaction)
    function approveToken(
        address token,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) external onlySubWallet {
        require(block.timestamp <= deadline, "Transaction expired");
        
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                msg.sender,
                spender,
                value,
                keccak256(abi.encodePacked("approveToken", token)),
                nonces[msg.sender]++,
                deadline
            ))
        );

        address signer = digest.recover(signature);
        require(signer == owner, "Invalid signature");
        
        tokenAllowances[msg.sender][token] = value;
        emit Approval(token, spender, value);
    }

    // Fungsi untuk revoke approval (meta-transaction)
    function revokeApproval(
        address token,
        address spender,
        uint256 deadline,
        bytes calldata signature
    ) external onlySubWallet {
        require(block.timestamp <= deadline, "Transaction expired");
        
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                msg.sender,
                spender,
                0,
                keccak256(abi.encodePacked("revokeApproval", token)),
                nonces[msg.sender]++,
                deadline
            ))
        );

        address signer = digest.recover(signature);
        require(signer == owner, "Invalid signature");
        
        delete tokenAllowances[msg.sender][token];
        emit ApprovalRevoked(token, spender);
    }

    // Fungsi untuk menerima pembayaran gas dari sub-wallet
    function payForGas(address subWallet, uint256 amount) external onlySubWallet {
        require(subWallets[subWallet], "Not a valid sub-wallet");
        require(address(this).balance >= amount, "Insufficient balance");
        payable(address(entryPoint)).transfer(amount);
    }

    // Fungsi untuk menyetujui depositor yang sah
    function authorizeDepositor(address depositor) external onlyOwner {
        authorizedDepositors[depositor] = true;
    }

    // Fungsi untuk menghapus depositor yang sah
    function revokeDepositor(address depositor) external onlyOwner {
        authorizedDepositors[depositor] = false;
    }

    // Fungsi untuk menerima deposit ETH
    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }
}
