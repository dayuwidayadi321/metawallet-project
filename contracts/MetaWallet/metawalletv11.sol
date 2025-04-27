// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MetaWalletV11 is ReentrancyGuard, Ownable {
    using ECDSA for bytes32;

    address public owner;
    address public smartWallet; // New smart wallet that will cover gas fees
    bytes public userWalletBytecode;
    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isDeployed;
    mapping(uint256 => bytes32) public domainSeparators; // For Multi-Chain support

    // EIP-712 constants
    bytes32 public constant META_TX_TYPEHASH = keccak256("MetaTransaction(address user,address target,bytes data,uint256 value,uint256 fee,uint256 nonce,uint256 chainId)");
    bytes32 public constant META_DEPLOY_TYPEHASH = keccak256("MetaDeploy(address user,uint256 nonce,uint256 chainId)");
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    
    string public constant NAME = "MetaWallet";
    string public constant VERSION = "11"; // Upgraded version

    event WalletDeployed(address indexed user, address wallet);
    event MetaTransactionExecuted(address indexed user, address target, uint256 value, bytes data, uint256 fee);
    event MetaWalletDeployed(address indexed user, address wallet);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event SmartWalletSet(address smartWallet);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyRelayer() {
        require(relayerWhitelist[msg.sender], "Relayer not authorized");
        _;
    }

    modifier validNonce(address user, uint256 nonce) {
        require(nonces[user] == nonce, "Invalid nonce");
        nonces[user]++;
        _;
    }

    modifier validSignature(bytes32 digest, address user, bytes memory signature) {
        require(digest.recover(signature) == user, "Invalid signature");
        _;
    }

    modifier hasSmartWallet() {
        require(smartWallet != address(0), "Smart wallet not set");
        _;
    }

    function setSmartWallet(address _smartWallet) external onlyOwner {
        smartWallet = _smartWallet;
        emit SmartWalletSet(_smartWallet);
    }

    function computeWalletAddress(address user) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        return Create2.computeAddress(salt, keccak256(bytecode));
    }

    function setDomainSeparator(uint256 chainId) external onlyOwner {
        domainSeparators[chainId] = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes(NAME)),
            keccak256(bytes(VERSION)),
            chainId,
            address(this)
        ));
    }

    function deployWallet(address user) external onlyOwner {
        require(!isDeployed[user], "Wallet already deployed");
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        address wallet = Create2.deploy(0, salt, bytecode);
        isDeployed[user] = true;
        emit WalletDeployed(user, wallet);
    }

    function deployWalletMeta(
        address user,
        uint256 nonce,
        bytes calldata signature,
        uint256 chainId
    ) external onlyRelayer validNonce(user, nonce) validSignature(getDeployDigest(user, nonce, chainId), user, signature) {
        require(!isDeployed[user], "Wallet already deployed");

        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        address wallet = Create2.deploy(0, salt, bytecode);
        isDeployed[user] = true;

        emit MetaWalletDeployed(user, wallet);
    }

    function executeMetaTransaction(
        address user,
        address target,
        bytes calldata data,
        uint256 value,
        uint256 fee,
        uint256 nonce,
        bytes calldata signature,
        uint256 chainId
    ) external payable onlyRelayer validNonce(user, nonce) validSignature(getTransactionDigest(user, target, data, value, fee, nonce, chainId), user, signature) nonReentrant hasSmartWallet {
        address wallet = computeWalletAddress(user);
        require(wallet.code.length > 0, "Wallet not deployed");

        uint256 totalAmount = value + fee;
        require(msg.value >= totalAmount, "Insufficient msg.value");

        // Pay the gas fee from smart wallet
        (bool success, ) = smartWallet.call{value: fee}("");
        require(success, "Gas fee payment failed");

        (success, ) = wallet.call{value: value}(abi.encodeWithSignature(
            "execute(address,bytes,uint256,uint256,address)",
            target,
            data,
            value,
            fee,
            msg.sender
        ));
        require(success, "Wallet execution failed");

        emit MetaTransactionExecuted(user, target, value, data, fee);
    }

    function addRelayer(address relayer) external onlyOwner {
        require(!relayerWhitelist[relayer], "Relayer already added");
        relayerWhitelist[relayer] = true;
        emit RelayerAdded(relayer);
    }

    function removeRelayer(address relayer) external onlyOwner {
        require(relayerWhitelist[relayer], "Relayer not found");
        relayerWhitelist[relayer] = false;
        emit RelayerRemoved(relayer);
    }

    function getTransactionDigest(
        address user,
        address target,
        bytes memory data,
        uint256 value,
        uint256 fee,
        uint256 nonce,
        uint256 chainId
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparators[chainId],
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                user,
                target,
                keccak256(data),
                value,
                fee,
                nonce,
                chainId
            ))
        ));
    }

    function getDeployDigest(address user, uint256 nonce, uint256 chainId) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparators[chainId],
            keccak256(abi.encode(
                META_DEPLOY_TYPEHASH,
                user,
                nonce,
                chainId
            ))
        ));
    }
}