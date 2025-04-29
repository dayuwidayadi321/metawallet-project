// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SmartWalletV5 is Ownable, EIP712 {
    // =============================================
    // ============== Constants ====================
    // =============================================
    string public constant WALLET_NAME = "SmartWallet";
    string public constant WALLET_VERSION = "5.0";

    bytes32 private constant _TRANSACTION_TYPEHASH =
        keccak256("Transaction(address to,uint256 value,bytes data,uint256 nonce,uint256 gasFee)");
    bytes32 private constant _REVOCATION_TYPEHASH =
        keccak256("RevokeAuthorization(address wallet,uint256 nonce,uint256 gasFee)");

    // =============================================
    // ============== State Variables ==============
    // =============================================
    uint256 private _nonce;
    bool public isRevoked;
    uint256 public minGasBalance;

    mapping(address => bool) public whitelistedRelayers;
    address[] public relayerAddresses;

    // =============================================
    // ================ Events =====================
    // =============================================
    event FundsReceived(address indexed sender, uint256 value);
    event ExecutedTransaction(address indexed to, uint256 value, bytes data, uint256 gasFee);
    event TokenWithdrawn(address indexed token, address indexed to, uint256 amount);
    event AuthorizationRevoked(address indexed revoker, uint256 gasFee);
    event AuthorizationRestored(address indexed restorer);
    event GasFeePaid(address indexed relayer, uint256 amount);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event MinGasBalanceUpdated(uint256 oldBalance, uint256 newBalance);

    // =============================================
    // ================ Modifiers ==================
    // =============================================
    modifier notRevoked() {
        require(!isRevoked, "Authorization has been revoked");
        _;
    }

    modifier ensureGasFunds() {
        require(address(this).balance >= minGasBalance, "Insufficient gas balance");
        _;
    }

    modifier onlyWhitelistedRelayer() {
        require(whitelistedRelayers[msg.sender], "Caller is not whitelisted relayer");
        _;
    }

    // =============================================
    // ============== Constructor ==================
    // =============================================
    constructor(uint256 _minGasBalance, address initialOwner) 
        Ownable(initialOwner)
        EIP712(WALLET_NAME, WALLET_VERSION)
    {
        minGasBalance = _minGasBalance;
        _addRelayer(msg.sender);
    }

    // =============================================
    // ========== External Functions ===============
    // =============================================

    receive() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }

    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 gasFee,
        bytes memory signature
    ) external onlyWhitelistedRelayer notRevoked ensureGasFunds returns (bytes memory) {
        require(to != address(0), "Invalid recipient");

        bytes32 structHash = keccak256(
            abi.encode(
                _TRANSACTION_TYPEHASH,
                to,
                value,
                keccak256(data),
                _nonce,
                gasFee
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        require(signer == owner(), "Invalid signature");

        _nonce++;

        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "Execution failed");

        if (gasFee > 0) {
            payable(msg.sender).transfer(gasFee);
            emit GasFeePaid(msg.sender, gasFee);
        }

        emit ExecutedTransaction(to, value, data, gasFee);
        return result;
    }

    function revokeAuthorization(
        uint256 gasFee,
        bytes memory signature
    ) external onlyWhitelistedRelayer ensureGasFunds {
        bytes32 structHash = keccak256(
            abi.encode(
                _REVOCATION_TYPEHASH,
                owner(),
                _nonce,
                gasFee
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        require(signer == owner(), "Invalid signature");

        isRevoked = true;
        _nonce++;

        if (gasFee > 0) {
            payable(msg.sender).transfer(gasFee);
            emit GasFeePaid(msg.sender, gasFee);
        }

        emit AuthorizationRevoked(owner(), gasFee);
    }

    function restoreAuthorization() external onlyOwner {
        require(isRevoked, "Authorization is not revoked");
        isRevoked = false;
        emit AuthorizationRestored(msg.sender);
    }

    function updateMinGasBalance(uint256 newMinGasBalance) external onlyOwner {
        uint256 oldBalance = minGasBalance;
        minGasBalance = newMinGasBalance;
        emit MinGasBalanceUpdated(oldBalance, newMinGasBalance);
    }

    // =============================================
    // ========== Relayer Management ===============
    // =============================================

    function addRelayer(address relayer) external onlyOwner {
        _addRelayer(relayer);
    }

    function removeRelayer(address relayer) external onlyOwner {
        require(whitelistedRelayers[relayer], "Address is not a relayer");

        whitelistedRelayers[relayer] = false;

        for (uint256 i = 0; i < relayerAddresses.length; i++) {
            if (relayerAddresses[i] == relayer) {
                relayerAddresses[i] = relayerAddresses[relayerAddresses.length - 1];
                relayerAddresses.pop();
                break;
            }
        }

        emit RelayerRemoved(relayer);
    }

    function _addRelayer(address relayer) internal {
        require(relayer != address(0), "Invalid relayer address");
        require(!whitelistedRelayers[relayer], "Relayer already whitelisted");

        whitelistedRelayers[relayer] = true;
        relayerAddresses.push(relayer);

        emit RelayerAdded(relayer);
    }

    // =============================================
    // ========== Asset Management =================
    // =============================================

    function withdrawETH(address payable to, uint256 amount) external onlyOwner notRevoked {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH balance");

        to.transfer(amount);
    }

    function withdrawERC20(
        address token,
        address to,
        uint256 amount
    ) external onlyOwner notRevoked {
        require(token != address(0) && to != address(0), "Invalid address");

        IERC20 erc20 = IERC20(token);
        require(erc20.balanceOf(address(this)) >= amount, "Insufficient token balance");
        require(erc20.transfer(to, amount), "Token transfer failed");

        emit TokenWithdrawn(token, to, amount);
    }

    // =============================================
    // =========== View Functions ==================
    // =============================================

    function canExecuteOperation(uint256 requiredValue, uint256 gasFee) external view returns (bool) {
        return address(this).balance >= (requiredValue + gasFee + minGasBalance);
    }

    function getNonce() external view returns (uint256) {
        return _nonce;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function getTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    function getAllRelayers() external view returns (address[] memory) {
        return relayerAddresses;
    }

    function isRelayer(address relayer) external view returns (bool) {
        return whitelistedRelayers[relayer];
    }
}