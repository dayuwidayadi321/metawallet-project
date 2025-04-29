// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";

contract SmartWalletV6 is Initializable, OwnableUpgradeable, EIP712Upgradeable {
    // =============================================
    // ============== Constants ====================
    // =============================================
    string public constant WALLET_NAME = "SmartWallet";
    string public constant WALLET_VERSION = "6.0";

    bytes32 private constant _TRANSACTION_TYPEHASH =
        keccak256("Transaction(address to,uint256 value,bytes data,uint256 nonce,uint256 gasFee,uint256 chainId)");
    bytes32 private constant _REVOCATION_TYPEHASH =
        keccak256("RevokeAuthorization(address wallet,uint256 nonce,uint256 gasFee,uint256 chainId)");

    // Storage slots (aman untuk proxy)
    bytes32 private constant _NONCE_SLOT = keccak256("SmartWalletV6.nonce");
    bytes32 private constant _REVOKED_SLOT = keccak256("SmartWalletV6.revoked");
    bytes32 private constant _GASBALANCE_SLOT = keccak256("SmartWalletV6.gasBalance");

    // =============================================
    // ============== State Variables ==============
    // =============================================
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
        require(!_getRevoked(), "Authorization revoked");
        _;
    }

    modifier ensureGasFunds() {
        require(address(this).balance >= _getMinGasBalance(), "Insufficient gas balance");
        _;
    }

    modifier onlyWhitelistedRelayer() {
        require(whitelistedRelayers[msg.sender], "Caller not whitelisted");
        _;
    }

    // =============================================
    // ============== Initializer ==================
    // =============================================
    function initialize(
        uint256 _minGasBalance,
        address initialOwner,
        address initialRelayer
    ) public initializer {
        __Ownable_init(initialOwner);
        __EIP712_init(WALLET_NAME, WALLET_VERSION);
        _setMinGasBalance(_minGasBalance);
        _addRelayer(initialRelayer);
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

        uint256 currentNonce = _getNonce();
        uint256 chainId = block.chainid;

        bytes32 structHash = keccak256(
            abi.encode(
                _TRANSACTION_TYPEHASH,
                to,
                value,
                keccak256(data),
                currentNonce,
                gasFee,
                chainId
            )
        );

        _verifySignature(structHash, signature);
        _setNonce(currentNonce + 1);

        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "Execution failed");

        _payGasFee(gasFee);
        emit ExecutedTransaction(to, value, data, gasFee);
        return result;
    }

    // =============================================
    // =========== Security Functions ==============
    // =============================================
    function revokeAuthorization(
        uint256 gasFee,
        bytes memory signature
    ) external onlyWhitelistedRelayer ensureGasFunds {
        uint256 currentNonce = _getNonce();
        uint256 chainId = block.chainid;

        bytes32 structHash = keccak256(
            abi.encode(
                _REVOCATION_TYPEHASH,
                address(this),
                currentNonce,
                gasFee,
                chainId
            )
        );

        _verifySignature(structHash, signature);
        _setNonce(currentNonce + 1);
        _setRevoked(true);

        _payGasFee(gasFee);
        emit AuthorizationRevoked(msg.sender, gasFee);
    }

    function restoreAuthorization() external onlyOwner {
        require(_getRevoked(), "Not revoked");
        _setRevoked(false);
        emit AuthorizationRestored(msg.sender);
    }

    // =============================================
    // ========== Storage Management ===============
    // =============================================
    function _getNonce() internal view returns (uint256) {
        return StorageSlot.getUint256Slot(_NONCE_SLOT).value;
    }

    function _setNonce(uint256 newNonce) internal {
        StorageSlot.getUint256Slot(_NONCE_SLOT).value = newNonce;
    }

    function _getRevoked() internal view returns (bool) {
        return StorageSlot.getBooleanSlot(_REVOKED_SLOT).value;
    }

    function _setRevoked(bool status) internal {
        StorageSlot.getBooleanSlot(_REVOKED_SLOT).value = status;
    }

    function _getMinGasBalance() internal view returns (uint256) {
        return StorageSlot.getUint256Slot(_GASBALANCE_SLOT).value;
    }

    function _setMinGasBalance(uint256 newBalance) internal {
        StorageSlot.getUint256Slot(_GASBALANCE_SLOT).value = newBalance;
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