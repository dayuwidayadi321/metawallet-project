// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SmartWalletV4 is Ownable, EIP712 {
    // =============================================
    // ============== Constants ====================
    // =============================================
    string public constant WALLET_NAME = "SmartWallet";
    string public constant WALLET_VERSION = "4.0";
    
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
    event ExecutedTransaction(
        address indexed to, 
        uint256 value, 
        bytes data,
        uint256 gasFee
    );
    event TokenWithdrawn(address indexed token, address indexed to, uint256 amount);
    event AuthorizationRevoked(address indexed revoker, uint256 gasFee);
    event GasFeePaid(address indexed relayer, uint256 amount);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);

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
    constructor(uint256 _minGasBalance) EIP712(WALLET_NAME, WALLET_VERSION) {
        minGasBalance = _minGasBalance;
        // Automatically whitelist the deployer as initial relayer
        _addRelayer(msg.sender);
    }

    // =============================================
    // ========== External Functions ===============
    // =============================================

    /// @notice Receive ETH
    receive() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }

    /// @notice Execute transaction with gas fee payment (whitelisted relayer only)
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 gasFee,
        bytes memory signature
    ) external onlyWhitelistedRelayer notRevoked ensureGasFunds returns (bytes memory) {
        require(to != address(0), "Invalid recipient");

        // Verify signature
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

        // Execute transaction
        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "Execution failed");

        // Pay gas fee to relayer
        if (gasFee > 0) {
            payable(msg.sender).transfer(gasFee);
            emit GasFeePaid(msg.sender, gasFee);
        }

        emit ExecutedTransaction(to, value, data, gasFee);
        return result;
    }

    /// @notice Revoke wallet authorization with gas fee (whitelisted relayer only)
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
        
        // Pay gas fee to relayer
        if (gasFee > 0) {
            payable(msg.sender).transfer(gasFee);
            emit GasFeePaid(msg.sender, gasFee);
        }

        emit AuthorizationRevoked(owner(), gasFee);
    }

    // =============================================
    // ========== Relayer Management ===============
    // =============================================

    /// @notice Add a new relayer to the whitelist
    function addRelayer(address relayer) external onlyOwner {
        _addRelayer(relayer);
    }

    /// @notice Remove a relayer from the whitelist
    function removeRelayer(address relayer) external onlyOwner {
        require(whitelistedRelayers[relayer], "Address is not a relayer");
        
        whitelistedRelayers[relayer] = false;
        
        // Remove from relayerAddresses array
        for (uint256 i = 0; i < relayerAddresses.length; i++) {
            if (relayerAddresses[i] == relayer) {
                relayerAddresses[i] = relayerAddresses[relayerAddresses.length - 1];
                relayerAddresses.pop();
                break;
            }
        }
        
        emit RelayerRemoved(relayer);
    }

    /// @notice Internal function to add a relayer
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

    /// @notice Withdraw ETH from the wallet
    function withdrawETH(address payable to, uint256 amount) external onlyOwner notRevoked {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH balance");
        
        to.transfer(amount);
    }

    /// @notice Withdraw ERC20 tokens from the wallet
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

    /// @notice Check if wallet has sufficient funds for operation
    function canExecuteOperation(
        uint256 requiredValue,
        uint256 gasFee
    ) external view returns (bool) {
        return address(this).balance >= (requiredValue + gasFee + minGasBalance);
    }

    /// @notice Get current nonce
    function getNonce() external view returns (uint256) {
        return _nonce;
    }

    /// @notice Get ETH balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Get ERC20 token balance
    function getTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /// @notice Get all whitelisted relayers
    function getAllRelayers() external view returns (address[] memory) {
        return relayerAddresses;
    }

    /// @notice Check if address is whitelisted relayer
    function isRelayer(address relayer) external view returns (bool) {
        return whitelistedRelayers[relayer];
    }
}