// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

contract SmartWalletV3 is Initializable, OwnableUpgradeable, EIP712Upgradeable {
    string public constant WALLET_NAME = "SmartWallet";
    string public constant WALLET_VERSION = "3.0";
    
    bytes32 private constant _TRANSACTION_TYPEHASH =
        keccak256("Transaction(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)");
    uint256 private _nonce;

    address public mainWallet;
    address public factory;
    bool public isRevoked;

    // Events
    event FundsReceived(address indexed sender, uint256 value);
    event ExecutedTransaction(address indexed to, uint256 value, bytes data);
    event TokenWithdrawn(address indexed token, address indexed to, uint256 amount);
    event AuthorizationRevoked(address indexed revoker);

    // Modifiers
    modifier onlyMainWallet() {
        require(msg.sender == mainWallet, "Caller is not main wallet");
        _;
    }

    modifier notRevoked() {
        require(!isRevoked, "Authorization has been revoked");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _mainWallet) public initializer {
        require(_mainWallet != address(0), "Invalid main wallet");
        __Ownable_init(_mainWallet);
        __EIP712_init(WALLET_NAME, WALLET_VERSION);
        mainWallet = _mainWallet;
        factory = msg.sender;
        isRevoked = false;
    }

    // Receive ETH function
    receive() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }

    // Function to execute transactions
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes memory signature
    ) external notRevoked returns (bytes memory) {
        require(to != address(0), "Invalid recipient");
        require(block.timestamp <= deadline, "Signature expired");

        // Estimate gas used
        uint256 gasBefore = gasleft();
        bytes32 structHash = keccak256(
            abi.encode(
                _TRANSACTION_TYPEHASH,
                to,
                value,
                keccak256(data),
                _nonce,
                deadline
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSAUpgradeable.recover(hash, signature);
        require(signer == mainWallet, "Invalid signature");

        _nonce++;

        // Execute transaction
        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "Execution failed");

        // Calculate gas used and gas fee
        uint256 gasUsed = gasBefore - gasleft();
        uint256 gasFee = gasUsed * tx.gasprice; // Gas fee to be paid

        // Ensure wallet has sufficient balance to cover gas fee
        require(address(this).balance >= gasFee, "Insufficient balance for gas fee");

        emit ExecutedTransaction(to, value, data);
        return result;
    }

    // Function to revoke authorization
    function revokeAuthorization(bytes memory signature) external onlyMainWallet {
        // Verify the revocation signature
        bytes32 structHash = keccak256(
            abi.encodePacked("RevokeAuthorization(address mainWallet,uint256 nonce)", mainWallet, _nonce)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSAUpgradeable.recover(hash, signature);
        require(signer == mainWallet, "Invalid signature");

        isRevoked = true;
        emit AuthorizationRevoked(mainWallet);
    }

    // Function to withdraw ETH
    function withdrawETH(address payable to, uint256 amount) external onlyMainWallet notRevoked {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH balance");
        to.transfer(amount);
    }

    // Function to withdraw ERC20 tokens
    function withdrawERC20(address token, address to, uint256 amount) external onlyMainWallet notRevoked {
        require(token != address(0) && to != address(0), "Invalid address");
        IERC20 erc20 = IERC20(token);
        require(erc20.balanceOf(address(this)) >= amount, "Insufficient token balance");
        require(erc20.transfer(to, amount), "Token transfer failed");

        emit TokenWithdrawn(token, to, amount);
    }

    // View functions
    function getNonce() external view returns (uint256) {
        return _nonce;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function getTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }
}