// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ========== IMPORTS ==========
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

// ========== CONTRACT ==========
contract SmartWalletV2 is Initializable, OwnableUpgradeable, EIP712Upgradeable {
    // ========== CONSTANTS ==========
    string public constant WALLET_NAME = "SmartWallet";
    string public constant WALLET_VERSION = "3.0";
    bytes32 private constant _TRANSACTION_TYPEHASH = 
        keccak256("Transaction(address to,uint256 value,bytes data,uint256 nonce)");

    // ========== STORAGE ==========
    uint256 private _nonce;
    address public mainWallet;
    address public factory;

    // ========== EVENTS ==========
    event FundsReceived(address indexed sender, uint256 value);
    event ExecutedTransaction(address indexed to, uint256 value, bytes data);
    event TokenWithdrawn(address indexed token, address indexed to, uint256 amount);

    // ========== MODIFIERS ==========
    modifier onlyMainWallet() {
        require(msg.sender == mainWallet, "Caller is not main wallet");
        _;
    }

    // ========== CONSTRUCTOR ==========
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ========== INITIALIZER ==========
    function initialize(address _mainWallet) public initializer {
        require(_mainWallet != address(0), "Invalid main wallet");
        __Ownable_init(_mainWallet);
        __EIP712_init(WALLET_NAME, WALLET_VERSION);
        mainWallet = _mainWallet;
        factory = msg.sender;
    }

    // ========== RECEIVE ==========
    receive() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }

    // ========== EXECUTE TRANSACTION ==========
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        bytes memory signature
    ) external returns (bytes memory) {
        require(to != address(0), "Invalid recipient");

        bytes32 structHash = keccak256(
            abi.encode(_TRANSACTION_TYPEHASH, to, value, keccak256(data), _nonce)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSAUpgradeable.recover(hash, signature);
        require(signer == mainWallet, "Invalid signature");

        _nonce++;

        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "Execution failed");

        emit ExecutedTransaction(to, value, data);
        return result;
    }

    // ========== WITHDRAW FUNCTIONS ==========
    function withdrawETH(address payable to, uint256 amount) external onlyMainWallet {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH balance");
        to.transfer(amount);
    }

    function withdrawERC20(address token, address to, uint256 amount) external onlyMainWallet {
        require(token != address(0) && to != address(0), "Invalid address");
        IERC20 erc20 = IERC20(token);
        require(erc20.balanceOf(address(this)) >= amount, "Insufficient token balance");
        require(erc20.transfer(to, amount), "Token transfer failed");

        emit TokenWithdrawn(token, to, amount);
    }

    // ========== VIEW FUNCTIONS ==========
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