// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract ProxySmartWallet is EIP712 {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // EIP712 type hashes
    bytes32 private constant DEPLOY_WALLET_TYPEHASH = 
        keccak256("DeployWallet(address owner,uint256 salt)");
    bytes32 private constant EXECUTE_TRANSACTION_TYPEHASH = 
        keccak256("ExecuteTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)");
    bytes32 private constant WITHDRAW_ALL_TYPEHASH = 
        keccak256("WithdrawAll(address from,address to,uint256 nonce,uint256 deadline)");

    address public immutable owner;
    uint256 public nonce;
    bool public initialized;

    // Mapping to track deployed sub-wallets
    mapping(address => bool) public isSubWallet;

    event SubWalletDeployed(address indexed subWallet, address indexed owner);
    event ExecutedTransaction(address indexed from, address indexed to, uint256 value, bytes data);
    event WithdrawnAll(address indexed from, address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyOwnerOrSubWallet() {
        require(msg.sender == owner || isSubWallet[msg.sender], "Not authorized");
        _;
    }

    constructor(address _owner) EIP712("ProxySmartWallet", "1") {
        owner = _owner;
    }

    // Initialize the main wallet (can only be done once)
    function initialize() external {
        require(!initialized, "Already initialized");
        initialized = true;
    }

    // Deploy a new sub-wallet with EIP712 signature
    function deploySubWallet(
        address _owner,
        uint256 _salt,
        bytes memory _signature
    ) external returns (address subWallet) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                DEPLOY_WALLET_TYPEHASH,
                _owner,
                _salt
            ))
        );

        address signer = digest.recover(_signature);
        require(signer == owner, "Invalid signature");

        bytes memory bytecode = abi.encodePacked(
            type(SubWallet).creationCode,
            abi.encode(_owner, address(this))
        );

        assembly {
            subWallet := create2(0, add(bytecode, 0x20), mload(bytecode), _salt)
        }

        isSubWallet[subWallet] = true;
        emit SubWalletDeployed(subWallet, _owner);
    }

    // Execute a transaction with EIP712 signature (can be called by sub-wallet to pay for gas)
    function executeTransaction(
        address _from,
        address _to,
        uint256 _value,
        bytes memory _data,
        uint256 _deadline,
        bytes memory _signature
    ) external onlyOwnerOrSubWallet returns (bytes memory) {
        require(block.timestamp <= _deadline, "Transaction expired");
        
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                EXECUTE_TRANSACTION_TYPEHASH,
                _from,
                _to,
                _value,
                keccak256(_data),
                nonce++,
                _deadline
            ))
        );

        address signer = digest.recover(_signature);
        require(signer == owner, "Invalid signature");

        (bool success, bytes memory result) = _to.call{value: _value}(_data);
        require(success, "Transaction failed");

        emit ExecutedTransaction(_from, _to, _value, _data);
        return result;
    }

    // Withdraw all funds from sub-wallet to main wallet with EIP712 signature
    function withdrawAll(
        address _from,
        address _to,
        uint256 _deadline,
        bytes memory _signature
    ) external onlyOwnerOrSubWallet {
        require(block.timestamp <= _deadline, "Withdrawal expired");
        
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                WITHDRAW_ALL_TYPEHASH,
                _from,
                _to,
                nonce++,
                _deadline
            ))
        );

        address signer = digest.recover(_signature);
        require(signer == owner, "Invalid signature");

        uint256 balance = address(_from).balance;
        (bool success, ) = _to.call{value: balance}("");
        require(success, "Transfer failed");

        emit WithdrawnAll(_from, _to, balance);
    }

    // Receive ETH
    receive() external payable {}
}

contract SubWallet {
    using SafeERC20 for IERC20;

    address public immutable owner;
    address public immutable mainWallet;

    constructor(address _owner, address _mainWallet) {
        owner = _owner;
        mainWallet = _mainWallet;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // Deposit ETH (can be called by anyone)
    function deposit() external payable {}

    // Withdraw ETH (only owner)
    function withdraw(uint256 amount) external onlyOwner {
        payable(owner).transfer(amount);
    }

    // Withdraw ERC20 tokens (only owner)
    function withdrawToken(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(owner, amount);
    }

    // Execute arbitrary transaction (only owner)
    function execute(address to, uint256 value, bytes calldata data) external onlyOwner returns (bytes memory) {
        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "Transaction failed");
        return result;
    }

    // Receive ETH
    receive() external payable {}
}