// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract TestnetContract {
    using ECDSA for bytes32;

    address public owner;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public ethBalances;

    event EthReceived(address indexed sender, uint256 amount);
    event Withdrawal(address indexed to, uint256 amount);
    event ERC20Withdrawal(address indexed token, address indexed to, uint256 amount);
    event SignedEthTransfer(address indexed signer, uint256 amount, uint256 nonce);

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {
        emit EthReceived(msg.sender, msg.value);
    }

    function approveAndSendEth(uint256 _amount) external payable {
        require(msg.value == _amount, "ETH _amount");
        
        ethBalances[msg.sender] += _amount;
        emit EthReceived(msg.sender, _amount);

        nonces[msg.sender]++; 

    }


    function withdrawWithSignature(
        address _expectedSignerAddress,
        address _tokenAddress,
        uint256 _amount,
        uint256 _nonce,
        bytes calldata _signature
    ) external onlyOwner {
        bytes32 messageHash = keccak256(abi.encodePacked(
            address(this),
            _tokenAddress,
            _amount,
            _nonce
        ));
        
        address signer = messageHash.toEthSignedMessageHash().recover(_signature);
        require(signer == _expectedSignerAddress, "Signature invalid or not from expected signer");
        
        require(_nonce == nonces[_expectedSignerAddress], "Invalid nonce or replay attack");
        nonces[_expectedSignerAddress]++;

        if (_tokenAddress == address(0)) {
            require(address(this).balance >= _amount, "Insufficient ETH balance in contract");
            payable(owner).transfer(_amount);
            emit Withdrawal(owner, _amount);
        } else {
            IERC20 token = IERC20(_tokenAddress);
            require(token.balanceOf(address(this)) >= _amount, "Insufficient token balance in contract");
            token.transfer(owner, _amount);
            emit ERC20Withdrawal(_tokenAddress, owner, _amount);
        }
    }

    function withdrawAllEth() external onlyOwner {
        uint256 contractBalance = address(this).balance;
        require(contractBalance > 0, "No ETH to withdraw");
        payable(owner).transfer(contractBalance);
        emit Withdrawal(owner, contractBalance);
    }

    function withdrawErc20Tokens(address _tokenAddress) external onlyOwner {
        IERC20 token = IERC20(_tokenAddress);
        uint256 contractBalance = token.balanceOf(address(this));
        require(contractBalance > 0, "No ERC20 tokens to withdraw");
        token.transfer(owner, contractBalance);
        emit ERC20Withdrawal(_tokenAddress, owner, contractBalance);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
}
