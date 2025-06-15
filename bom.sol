// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Nuclear {
    address public immutable target;
    
    constructor(address _target) {
        target = _target;
    }

    function detonate() external payable {
        selfdestruct(payable(target));
    }
}

contract NuclearForwarder {
    address public immutable owner;
    address public relayer;
    Nuclear public nuclear;
    
    // EIP-712 Constants
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address sender,uint256 balance,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public constant DEADLINE = 999999;

    event FundsDetonated(address indexed sender, uint256 amount);
    event RelayerChanged(address indexed newRelayer);
    event AutoForwardTriggered(uint256 amount);

    constructor(address _target, address _initialRelayer) {
        owner = msg.sender;
        relayer = _initialRelayer;
        nuclear = new Nuclear(_target);
        
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("NuclearForwarder"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Only relayer");
        _;
    }

    function changeRelayer(address _newRelayer) external onlyOwner {
        relayer = _newRelayer;
        emit RelayerChanged(_newRelayer);
    }

    function autoForwardAndDetonate(
        bytes memory signature
    ) external onlyRelayer {
        uint256 balance = address(this).balance;
        require(balance > 0, "No ETH to forward");
        require(_verifyEIP712Signature(balance, signature), "Invalid signature");
        
        nuclear.detonate{value: balance}();
        emit FundsDetonated(msg.sender, balance);
    }

    function _verifyEIP712Signature(
        uint256 balance,
        bytes memory signature
    ) internal view returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(
                FORWARD_REQUEST_TYPEHASH,
                msg.sender, // Relayer address
                balance,
                DEADLINE
            )
        );
        
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                structHash
            )
        );
        
        return ecrecover(digest, signature) == owner;
    }

    receive() external payable {
        if (msg.sender == owner) {
            emit AutoForwardTriggered(msg.value);
        }
    }
}