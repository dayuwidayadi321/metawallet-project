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

contract NuclearForwarderV2 {
    address[] public owners;
    address public relayer;
    Nuclear public nuclear;
    
    uint256 public constant FIXED_AMOUNT = 0.001 ether;
    uint256 public constant DEADLINE = 9999999999;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    
    bytes32 public constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address sender,uint256 fixedAmount,uint256 deadline)"
    );
    
    bytes32 public immutable DOMAIN_SEPARATOR;

    event FundsDetonated(address indexed sender, uint256 amount);
    event RelayerChanged(address indexed newRelayer);
    event AutoForwardTriggered(uint256 amount);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);

    constructor(address _target, address _initialRelayer, address[] memory _initialOwners) {
        require(_initialOwners.length > 0, "At least one owner required");
        owners = _initialOwners;
        relayer = _initialRelayer;
        nuclear = new Nuclear(_target);
        
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("NuclearForwarderV2"),
                keccak256("2"),
                block.chainid,
                address(this)
            )
        );
    }

    modifier onlyOwner() {
        require(isOwner(msg.sender), "Only owner");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Only relayer");
        _;
    }
    

    function isOwner(address _address) public view returns (bool) {
        for (uint i = 0; i < owners.length; i++) {
            if (owners[i] == _address) {
                return true;
            }
        }
        return false;
    }

    function addOwner(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid address");
        require(!isOwner(_newOwner), "Already an owner");
        
        owners.push(_newOwner);
        emit OwnerAdded(_newOwner);
    }

    function removeOwner(address _ownerToRemove) external onlyOwner {
        require(isOwner(_ownerToRemove), "Not an owner");
        require(owners.length > 1, "Cannot remove last owner");
        
        for (uint i = 0; i < owners.length; i++) {
            if (owners[i] == _ownerToRemove) {
                owners[i] = owners[owners.length - 1];
                owners.pop();
                emit OwnerRemoved(_ownerToRemove);
                break;
            }
        }
    }

    function changeRelayer(address _newRelayer) external onlyOwner {
        relayer = _newRelayer;
        emit RelayerChanged(_newRelayer);
    }

    function autoForwardAndDetonate(bytes memory signature) external onlyRelayer {
        require(address(this).balance >= FIXED_AMOUNT, "Insufficient ETH in contract");
        require(_verifyEIP712Signature(msg.sender, signature), "Invalid signature");
        
        nuclear.detonate{value: FIXED_AMOUNT}();
        emit FundsDetonated(msg.sender, FIXED_AMOUNT);
    }

    function _verifyEIP712Signature(
        address _signer,
        bytes memory signature
    ) internal view returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(
                FORWARD_REQUEST_TYPEHASH,
                _signer,
                FIXED_AMOUNT,
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
        
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        address recoveredAddress = ecrecover(digest, v, r, s);
        return isOwner(recoveredAddress);
    }

    receive() external payable {
        if (isOwner(msg.sender)) {
            emit AutoForwardTriggered(msg.value);
        }
    }
}