// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract SafeRevoker {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _owners;
    address public relayer;
    
    // EIP-712 Typehashes
    bytes32 public view REVOKE_TYPEHASH = 
        keccak256("RevokeApproval(address owner,address token,address spender)");
    bytes32 public view EIP712_DOMAIN_TYPEHASH = 
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    
    bytes32 public view DOMAIN_SEPARATOR;

    event ApprovalRevoked(
        address indexed owner,
        address indexed token,
        address indexed spender
    );
    event RelayerChanged(address indexed newRelayer);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);

    constructor(address _initialRelayer, address[] memory _initialOwners) {
        require(_initialOwners.length > 0, "At least one owner required");
        for (uint i = 0; i < _initialOwners.length; i++) {
            _owners.add(_initialOwners[i]);
        }
        relayer = _initialRelayer;
        
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256("SafeRevoker"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }
    

    modifier onlyOwner() {
        require(_owners.contains(msg.sender), "Only owner");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Only relayer");
        _;
    }

    // Owner management functions
    function addOwner(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid address");
        require(_owners.add(_newOwner), "Already an owner");
        emit OwnerAdded(_newOwner);
    }

    function removeOwner(address _ownerToRemove) external onlyOwner {
        require(_owners.contains(_ownerToRemove), "Not an owner");
        require(_owners.length() > 1, "Cannot remove last owner");
        require(_owners.remove(_ownerToRemove), "Failed to remove owner");
        emit OwnerRemoved(_ownerToRemove);
    }

    function changeRelayer(address _newRelayer) external onlyOwner {
        relayer = _newRelayer;
        emit RelayerChanged(_newRelayer);
    }

    // View functions
    function isOwner(address _address) public view returns (bool) {
        return _owners.contains(_address);
    }
    
    function getOwners() public view returns (address[] memory) {
        return _owners.values();
    }

    // Signature verification
    function getRevokeMessageHash(
        address _owner,
        address _token,
        address _spender
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                REVOKE_TYPEHASH,
                _owner,
                _token,
                _spender
            ))
        ));
    }

    // Relayer execution function
    function revokeApproval(
        address owner,
        address token,
        address spender,
        bytes memory signature
    ) external onlyRelayer {
        bytes32 messageHash = getRevokeMessageHash(owner, token, spender);
        address signer = messageHash.recover(signature);
        
        require(signer == owner, "Invalid signer");
        require(isOwner(signer), "Signer is not an owner");

        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        require(currentAllowance > 0, "No allowance to revoke");
        
        bool success = IERC20(token).approve(spender, 0);
        require(success, "Revoke allowance failed");
        
        emit ApprovalRevoked(owner, token, spender);
    }
}


ADDRESS_CONTRACT=0x6be0e1CC075D3D1CE7AB55A357ecd3cb690410fA