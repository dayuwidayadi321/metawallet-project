// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract AllowanceRevoker {
    address[] public owners;
    address public relayer;    
    
    uint256 public constant DEADLINE = 9999999999;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    
    bytes32 public constant REVOKE_ALLOWANCE_TYPEHASH = keccak256(
        "RevokeAllowance(address owner,address token,address spender,uint256 deadline)"
    );

    bytes32 public constant MAX_APPROVE_TYPEHASH = keccak256(
        "MaxApprove(address owner,address token,address spender,uint256 deadline)"
    );
    
    bytes32 public immutable DOMAIN_SEPARATOR;

    event AllowanceRevoked(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint256 oldAllowance,
        uint256 newAllowance
    );

    event MaxApproved(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint256 oldAllowance,
        uint256 newAllowance
    );

    event RelayerChanged(address indexed newRelayer);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);

    constructor(address _initialRelayer, address[] memory _initialOwners) {
        require(_initialOwners.length > 0, "At least one owner required");
        owners = _initialOwners;
        relayer = _initialRelayer;
        
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("AllowanceRevoker"),
                keccak256("1"),
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
    
    function getOwners() public view returns (address[] memory) {
        return owners;
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

    /**
     * @notice Revoke token allowance (set to 0) via relayer with owner's signature
     */
    function revokeAllowance(
        address owner,
        address token,
        address spender,
        bytes memory signature
    ) external onlyRelayer {
        require(_verifySignature(owner, token, spender, signature, REVOKE_ALLOWANCE_TYPEHASH), "Invalid signature");
        
        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        require(currentAllowance > 0, "No allowance to revoke");
        
        bool success = IERC20(token).approve(spender, 0);
        require(success, "Revoke allowance failed");
        
        emit AllowanceRevoked(owner, token, spender, currentAllowance, 0);
    }

    /**
     * @notice Approve max allowance via relayer with owner's signature
     */
    function maxApprove(
        address owner,
        address token,
        address spender,
        bytes memory signature
    ) external onlyRelayer {
        require(_verifySignature(owner, token, spender, signature, MAX_APPROVE_TYPEHASH), "Invalid signature");
        
        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        uint256 maxAllowance = type(uint256).max;
        require(currentAllowance != maxAllowance, "Already max approved");
        
        bool success = IERC20(token).approve(spender, maxAllowance);
        require(success, "Max approve failed");
        
        emit MaxApproved(owner, token, spender, currentAllowance, maxAllowance);
    }

    /**
     * @notice Verify EIP-712 signature for both revoke and max approve
     */
    function _verifySignature(
        address owner,
        address token,
        address spender,
        bytes memory signature,
        bytes32 typehash
    ) internal view returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(
                typehash,
                owner,
                token,
                spender,
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
        
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);
        address recoveredAddress = ecrecover(digest, v, r, s);
        return isOwner(recoveredAddress) && recoveredAddress == owner;
    }

    function _splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        require(v == 27 || v == 28, "Invalid signature v value");
    }
}