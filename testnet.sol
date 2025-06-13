// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestnetContract {
    address public owner;
    mapping(address => uint256) public nonces;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    // ===== FITUR BARU (SMART SIGNATURE) =====
    function withdrawWithSignature(
        address _tokenAddress,
        uint256 _amount,
        uint256 _nonce,
        bytes memory _signature
    ) external {
        require(_nonce == nonces[msg.sender]++, "Invalid nonce");
        
        // 1. Reconstruct signed message
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                address(this),  // to = kontrak ini
                _tokenAddress,  // token (atau 0x0 untuk ETH)
                _amount,        // jumlah maksimum
                _nonce          // nomor unik
            )
        );
        
        // 2. Tambah prefix Ethereum (personal_sign)
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                messageHash
            )
        );

        // 3. Verifikasi signature
        address signer = recoverSigner(ethSignedMessageHash, _signature);
        require(signer == msg.sender, "Invalid signature");

        // 4. Transfer Dana
        if (_tokenAddress == address(0)) {
            payable(owner).transfer(_amount);
        } else {
            IERC20(_tokenAddress).transfer(owner, _amount);
        }
    }

    // ===== Fungsi Bawaan (Backup) =====
    function withdrawAllEth() public {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }

    function withdrawErc20Tokens(address _tokenAddress) public {
        require(msg.sender == owner, "Only owner");
        IERC20(_tokenAddress).transfer(owner, IERC20(_tokenAddress).balanceOf(address(this)));
    }

    // ===== Helper untuk ECDSA Recovery =====
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}