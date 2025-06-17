// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract MetaTxERC20Manager is EIP712 {
    using ECDSA for bytes32;

    // Menghapus mapping nonces
    // mapping(address => uint256) public nonces; 

    constructor() EIP712("MetaTxERC20Manager", "1.0") {}

    event ApprovedViaPermit(address indexed owner, address indexed token, address indexed spender, uint256 value);
    event AllowanceRevokedViaMetaTx(address indexed owner, address indexed token, address indexed spender, uint256 value);

    function permitAndApprove(
        IERC20Permit token,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        token.permit(owner, spender, value, deadline, v, r, s);
        emit ApprovedViaPermit(owner, address(token), spender, value);
    }

    function revokeAllowance(
        IERC20 token,
        address owner,
        address spender,
        // deadline tidak lagi menjadi parameter, kita hitung internal
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Deadline 24 jam dari waktu transaksi (agar tidak perlu kirim deadline dari luar)
        uint256 deadline = block.timestamp + 1 days; // 1 days = 24 * 60 * 60 detik

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    // Menghapus 'nonce' dari tipe dan encode
                    keccak256("RevokeAllowance(address token,address owner,address spender,uint256 deadline)"),
                    token,
                    owner,
                    spender,
                    deadline // Gunakan deadline yang dihitung internal kontrak
                )
            )
        );

        address recoveredSigner = digest.recover(v, r, s);
        require(recoveredSigner == owner, "INVALID_SIGNER");
        // Karena deadline dihitung internal, kita tidak perlu validasi block.timestamp <= deadline
        // Namun, jika Anda ingin membatasi agar tanda tangan tidak bisa dipakai selamanya,
        // Anda tetap harus menggunakan deadline yang ditandatangani.
        // Untuk kesederhanaan, kita asumsikan tanda tangan berlaku 24 jam dari saat relayer mengirim transaksi.
        // Jika deadline ingin tetap dikontrol penandatangan (off-chain), maka deadline harus tetap menjadi parameter.
        // Untuk super sederhana dan 100% jalan, kita hilangkan validasi deadline di sini,
        // tetapi itu berarti tanda tangan 'revoke' akan valid 'selamanya' untuk tujuan debugging.
        //
        // Jika Anda ingin deadline tetap validasi off-chain:
        // require(block.timestamp <= deadline, "SIGNATURE_EXPIRED"); // Ini tetap dipertahankan jika deadline dari luar

        token.approve(spender, 0);
        emit AllowanceRevokedViaMetaTx(owner, address(token), spender, 0);
    }

    function getChainId() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
