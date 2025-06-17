// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract MetaTxERC20Manager is EIP712 {
    using ECDSA for bytes32;

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
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // 'deadline' di sini hanya digunakan secara internal untuk tujuan dokumentasi atau jika diperlukan logika lain.
        // TIDAK TERMASUK dalam pesan yang ditandatangani.
        uint256 internalDeadlineForLogging = block.timestamp + 1 days; 

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    // Hapus 'deadline' dari tipe dan encode
                    keccak256("RevokeAllowance(address token,address owner,address spender)"), // Perhatikan perubahan di sini!
                    token,
                    owner,
                    spender
                    // Hapus 'deadline' dari argumen abi.encode
                )
            )
        );

        address recoveredSigner = digest.recover(v, r, s);
        require(recoveredSigner == owner, "INVALID_SIGNER");
        
        // Tidak ada validasi deadline di sini, sesuai permintaan Anda.
        // Tanda tangan ini berlaku "selamanya" untuk tujuan pemulihan.

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

