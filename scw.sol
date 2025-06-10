// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract MiniBitcoin is ERC20, Ownable {
    using SafeMath for uint256;

    address private constant BURN_ADDRESS = 0x0000000000000000000000000000000000000000;
    uint256 private constant _FEE_BASIS_POINTS = 1; // 0.01%

    string private _tokenIconUri; // Variabel untuk menyimpan URI ikon token

    event TokenIconUriUpdated(string newUri); // Event untuk memberi tahu saat URI ikon diperbarui

    constructor() ERC20("Mini Bitcoin", "mBTC") {
        uint256 initialSupply = 21000000 * (10**18);
        _mint(msg.sender, initialSupply);
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual override {
        if (sender != BURN_ADDRESS && amount > 0) {
            uint256 feeAmount = amount.mul(_FEE_BASIS_POINTS).div(10000);
            uint256 amountAfterFee = amount.sub(feeAmount);

            super._transfer(sender, recipient, amountAfterFee);

            if (feeAmount > 0) {
                super._transfer(sender, BURN_ADDRESS, feeAmount);
            }
        } else {
            super._transfer(sender, recipient, amount);
        }
    }

    // Fungsi untuk mendapatkan URI ikon token
    function tokenIconUri() public view returns (string memory) {
        return _tokenIconUri;
    }

    // Fungsi untuk mengatur atau mengubah URI ikon token
    // Hanya pemilik kontrak yang bisa memanggil fungsi ini
    function setTokenIconUri(string memory uri_) public onlyOwner {
        _tokenIconUri = uri_;
        emit TokenIconUriUpdated(uri_);
    }
}
