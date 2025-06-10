// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract MiniBitcoin is ERC20, Ownable {
    using SafeMath for uint256;

    address private constant BURN_ADDRESS = 0x0000000000000000000000000000000000000000;
    uint256 private constant _FEE_BASIS_POINTS = 1; // 0.01%

    string private _tokenIconUri;

    event TokenIconUriUpdated(string newUri);

    constructor() ERC20("Mini Bitcoin", "mBTC") Ownable(msg.sender) {
        uint256 initialSupply = 21000000 * (10**18);
        _mint(msg.sender, initialSupply);
    }

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override {
        if (from != BURN_ADDRESS && amount > 0) {
            uint256 feeAmount = amount.mul(_FEE_BASIS_POINTS).div(10000);
            uint256 amountAfterFee = amount.sub(feeAmount);

            super._update(from, to, amountAfterFee);

            if (feeAmount > 0) {
                super._update(from, BURN_ADDRESS, feeAmount);
            }
        } else {
            super._update(from, to, amount);
        }
    }

    function tokenIconUri() public view returns (string memory) {
        return _tokenIconUri;
    }

    function setTokenIconUri(string memory uri_) public onlyOwner {
        _tokenIconUri = uri_;
        emit TokenIconUriUpdated(uri_);
    }
}
