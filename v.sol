// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Nuclear {
    function nuclear(address target) public payable {
        selfdestruct(payable(target));
    }
}