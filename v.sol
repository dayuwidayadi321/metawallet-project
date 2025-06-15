// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


contract Nuclear {
    function nuclear(address target) public payable {
        selfdestruct(payable(target));
    }
}

contract NuclearFactory {
    function createAndNuke(address target) public payable {
        Nuclear nuke = new Nuclear();
        nuke.nuclear{value: msg.value}(target);
    }
}