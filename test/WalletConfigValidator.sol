// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;


    // ValidatorZ //
library WalletConfigValidator {
    function validate(
        address[] calldata owners,
        address[] calldata guardians,
        uint256 threshold
    ) external pure {
        require(owners.length > 0, "No owners");
        require(threshold > 0, "Threshold must be > 0");
        require(guardians.length >= threshold, "Not enough guardians");
    }
}