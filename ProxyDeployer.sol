// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract ProxyDeployer {
    function deployProxy(
        address logic,
        address admin,
        bytes memory data
    ) external returns (address) {
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            logic,
            admin,
            data
        );
        return address(proxy);
    }
}
