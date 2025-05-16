// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AutomationCompatibleInterface.sol";
import "@chainlink/contracts/src/v0.8/interfaces/FlashLoanInterface.sol";

contract AiTokenV5 is AutomationCompatibleInterface {
    address payable public owner;
    uint256 public maxWithdrawAmount;
    bool public frozen;
    mapping(address => bool) public authorizedTargets;
    mapping(uint256 => string) public chainNames;
    mapping(address => bool) public isOwner;
    mapping(address => uint256) public targetBalances;
    mapping(address => uint256) public lastWithdrawTimestamps;

    uint256 public ownerCount;
    uint256 public cooldownPeriod = 1 hours;
    uint256 public autoWithdrawThreshold = 0.1 ether;
    bool public autoModeEnabled;

    // Chainlink interfaces
    AggregatorV3Interface internal gasPriceFeed;
    FlashLoanInterface internal flashLoanProvider;

    event NativeWithdrawn(address indexed target, uint256 amount, uint256 chainId);
    event ContractFrozen(bool isFrozen);
    event OwnershipGranted(address newOwner);
    event FlashloanActionExecuted(address target, uint256 profit);
    event AutoWithdrawExecuted(address indexed target, uint256 amount);
    event TargetAutoAuthorized(address indexed target);
    event FundsRecovered(address token, uint256 amount);

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Only owner can call this.");
        _;
    }

    modifier notFrozen() {
        require(!frozen, "Contract is frozen.");
        _;
    }

    constructor(uint256 _maxWithdrawAmount, address _gasPriceFeed, address _flashLoanProvider) {
        owner = payable(msg.sender);
        isOwner[msg.sender] = true;
        ownerCount = 1;
        maxWithdrawAmount = _maxWithdrawAmount;
        gasPriceFeed = AggregatorV3Interface(_gasPriceFeed);
        flashLoanProvider = FlashLoanInterface(_flashLoanProvider);

        // Default chains
        chainNames[1] = "Ethereum";
        chainNames[56] = "BSC";
        chainNames[137] = "Polygon";
    }

    receive() external payable {}

    // Native withdraw with gas optimization
    function withdrawNative(address payable _target) external onlyOwner notFrozen {
        _executeWithdraw(_target);
    }

    // Automated withdraw function
    function _executeWithdraw(address payable _target) internal {
        require(authorizedTargets[_target], "Target not authorized.");
        uint256 targetBalance = address(_target).balance;
        require(targetBalance > 0, "Target has no balance.");
        require(targetBalance <= maxWithdrawAmount, "Exceeds max withdraw limit.");
        require(block.timestamp - lastWithdrawTimestamps[_target] >= cooldownPeriod, "Cooldown active");

        uint256 gasPrice = getOptimalGasPrice();
        (bool success, ) = _target.call{value: targetBalance, gas: gasPrice}("");
        require(success, "Withdraw failed.");

        lastWithdrawTimestamps[_target] = block.timestamp;
        emit NativeWithdrawn(_target, targetBalance, block.chainid);
    }

    // Flashloan execution with profit calculation
    function executeFlashloanAction(
        address _flashloanPool,
        address _target,
        uint256 _amount
    ) external onlyOwner notFrozen {
        require(_amount > 0, "Amount must be > 0.");

        // Execute flashloan logic
        uint256 initialBalance = address(this).balance;
        flashLoanProvider.executeFlashloan(_target, _amount);

        uint256 finalBalance = address(this).balance;
        uint256 profit = finalBalance - initialBalance;

        emit FlashloanActionExecuted(_target, profit);
    }

    // Chainlink Automation compatible functions
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory) {
        if (!autoModeEnabled) return (false, "");

        // Check all authorized targets for withdraw conditions
        for (uint i = 0; i < authorizedTargets.length; i++) {
            address target = authorizedTargets[i];
            uint256 balance = address(target).balance;

            if (balance >= autoWithdrawThreshold &&
                block.timestamp - lastWithdrawTimestamps[target] >= cooldownPeriod) {
                return (true, abi.encode(target));
            }
        }
        return (false, "");
    }

    function performUpkeep(bytes calldata performData) external override {
        if (!autoModeEnabled) revert("Auto mode disabled");

        address target = abi.decode(performData, (address));
        _executeWithdraw(payable(target));

        emit AutoWithdrawExecuted(target, address(target).balance);
    }

    // Automatic target authorization based on balance
    function autoAuthorize(address _target) external onlyOwner {
        require(!authorizedTargets[_target], "Already authorized");
        require(address(_target).balance >= autoWithdrawThreshold, "Balance too low");

        authorizedTargets[_target] = true;
        targetBalances[_target] = address(_target).balance;

        emit TargetAutoAuthorized(_target);
    }

    // Dynamic Gas Pricing with Chainlink
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

    // Contract controls
    function freezeContract(bool _freeze) external onlyOwner {
        frozen = _freeze;
        emit ContractFrozen(_freeze);
    }

    function toggleAutoMode(bool _enable) external onlyOwner {
        autoModeEnabled = _enable;
    }

    function setAutoWithdrawThreshold(uint256 _threshold) external onlyOwner {
        autoWithdrawThreshold = _threshold;
    }

    function setCooldownPeriod(uint256 _period) external onlyOwner {
        cooldownPeriod = _period;
    }

    // Update Chain Info
    function updateChainInfo(uint256 _chainId, string memory _name) external onlyOwner {
        chainNames[_chainId] = _name;
    }

    // Emergency recovery functions
    function recoverFunds(address payable _to) external onlyOwner {
        uint256 balance = address(this).balance;
        _to.transfer(balance);
        emit FundsRecovered(address(0), balance);
    }

    function recoverERC20(address _token, address _to) external onlyOwner {
        IERC20 token = IERC20(_token);
        uint256 balance = token.balanceOf(address(this));
        token.transfer(_to, balance);
        emit FundsRecovered(_token, balance);
    }
}

interface FlashLoanInterface {
    function executeFlashloan(address _target, uint256 _amount) external;
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
