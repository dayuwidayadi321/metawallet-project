// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SmartBNBStaking is Ownable, ReentrancyGuard {
    IERC20 public stakingToken;
    uint256 public totalStaked;
    uint256 public totalRewardsDistributed;
    uint256 public constant MIN_STAKE = 0.01 ether;
    uint256 public constant MAX_STAKE = 100 ether;
    uint256 public constant WITHDRAWAL_FEE = 1; // 0.01%
    uint256 public constant FEE_DIVISOR = 10000;
    uint256 public APY = 1500; // 15% default APY (1500 = 15%)
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    uint256 public constant REWARD_INTERVAL = 1 days;

    struct Staker {
        uint256 balance;
        uint256 rewards;
        uint256 rewardPerTokenPaid;
        uint256 lastStakedTime;
    }

    mapping(address => Staker) public stakers;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    event APYUpdated(uint256 newAPY);

    constructor(address _stakingToken) {
        stakingToken = IERC20(_stakingToken);
        lastUpdateTime = block.timestamp;
    }

    function updateReward(address account) internal {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        
        if (account != address(0)) {
            stakers[account].rewards = earned(account);
            stakers[account].rewardPerTokenPaid = rewardPerTokenStored;
        }
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        uint256 timeElapsed = block.timestamp - lastUpdateTime;
        uint256 additionalReward = (timeElapsed * APY * 1e18) / (365 days * FEE_DIVISOR);
        return rewardPerTokenStored + additionalReward;
    }

    function earned(address account) public view returns (uint256) {
        Staker memory staker = stakers[account];
        uint256 currentRewardPerToken = rewardPerToken();
        uint256 rewardDifference = currentRewardPerToken - staker.rewardPerTokenPaid;
        uint256 newlyEarned = (staker.balance * rewardDifference) / 1e18;
        return staker.rewards + newlyEarned;
    }

    function stake(uint256 amount) external nonReentrant {
        require(amount >= MIN_STAKE, "Amount too low");
        require(amount <= MAX_STAKE, "Amount exceeds max stake");
        require(stakingToken.balanceOf(msg.sender) >= amount, "Insufficient balance");

        updateReward(msg.sender);
        
        stakingToken.transferFrom(msg.sender, address(this), amount);
        stakers[msg.sender].balance += amount;
        stakers[msg.sender].lastStakedTime = block.timestamp;
        totalStaked += amount;

        emit Staked(msg.sender, amount);
    }

    function claimReward() external nonReentrant {
        updateReward(msg.sender);
        uint256 reward = stakers[msg.sender].rewards;
        if (reward > 0) {
            stakers[msg.sender].rewards = 0;
            totalRewardsDistributed += reward;
            
            // Auto-compound 50% of rewards
            uint256 compoundAmount = reward / 2;
            uint256 claimAmount = reward - compoundAmount;
            
            stakers[msg.sender].balance += compoundAmount;
            totalStaked += compoundAmount;
            
            stakingToken.transfer(msg.sender, claimAmount);
            emit RewardPaid(msg.sender, claimAmount);
            emit Staked(msg.sender, compoundAmount);
        }
    }

    function withdraw(uint256 amount) external nonReentrant {
        Staker storage staker = stakers[msg.sender];
        require(staker.balance >= amount, "Insufficient staked balance");
        
        updateReward(msg.sender);
        
        uint256 fee = (amount * WITHDRAWAL_FEE) / FEE_DIVISOR;
        uint256 amountAfterFee = amount - fee;
        
        staker.balance -= amount;
        totalStaked -= amount;
        
        stakingToken.transfer(msg.sender, amountAfterFee);
        emit Withdrawn(msg.sender, amountAfterFee);
    }

    function exit() external nonReentrant {
        withdraw(stakers[msg.sender].balance);
        claimReward();
    }

    function setAPY(uint256 _newAPY) external onlyOwner {
        require(_newAPY >= 1000 && _newAPY <= 2000, "APY must be between 10% and 20%");
        updateReward(address(0));
        APY = _newAPY;
        emit APYUpdated(_newAPY);
    }

    function recoverTokens(address tokenAddress, uint256 amount) external onlyOwner {
        IERC20(tokenAddress).transfer(owner(), amount);
    }

    function getStakeInfo(address account) external view returns (
        uint256 stakedAmount,
        uint256 pendingRewards,
        uint256 apy,
        uint256 lastStakedTime
    ) {
        Staker memory staker = stakers[account];
        return (
            staker.balance,
            earned(account),
            APY,
            staker.lastStakedTime
        );
    }
}