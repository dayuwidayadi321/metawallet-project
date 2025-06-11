// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract SmartBNBStaking is Ownable, ReentrancyGuard { // Baris ini
    using SafeMath for uint256;

    IERC20 public immutable stakingToken;
    uint256 public totalStaked;
    uint256 public totalRewardsDistributed;

    uint256 public constant MIN_STAKE = 0.01 ether;
    uint256 public constant MAX_STAKE = 100 ether;

    uint256 public constant WITHDRAWAL_FEE_BPS = 10;
    uint256 public constant BASIS_POINTS_DIVISOR = 10000;

    uint256 public APY;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;

    struct Staker {
        uint256 balance;
        uint256 rewards;
        uint256 rewardPerTokenPaid;
        uint256 lastStakedTime;
    }

    mapping(address => Staker) public stakers;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 rewardAmount, uint256 compoundedAmount);
    event APYUpdated(uint256 oldAPY, uint256 newAPY);

    // Perubahan di sini: meneruskan msg.sender ke konstruktor Ownable
    constructor(address _stakingToken, uint256 _initialAPY)
        Ownable(msg.sender) // <--- Tambahkan baris ini
    {
        require(_stakingToken != address(0), "Alamat token staking tidak boleh nol");
        require(_initialAPY >= 1000 && _initialAPY <= 2000, "APY awal harus antara 10% dan 20%");
        stakingToken = IERC20(_stakingToken);
        APY = _initialAPY;
        lastUpdateTime = block.timestamp;
    }

    // ... sisa kode kontrak Anda tetap sama ...
    function _updateReward(address account) internal {
        uint256 currentRewardPerToken = _calculateRewardPerToken();
        
        rewardPerTokenStored = currentRewardPerToken;
        lastUpdateTime = block.timestamp;
        
        if (account != address(0)) {
            Staker storage staker = stakers[account];
            staker.rewards = earned(account);
            staker.rewardPerTokenPaid = currentRewardPerToken;
        }
    }

    function _calculateRewardPerToken() internal view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        uint256 timeElapsed = block.timestamp.sub(lastUpdateTime);
        uint256 additionalReward = timeElapsed.mul(APY).mul(1e18).div(365 days).div(BASIS_POINTS_DIVISOR);
        return rewardPerTokenStored.add(additionalReward);
    }

    function earned(address account) public view returns (uint256) {
        Staker memory staker = stakers[account];
        uint256 currentRewardPerToken = _calculateRewardPerToken();
        
        uint256 rewardDifference = currentRewardPerToken.sub(staker.rewardPerTokenPaid);
        
        uint256 newlyEarned = staker.balance.mul(rewardDifference).div(1e18);

        return staker.rewards.add(newlyEarned);
    }

    function stake(uint256 amount) external nonReentrant {
        require(amount >= MIN_STAKE, "SmartBNBStaking: Jumlah terlalu rendah");
        require(amount <= MAX_STAKE, "SmartBNBStaking: Jumlah melebihi batas stake");
        require(stakingToken.balanceOf(msg.sender) >= amount, "SmartBNBStaking: Saldo tidak cukup");

        _updateReward(msg.sender);
        
        stakingToken.transferFrom(msg.sender, address(this), amount);
        
        stakers[msg.sender].balance = stakers[msg.sender].balance.add(amount);
        stakers[msg.sender].lastStakedTime = block.timestamp;
        totalStaked = totalStaked.add(amount);

        emit Staked(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        Staker storage staker = stakers[msg.sender];
        require(staker.balance >= amount, "SmartBNBStaking: Saldo stake tidak cukup");
        
        _updateReward(msg.sender);
        
        uint256 fee = amount.mul(WITHDRAWAL_FEE_BPS).div(BASIS_POINTS_DIVISOR);
        uint256 amountAfterFee = amount.sub(fee);
        
        staker.balance = staker.balance.sub(amount);
        totalStaked = totalStaked.sub(amount);
        
        stakingToken.transfer(msg.sender, amountAfterFee);
        emit Withdrawn(msg.sender, amountAfterFee);
    }

    function claimReward() external nonReentrant {
        _updateReward(msg.sender);
        uint256 reward = stakers[msg.sender].rewards;
        
        require(reward > 0, "SmartBNBStaking: Tidak ada reward untuk diklaim");

        stakers[msg.sender].rewards = 0;
        
        uint256 compoundAmount = reward.div(2);
        uint256 claimAmount = reward.sub(compoundAmount);
        
        stakers[msg.sender].balance = stakers[msg.sender].balance.add(compoundAmount);
        totalStaked = totalStaked.add(compoundAmount);
        
        stakingToken.transfer(msg.sender, claimAmount);
        
        totalRewardsDistributed = totalRewardsDistributed.add(reward);

        emit RewardPaid(msg.sender, claimAmount, compoundAmount);
        emit Staked(msg.sender, compoundAmount);
    }

    function exit() external nonReentrant {
        Staker storage staker = stakers[msg.sender];
        
        require(staker.balance > 0 || staker.rewards > 0, "SmartBNBStaking: Tidak ada saldo stake atau reward");

        _updateReward(msg.sender); 

        uint256 stakedAmount = staker.balance;
        if (stakedAmount > 0) {
            uint256 fee = stakedAmount.mul(WITHDRAWAL_FEE_BPS).div(BASIS_POINTS_DIVISOR);
            uint256 amountAfterFee = stakedAmount.sub(fee);
            
            staker.balance = 0;
            totalStaked = totalStaked.sub(stakedAmount);
            
            stakingToken.transfer(msg.sender, amountAfterFee);
            emit Withdrawn(msg.sender, amountAfterFee);
        }

        uint256 reward = staker.rewards;
        if (reward > 0) {
            staker.rewards = 0;
            totalRewardsDistributed = totalRewardsDistributed.add(reward);
            stakingToken.transfer(msg.sender, reward);
            emit RewardPaid(msg.sender, reward, 0);
        }
    }

    function setAPY(uint256 _newAPY) external onlyOwner {
        require(_newAPY >= 1000 && _newAPY <= 2000, "SmartBNBStaking: APY harus antara 10% (1000) dan 20% (2000)");
        
        _updateReward(address(0)); 
        
        uint256 oldAPY = APY;
        APY = _newAPY;
        emit APYUpdated(oldAPY, _newAPY);
    }

    function recoverTokens(address _tokenAddress, uint256 _amount) external onlyOwner {
        require(_tokenAddress != address(stakingToken), "SmartBNBStaking: Tidak dapat memulihkan token staking");
        require(_amount > 0, "SmartBNBStaking: Jumlah harus lebih dari nol");
        IERC20(_tokenAddress).transfer(owner(), _amount);
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
