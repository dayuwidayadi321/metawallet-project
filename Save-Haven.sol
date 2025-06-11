// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol"; // Import UUPSUpgradeable
import "@openzeppelin/contracts/access/AccessControl.sol"; // Untuk kontrol akses yang lebih granular

contract SafeHaven is ERC20, Ownable, Pausable, UUPSUpgradeable {
    using SafeMath for uint256;
    using Counters for Counters.Counter;

    address private immutable BURN_ADDRESS = 0x0000000000000000000000000000000000000000;
    uint256 private _feeBasisPoints;

    string private _tokenIconUri;

    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 rewardClaimed;
    }

    mapping(address => mapping(uint256 => Stake)) public userStakes;
    mapping(address => Counters.Counter) private _stakeIds;
    uint256 public stakingRewardRate;
    uint256 public constant SECONDS_IN_DAY = 86400;

    event TokenIconUriUpdated(string newUri);
    event FeeBasisPointsUpdated(uint256 newFeeBasisPoints);
    event TokensBurned(address indexed burner, uint256 amount);
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime);
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);

    function initialize(address ownerAddress, uint256 initialSupply) public initializer {
        __ERC20_init("Safe Haven Coin", "BURN");
        __Ownable_init(ownerAddress);
        __Pausable_init();
        __UUPSUpgradeable_init();

        _feeBasisPoints = 1;
        stakingRewardRate = 100000000000000000; // 0.1 SAFE per hari per 1 SAFE

        _mint(ownerAddress, initialSupply);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        if (from != BURN_ADDRESS && amount > 0) {
            uint256 feeAmount = amount.mul(_feeBasisPoints).div(10000);
            uint256 amountAfterFee = amount.sub(feeAmount);

            super._update(from, to, amountAfterFee);

            if (feeAmount > 0) {
                super._update(from, BURN_ADDRESS, feeAmount);
            }
        } else {
            super._update(from, to, amount);
        }
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
        emit TokensBurned(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) public {
        uint256 currentAllowance = allowance(account, msg.sender);
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, msg.sender, currentAllowance.sub(amount));
        _burn(account, amount);
        emit TokensBurned(account, amount);
    }

    function stake(uint256 amount) public whenNotPaused {
        require(amount > 0, "Stake amount must be greater than zero");
        _transfer(msg.sender, address(this), amount);
        
        _stakeIds[msg.sender].increment();
        uint256 newStakeId = _stakeIds[msg.sender].current();
        userStakes[msg.sender][newStakeId] = Stake({
            amount: amount,
            startTime: block.timestamp,
            rewardClaimed: 0
        });

        emit Staked(msg.sender, newStakeId, amount, block.timestamp);
    }

    function calculateStakeRewards(address user, uint256 stakeId) public view returns (uint256) {
        Stake memory stake = userStakes[user][stakeId];
        if (stake.amount == 0) {
            return 0;
        }

        uint256 duration = block.timestamp.sub(stake.startTime);
        uint256 potentialReward = stake.amount.mul(stakingRewardRate).mul(duration).div(SECONDS_IN_DAY).div(10**18);
        return potentialReward.sub(stake.rewardClaimed);
    }

    function claimStakeRewards(uint256 stakeId) public whenNotPaused {
        Stake storage stake = userStakes[msg.sender][stakeId];
        require(stake.amount > 0, "No active stake found for this ID");

        uint256 rewards = calculateStakeRewards(msg.sender, stakeId);
        require(rewards > 0, "No rewards to claim");

        stake.rewardClaimed = stake.rewardClaimed.add(rewards);

        _mint(msg.sender, rewards);
        emit RewardsClaimed(msg.sender, stakeId, rewards);
    }

    function unstake(uint256 stakeId) public whenNotPaused {
        Stake storage stake = userStakes[msg.sender][stakeId];
        require(stake.amount > 0, "No active stake found for this ID");

        uint256 amountToReturn = stake.amount;
        uint256 pendingRewards = calculateStakeRewards(msg.sender, stakeId);

        delete userStakes[msg.sender][stakeId];

        _transfer(address(this), msg.sender, amountToReturn);

        if (pendingRewards > 0) {
            stake.rewardClaimed = stake.rewardClaimed.add(pendingRewards);
            _mint(msg.sender, pendingRewards);
            emit RewardsClaimed(msg.sender, stakeId, pendingRewards);
        }

        emit Unstaked(msg.sender, stakeId, amountToReturn);
    }

    function tokenIconUri() public view returns (string memory) {
        return _tokenIconUri;
    }

    function feeBasisPoints() public view returns (uint256) {
        return _feeBasisPoints;
    }

    function setTokenIconUri(string memory uri_) public onlyOwner {
        _tokenIconUri = uri_;
        emit TokenIconUriUpdated(uri_);
    }

    function setFeeBasisPoints(uint256 newFeeBasisPoints) public onlyOwner {
        require(newFeeBasisPoints <= 1000, "Fee cannot exceed 10%");
        _feeBasisPoints = newFeeBasisPoints;
        emit FeeBasisPointsUpdated(newFeeBasisPoints);
    }

    function setStakingRewardRate(uint256 newRate) public onlyOwner {
        stakingRewardRate = newRate;
    }
}
