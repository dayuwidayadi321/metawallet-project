// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";

contract SafeHaven is ERC20Upgradeable, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable, ERC20PermitUpgradeable {
    using CountersUpgradeable for CountersUpgradeable.Counter;

    address private _burnAddress; // Alamat burn
    uint256 private _burnFeeBasisPoints;
    uint256 private _stakingPoolFeeBasisPoints;
    uint256 public constant MAX_TOTAL_FEE_BASIS_POINTS = 1000; // 10%
    
    string private _tokenIconUri;

    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 rewardClaimed;
    }

    mapping(address => mapping(uint256 => Stake)) public userStakes;
    mapping(address => CountersUpgradeable.Counter) private _stakeIds;
    
    uint256 public stakingRewardRate;
    uint256 public totalStakedAmount;
    uint256 public secondsInDay; 

    uint256 private _totalBurnedTokens; // Variabel baru untuk melacak total token yang dibakar

    string public constant CONTRACT_VERSION = "8.2"; // Versi kontrak yang diperbarui

    event TokenIconUriUpdated(string newUri);
    event FeeBasisPointsUpdated(uint256 newBurnFee, uint256 newStakingFee);
    event TokensBurned(address indexed burner, uint256 amount);
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime);
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);
    event StakingPoolFunded(uint256 amount);
    event StakingRewardRateUpdated(uint256 newRate); 
    event TotalTokensBurnedUpdated(uint256 totalAmount); // Event baru

    function initialize(address ownerAddress, uint256 initialSupply) public initializer {
        __ERC20_init("BURN TOKEN", "BURN"); 
        __Ownable_init(ownerAddress);
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ERC20Permit_init("BURN");

        _burnAddress = address(0x000000000000000000000000000000000000dEaD); // Menggunakan 0x...dEaD sebagai alamat burn yang lebih eksplisit
        _burnFeeBasisPoints = 10;
        _stakingPoolFeeBasisPoints = 10;
        
        stakingRewardRate = 100000000000000000; 
        totalStakedAmount = 0;
        secondsInDay = 86400; 
        _totalBurnedTokens = 0; // Inisialisasi total burned tokens

        _mint(ownerAddress, initialSupply);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        if (from != address(0) && from != _burnAddress && amount > 0) {
            uint256 burnAmount = amount * _burnFeeBasisPoints / 10000;
            uint256 stakingPoolAmount = amount * _stakingPoolFeeBasisPoints / 10000;
            uint256 amountAfterFees = amount - burnAmount - stakingPoolAmount; 

            super._update(from, to, amountAfterFees);

            if (burnAmount > 0) {
                super._update(from, _burnAddress, burnAmount);
                _totalBurnedTokens += burnAmount; // Tambahkan ke total burned tokens
                emit TokensBurned(from, burnAmount);
                emit TotalTokensBurnedUpdated(_totalBurnedTokens); // Pancarkan event baru
            }

            if (stakingPoolAmount > 0) {
                super._update(from, address(this), stakingPoolAmount);
                emit StakingPoolFunded(stakingPoolAmount);
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
        _burn(_msgSender(), amount);
        _totalBurnedTokens += amount; // Tambahkan ke total burned tokens
        emit TokensBurned(_msgSender(), amount);
        emit TotalTokensBurnedUpdated(_totalBurnedTokens); // Pancarkan event baru
    }

    function burnFrom(address account, uint256 amount) public {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - amount); 
        _burn(account, amount);
        _totalBurnedTokens += amount; // Tambahkan ke total burned tokens
        emit TokensBurned(account, amount);
        emit TotalTokensBurnedUpdated(_totalBurnedTokens); // Pancarkan event baru
    }

    function stake(uint256 amount) public whenNotPaused {
        require(amount > 0, "Stake amount must be greater than zero");
        _transfer(_msgSender(), address(this), amount);
        
        _stakeIds[_msgSender()].increment();
        uint256 newStakeId = _stakeIds[_msgSender()].current();
        userStakes[_msgSender()][newStakeId] = Stake({
            amount: amount,
            startTime: block.timestamp,
            rewardClaimed: 0
        });
        totalStakedAmount = totalStakedAmount + amount; 

        emit Staked(_msgSender(), newStakeId, amount, block.timestamp);
    }

    function calculateStakeRewards(address user, uint256 _stakeId) public view returns (uint256) {
        Stake memory _currentStake = userStakes[user][_stakeId];
        if (_currentStake.amount == 0) {
            return 0;
        }

        uint256 duration = block.timestamp - _currentStake.startTime; 
        uint256 potentialReward = _currentStake.amount * stakingRewardRate * duration / secondsInDay / (10**18);
        return potentialReward - _currentStake.rewardClaimed; 
    }

    function claimStakeRewards(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 rewards = calculateStakeRewards(_msgSender(), _stakeId);
        require(rewards > 0, "No rewards to claim");
        
        require(balanceOf(address(this)) >= rewards, "Insufficient funds in staking pool");

        _currentStake.rewardClaimed = _currentStake.rewardClaimed + rewards; 

        _transfer(address(this), _msgSender(), rewards);
        emit RewardsClaimed(_msgSender(), _stakeId, rewards);
    }

    function unstake(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 amountToReturn = _currentStake.amount;
        uint256 pendingRewards = calculateStakeRewards(_msgSender(), _stakeId);

        totalStakedAmount = totalStakedAmount - amountToReturn; 
        delete userStakes[_msgSender()][_stakeId]; 

        _transfer(address(this), _msgSender(), amountToReturn); 

        if (pendingRewards > 0) {
            require(balanceOf(address(this)) >= pendingRewards, "Insufficient funds in staking pool for pending rewards");
            _currentStake.rewardClaimed = _currentStake.rewardClaimed + pendingRewards; 
            _transfer(address(this), _msgSender(), pendingRewards); 
            emit RewardsClaimed(_msgSender(), _stakeId, pendingRewards);
        }

        emit Unstaked(_msgSender(), _stakeId, amountToReturn);
    }

    function tokenIconUri() public view returns (string memory) {
        return _tokenIconUri;
    }

    function burnFeeBasisPoints() public view returns (uint256) {
        return _burnFeeBasisPoints;
    }

    function stakingPoolFeeBasisPoints() public view returns (uint256) {
        return _stakingPoolFeeBasisPoints;
    }

    function setTokenIconUri(string memory uri_) public onlyOwner {
        _tokenIconUri = uri_;
        emit TokenIconUriUpdated(uri_);
    }

    function setFeesBasisPoints(uint256 newBurnFee, uint256 newStakingFee) public onlyOwner {
        require(newBurnFee + newStakingFee <= MAX_TOTAL_FEE_BASIS_POINTS, "Total fee cannot exceed 10%"); 
        _burnFeeBasisPoints = newBurnFee;
        _stakingPoolFeeBasisPoints = newStakingFee;
        emit FeeBasisPointsUpdated(newBurnFee, newStakingFee);
    }

    function setStakingRewardRate(uint256 newRate) public onlyOwner {
        stakingRewardRate = newRate;
        emit StakingRewardRateUpdated(newRate); 
    }

    function setSecondsInDay(uint256 newSeconds) public onlyOwner {
        require(newSeconds > 0, "Duration must be greater than zero");
        secondsInDay = newSeconds;
    }

    function getContractVersion() public pure returns (string memory) {
        return CONTRACT_VERSION;
    }

    /**
     * @dev Mengembalikan total token yang telah dibakar.
     */
    function totalBurnedTokens() public view returns (uint256) {
        return _totalBurnedTokens;
    }
}
