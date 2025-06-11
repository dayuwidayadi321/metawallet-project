// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SafeHaven is ERC20, Ownable, Pausable, UUPSUpgradeable {
    using SafeMath for uint256;
    using Counters for Counters.Counter;

    address private immutable BURN_ADDRESS = 0x0000000000000000000000000000000000000000;
    
    uint256 private _burnFeeBasisPoints;         // 0.01% untuk burn
    uint256 private _stakingPoolFeeBasisPoints;  // 0.01% untuk staking pool
    uint256 public constant TOTAL_FEE_BASIS_POINTS = 20; // 0.02% (0.01% burn + 0.01% staking pool)
    
    string private _tokenIconUri;

    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 rewardClaimed;
    }

    mapping(address => mapping(uint256 => Stake)) public userStakes;
    mapping(address => Counters.Counter) private _stakeIds;
    
    uint256 public stakingRewardRate; // Ini akan menjadi faktor untuk APY dinamis, bisa diatur oleh owner
    uint256 public totalStakedAmount; // Total token yang di-stake di kontrak
    uint256 public constant SECONDS_IN_DAY = 86400;

    // Tambahkan variabel untuk versi smart contract
    string public constant CONTRACT_VERSION = "5.0"; 

    event TokenIconUriUpdated(string newUri);
    event FeeBasisPointsUpdated(uint256 newBurnFee, uint256 newStakingFee);
    event TokensBurned(address indexed burner, uint256 amount);
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime);
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);
    event StakingPoolFunded(uint256 amount);

    function initialize(address ownerAddress, uint256 initialSupply) public initializer {
        __ERC20_init("Safe Haven Coin", "BURN");
        __Ownable_init(ownerAddress);
        __Pausable_init();
        __UUPSUpgradeable_init();

        // Mengatur fee awal: 0.01% untuk burn dan 0.01% untuk staking pool (total 0.02%)
        _burnFeeBasisPoints = 10; // 0.01% (10/10000 = 0.001)
        _stakingPoolFeeBasisPoints = 10; // 0.01% (10/10000 = 0.001)
        
        stakingRewardRate = 100000000000000000; // Contoh awal: 0.1 SAFE per hari per 1 SAFE (akan dinamis)
        totalStakedAmount = 0;

        _mint(ownerAddress, initialSupply);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        if (from != address(0) && from != BURN_ADDRESS && amount > 0) {
            uint256 burnAmount = amount.mul(_burnFeeBasisPoints).div(10000);
            uint256 stakingPoolAmount = amount.mul(_stakingPoolFeeBasisPoints).div(10000);
            uint256 amountAfterFees = amount.sub(burnAmount).sub(stakingPoolAmount);

            // Transfer jumlah bersih ke penerima
            super._update(from, to, amountAfterFees);

            // Transfer ke BURN_ADDRESS (dibakar)
            if (burnAmount > 0) {
                super._update(from, BURN_ADDRESS, burnAmount);
                emit TokensBurned(from, burnAmount);
            }

            // Transfer ke kontrak ini sendiri untuk staking pool
            if (stakingPoolAmount > 0) {
                super._update(from, address(this), stakingPoolAmount);
                emit StakingPoolFunded(stakingPoolAmount);
            }
        } else {
            // Untuk minting atau transfer dari BURN_ADDRESS atau ke address(0)
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
        totalStakedAmount = totalStakedAmount.add(amount);

        emit Staked(msg.sender, newStakeId, amount, block.timestamp);
    }

    // Fungsi ini akan menjadi lebih kompleks untuk APY dinamis yang sesungguhnya.
    // Saat ini, APY dinamis diimplementasikan dengan menyesuaikan stakingRewardRate oleh owner
    // dan reward diambil dari pool. Implementasi APY dinamis yang lebih canggih (misalnya berdasarkan
    // rasio pool_balance / total_staked_amount) akan memerlukan perhitungan yang lebih mendalam.
    function calculateStakeRewards(address user, uint256 _stakeId) public view returns (uint256) {
        Stake memory _currentStake = userStakes[user][_stakeId];
        if (_currentStake.amount == 0) {
            return 0;
        }

        uint256 duration = block.timestamp.sub(_currentStake.startTime);
        // Menggunakan stakingRewardRate yang dapat diatur owner untuk mensimulasikan APY dinamis
        // Reward dihitung sebagai persentase dari amount yang di-stake, dikalikan durasi
        uint256 potentialReward = _currentStake.amount.mul(stakingRewardRate).mul(duration).div(SECONDS_IN_DAY).div(10**18);
        return potentialReward.sub(_currentStake.rewardClaimed);
    }

    function claimStakeRewards(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[msg.sender][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 rewards = calculateStakeRewards(msg.sender, _stakeId);
        require(rewards > 0, "No rewards to claim");
        
        // Pastikan kontrak memiliki cukup dana untuk membayar reward
        require(balanceOf(address(this)) >= rewards, "Insufficient funds in staking pool");

        _currentStake.rewardClaimed = _currentStake.rewardClaimed.add(rewards);

        // Transfer reward dari saldo kontrak ke user
        _transfer(address(this), msg.sender, rewards);
        emit RewardsClaimed(msg.sender, _stakeId, rewards);
    }

    function unstake(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[msg.sender][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 amountToReturn = _currentStake.amount;
        uint256 pendingRewards = calculateStakeRewards(msg.sender, _stakeId);

        totalStakedAmount = totalStakedAmount.sub(amountToReturn);
        delete userStakes[msg.sender][_stakeId];

        // Transfer kembali jumlah stake
        _transfer(address(this), msg.sender, amountToReturn);

        // Jika ada reward yang belum diklaim, klaim dan transfer
        if (pendingRewards > 0) {
            require(balanceOf(address(this)) >= pendingRewards, "Insufficient funds in staking pool for pending rewards");
            _currentStake.rewardClaimed = _currentStake.rewardClaimed.add(pendingRewards);
            _transfer(address(this), msg.sender, pendingRewards);
            emit RewardsClaimed(msg.sender, _stakeId, pendingRewards);
        }

        emit Unstaked(msg.sender, _stakeId, amountToReturn);
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

    // Fungsi untuk mengatur kedua fee sekaligus
    function setFeesBasisPoints(uint256 newBurnFee, uint256 newStakingFee) public onlyOwner {
        // Total fee tidak boleh melebihi batas yang wajar (misalnya 10%)
        require(newBurnFee.add(newStakingFee) <= 1000, "Total fee cannot exceed 10%");
        _burnFeeBasisPoints = newBurnFee;
        _stakingPoolFeeBasisPoints = newStakingFee;
        emit FeeBasisPointsUpdated(newBurnFee, newStakingFee);
    }

    // Owner dapat menyesuaikan reward rate untuk mensimulasikan APY dinamis
    function setStakingRewardRate(uint256 newRate) public onlyOwner {
        stakingRewardRate = newRate;
    }

    // Fungsi read untuk mendapatkan versi smart contract
    function getContractVersion() public pure returns (string memory) {
        return CONTRACT_VERSION;
    }
}
