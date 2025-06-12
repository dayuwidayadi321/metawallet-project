// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
contract SafeHaven is ERC20Upgradeable, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable, ERC20PermitUpgradeable {
    using CountersUpgradeable for CountersUpgradeable.Counter;
    using SafeMathUpgradeable for uint256;

    address private _burnAddress;
    uint256 private _burnFeeBasisPoints;
    uint256 private _stakingPoolFeeBasisPoints;
    uint256 public constant MAX_TOTAL_FEE_BASIS_POINTS = 1000; // 10%

    string private _tokenIconUri;

    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 rewardClaimed;
        uint256 lastCompoundTime;
        uint256 compoundInterval;
    }

    mapping(address => mapping(uint256 => Stake)) public userStakes;
    mapping(address => CountersUpgradeable.Counter) private _stakeIds;

    uint256 public stakingRewardRate;
    uint256 public totalStakedAmount;
    uint256 public secondsInDay;
    uint256 public defaultCompoundInterval;

    uint256 private _totalBurnedTokens;

    string public constant CONTRACT_VERSION = "9.0";

    event TokenIconUriUpdated(string newUri);
    event FeeBasisPointsUpdated(uint256 newBurnFee, uint256 newStakingFee);
    event TokensBurned(address indexed burner, uint256 amount);
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime, uint256 compoundInterval); // Tambah compoundInterval
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);
    event StakingPoolFunded(uint256 amount);
    event StakingRewardRateUpdated(uint256 newRate);
    event TotalTokensBurnedUpdated(uint256 totalAmount);
    event StakingCompounded(address indexed user, uint256 stakeId, uint256 compoundedAmount);
    event DefaultCompoundIntervalUpdated(uint256 newInterval);

    function initialize(address ownerAddress, uint256 initialSupply) public initializer {
        __ERC20_init("BURN TOKEN", "BURN");
        __Ownable_init(ownerAddress);
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ERC20Permit_init("BURN");

        _burnAddress = address(0x000000000000000000000000000000000000dEaD);
        _burnFeeBasisPoints = 10;
        _stakingPoolFeeBasisPoints = 10;

        stakingRewardRate = 100000000000000000;
        totalStakedAmount = 0;
        secondsInDay = 86400;
        defaultCompoundInterval = 7 * secondsInDay; // Default: 7 hari (1 minggu)
        _totalBurnedTokens = 0;

        _mint(ownerAddress, initialSupply);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        if (from != address(0) && from != _burnAddress && amount > 0) {
            uint256 burnAmount = amount.mul(_burnFeeBasisPoints).div(10000);
            uint256 stakingPoolAmount = amount.mul(_stakingPoolFeeBasisPoints).div(10000);
            uint256 amountAfterFees = amount.sub(burnAmount).sub(stakingPoolAmount);

            super._update(from, to, amountAfterFees);

            if (burnAmount > 0) {
                super._update(from, _burnAddress, burnAmount);
                _totalBurnedTokens = _totalBurnedTokens.add(burnAmount);
                emit TokensBurned(from, burnAmount);
                emit TotalTokensBurnedUpdated(_totalBurnedTokens);
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
        _totalBurnedTokens = _totalBurnedTokens.add(amount);
        emit TokensBurned(_msgSender(), amount);
        emit TotalTokensBurnedUpdated(_totalBurnedTokens);
    }

    function burnFrom(address account, uint256 amount) public {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance.sub(amount));
        _burn(account, amount);
        _totalBurnedTokens = _totalBurnedTokens.add(amount);
        emit TokensBurned(account, amount);
        emit TotalTokensBurnedUpdated(_totalBurnedTokens);
    }

    // --- FITUR BARU: Auto-Compound Staking ---

    /**
     * @dev Melakukan staking token dengan interval compounding yang bisa diatur.
     * @param amount Jumlah token yang akan di-stake.
     * @param _compoundInterval Interval dalam detik untuk auto-compound. Jika 0, menggunakan default.
     */
    function stake(uint256 amount, uint256 _compoundInterval) public whenNotPaused {
        require(amount > 0, "Stake amount must be greater than zero");
        _transfer(_msgSender(), address(this), amount);

        _stakeIds[_msgSender()].increment();
        uint256 newStakeId = _stakeIds[_msgSender()].current();

        uint256 actualCompoundInterval = (_compoundInterval == 0) ? defaultCompoundInterval : _compoundInterval;
        require(actualCompoundInterval > 0, "Compound interval must be greater than zero"); // Pastikan interval valid

        userStakes[_msgSender()][newStakeId] = Stake({
            amount: amount,
            startTime: block.timestamp,
            rewardClaimed: 0,
            lastCompoundTime: block.timestamp,
            compoundInterval: actualCompoundInterval
        });
        totalStakedAmount = totalStakedAmount.add(amount);

        emit Staked(_msgSender(), newStakeId, amount, block.timestamp, actualCompoundInterval);
    }

    /**
     * @dev Overload fungsi stake agar tetap kompatibel dengan panggilan lama tanpa interval.
     */
    function stake(uint256 amount) public whenNotPaused {
        stake(amount, defaultCompoundInterval);
    }

    /**
     * @dev Mengatur ulang interval compounding untuk stake tertentu.
     * @param _stakeId ID dari stake yang ingin diatur ulang.
     * @param newCompoundInterval Interval baru dalam detik.
     */
    function setCompoundInterval(uint256 _stakeId, uint256 newCompoundInterval) public {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");
        require(newCompoundInterval > 0, "Compound interval must be greater than zero");
        _currentStake.compoundInterval = newCompoundInterval;
    }

    /**
     * @dev Melakukan auto-compounding rewards untuk stake tertentu jika waktunya sudah tiba.
     * Dapat dipanggil oleh siapa saja, tetapi hanya akan bekerja jika interval telah berlalu.
     * Hadiah akan ditambahkan ke jumlah stake utama.
     * @param _stakeId ID dari stake yang akan di-compound.
     */
    function compoundStake(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        // Hitung rewards yang tersedia sejak terakhir kali di-compound atau mulai staking
        uint256 durationSinceLastCompound = block.timestamp.sub(_currentStake.lastCompoundTime);
        require(durationSinceLastCompound >= _currentStake.compoundInterval, "Compound interval has not passed");

        // Hitung reward potensial untuk periode ini (dari lastCompoundTime hingga sekarang)
        uint256 rewards = _currentStake.amount
                            .mul(stakingRewardRate)
                            .mul(durationSinceLastCompound)
                            .div(secondsInDay)
                            .div(10**18)
                            .sub(_currentStake.rewardClaimed); // Kurangi reward yang sudah diklaim

        require(rewards > 0, "No rewards to compound");
        require(balanceOf(address(this)) >= rewards, "Insufficient funds in staking pool for compounding");

        // Update jumlah stake
        _currentStake.amount = _currentStake.amount.add(rewards);
        _currentStake.lastCompoundTime = block.timestamp;
        _currentStake.rewardClaimed = 0; // Reset rewardClaimed setelah compounding

        totalStakedAmount = totalStakedAmount.add(rewards); // Tambahkan ke total staked amount global

        // Transfer dana ke stake itu sendiri
        _transfer(address(this), address(this), rewards); // Token tetap di kontrak untuk staking

        emit StakingCompounded(_msgSender(), _stakeId, rewards);
    }

    function calculateStakeRewards(address user, uint256 _stakeId) public view returns (uint256) {
        Stake memory _currentStake = userStakes[user][_stakeId];
        if (_currentStake.amount == 0) {
            return 0;
        }

        uint256 duration = block.timestamp.sub(_currentStake.lastCompoundTime); // Hitung dari lastCompoundTime
        uint256 potentialReward = _currentStake.amount.mul(stakingRewardRate).mul(duration).div(secondsInDay).div(10**18);
        return potentialReward.sub(_currentStake.rewardClaimed);
    }

    function claimStakeRewards(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        // Pastikan untuk meng-compound terlebih dahulu jika sudah waktunya
        // Atau biarkan user panggil compoundStake() secara eksplisit
        // Untuk kesederhanaan, kita hanya mengklaim apa yang sudah terakumulasi
        uint256 rewards = calculateStakeRewards(_msgSender(), _stakeId);
        require(rewards > 0, "No rewards to claim");

        require(balanceOf(address(this)) >= rewards, "Insufficient funds in staking pool");

        _currentStake.rewardClaimed = _currentStake.rewardClaimed.add(rewards); // Tambahkan ke rewardClaimed
        _currentStake.lastCompoundTime = block.timestamp; // Update lastCompoundTime setelah klaim

        _transfer(address(this), _msgSender(), rewards);
        emit RewardsClaimed(_msgSender(), _stakeId, rewards);
    }

    function unstake(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        // Pastikan untuk meng-compound terlebih dahulu jika sudah waktunya, sebelum unstake
        // atau klaim reward sebelum unstake. Untuk kesederhanaan, kita akan mengklaim semua yang tersisa.
        uint256 pendingRewards = calculateStakeRewards(_msgSender(), _stakeId);

        uint256 amountToReturn = _currentStake.amount;
        uint256 totalPayout = amountToReturn.add(pendingRewards);

        require(balanceOf(address(this)) >= totalPayout, "Insufficient funds in staking pool for unstake and rewards");

        totalStakedAmount = totalStakedAmount.sub(amountToReturn);
        delete userStakes[_msgSender()][_stakeId];

        // Transfer kembali jumlah stake asli + hadiah yang belum diklaim
        _transfer(address(this), _msgSender(), totalPayout);

        emit Unstaked(_msgSender(), _stakeId, amountToReturn);
        if (pendingRewards > 0) {
            emit RewardsClaimed(_msgSender(), _stakeId, pendingRewards);
        }
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
        override
    {
        super.permit(owner, spender, value, deadline, v, r, s);

        if ((spender == address(this) || spender == owner) && value == type(uint256).max) {
             _approve(owner, spender, type(uint256).max);
        }
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
        require(newBurnFee.add(newStakingFee) <= MAX_TOTAL_FEE_BASIS_POINTS, "Total fee cannot exceed 10%");
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

    function setDefaultCompoundInterval(uint256 newInterval) public onlyOwner {
        require(newInterval > 0, "Compound interval must be greater than zero");
        defaultCompoundInterval = newInterval;
        emit DefaultCompoundIntervalUpdated(newInterval);
    }

    function getContractVersion() public pure returns (string memory) {
        return CONTRACT_VERSION;
    }

    function totalBurnedTokens() public view returns (uint256) {
        return _totalBurnedTokens;
    }
}
