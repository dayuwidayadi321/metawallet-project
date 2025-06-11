// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Context.sol"; // Untuk _msgSender()
import "@openzeppelin/contracts/utils/math/SafeMath.sol"; // Biasanya tidak lagi diperlukan untuk Solidity ^0.8.0 karena defaultnya sudah overflow/underflow safe
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

// Hapus import AccessControl jika tidak digunakan, untuk menjaga kode tetap bersih
// import "@openzeppelin/contracts/access/AccessControl.sol"; // Ini tidak ada di kode Anda sebelumnya

contract SafeHaven is ERC20, Ownable, Pausable, UUPSUpgradeable {
    using SafeMath for uint256; // Bisa dihapus jika Anda yakin dengan Solidity 0.8.0+
    using Counters for Counters.Counter;

    address private immutable BURN_ADDRESS = 0x0000000000000000000000000000000000000000;
    
    uint256 private _burnFeeBasisPoints;
    uint256 private _stakingPoolFeeBasisPoints;
    uint256 public constant TOTAL_FEE_BASIS_POINTS = 20;
    
    string private _tokenIconUri;

    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 rewardClaimed;
    }

    mapping(address => mapping(uint256 => Stake)) public userStakes;
    mapping(address => Counters.Counter) private _stakeIds;
    
    uint256 public stakingRewardRate;
    uint256 public totalStakedAmount;
    uint256 public constant SECONDS_IN_DAY = 86400;

    string public constant CONTRACT_VERSION = "6.0"; 

    event TokenIconUriUpdated(string newUri);
    event FeeBasisPointsUpdated(uint256 newBurnFee, uint256 newStakingFee);
    event TokensBurned(address indexed burner, uint256 amount);
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime);
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);
    event StakingPoolFunded(uint256 amount);

    function initialize(address ownerAddress, uint256 initialSupply) public initializer {
        // Urutan inisialisasi yang disarankan:
        // 1. ERC20 (yang paling dasar)
        __ERC20_init("Safe Haven Coin", "BURN");
        // 2. Ownable (mengatur pemilik)
        __Ownable_init(ownerAddress);
        // 3. Pausable (kemampuan pause)
        __Pausable_init();
        // 4. UUPSUpgradeable (yang bergantung pada owner)
        __UUPSUpgradeable_init();

        // Inisialisasi variabel khusus kontrak
        _burnFeeBasisPoints = 10;
        _stakingPoolFeeBasisPoints = 10;
        
        stakingRewardRate = 100000000000000000;
        totalStakedAmount = 0;

        // Panggil _mint setelah semua inisialisasi dasar selesai
        // Ini memastikan ERC20 sudah sepenuhnya terinisialisasi
        _mint(ownerAddress, initialSupply);
    }

    // Fungsi _authorizeUpgrade sudah benar
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // Fungsi _update sudah benar, namun perlu diperhatikan
    // Jika Anda menggunakan OpenZeppelin Contracts v5.x, SafeMath mungkin tidak lagi diperlukan
    // dan _update mungkin tidak perlu dioverride secara eksplisit seperti ini
    // kecuali Anda melakukan modifikasi perilaku ERC20 yang sangat spesifik
    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        // Logika fee tetap dipertahankan
        if (from != address(0) && from != BURN_ADDRESS && amount > 0) {
            uint256 burnAmount = amount.mul(_burnFeeBasisPoints).div(10000);
            uint256 stakingPoolAmount = amount.mul(_stakingPoolFeeBasisPoints).div(10000);
            uint256 amountAfterFees = amount.sub(burnAmount).sub(stakingPoolAmount);

            super._update(from, to, amountAfterFees);

            if (burnAmount > 0) {
                super._update(from, BURN_ADDRESS, burnAmount);
                emit TokensBurned(from, burnAmount);
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
        _burn(_msgSender(), amount); // Gunakan _msgSender() di sini juga
        emit TokensBurned(_msgSender(), amount);
    }

    function burnFrom(address account, uint256 amount) public {
        uint256 currentAllowance = allowance(account, _msgSender()); // Gunakan _msgSender()
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance.sub(amount)); // Gunakan _msgSender()
        _burn(account, amount);
        emit TokensBurned(account, amount);
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
        totalStakedAmount = totalStakedAmount.add(amount);

        emit Staked(_msgSender(), newStakeId, amount, block.timestamp);
    }

    function calculateStakeRewards(address user, uint256 _stakeId) public view returns (uint256) {
        Stake memory _currentStake = userStakes[user][_stakeId];
        if (_currentStake.amount == 0) {
            return 0;
        }

        uint256 duration = block.timestamp.sub(_currentStake.startTime);
        uint256 potentialReward = _currentStake.amount.mul(stakingRewardRate).mul(duration).div(SECONDS_IN_DAY).div(10**18);
        return potentialReward.sub(_currentStake.rewardClaimed);
    }

    function claimStakeRewards(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 rewards = calculateStakeRewards(_msgSender(), _stakeId);
        require(rewards > 0, "No rewards to claim");
        
        require(balanceOf(address(this)) >= rewards, "Insufficient funds in staking pool");

        _currentStake.rewardClaimed = _currentStake.rewardClaimed.add(rewards);

        _transfer(address(this), _msgSender(), rewards);
        emit RewardsClaimed(_msgSender(), _stakeId, rewards);
    }

    function unstake(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 amountToReturn = _currentStake.amount;
        uint256 pendingRewards = calculateStakeRewards(_msgSender(), _stakeId);

        totalStakedAmount = totalStakedAmount.sub(amountToReturn);
        delete userStakes[_msgSender()][_stakeId];

        _transfer(address(this), _msgSender(), amountToReturn);

        if (pendingRewards > 0) {
            require(balanceOf(address(this)) >= pendingRewards, "Insufficient funds in staking pool for pending rewards");
            _currentStake.rewardClaimed = _currentStake.rewardClaimed.add(pendingRewards);
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
        require(newBurnFee.add(newStakingFee) <= 1000, "Total fee cannot exceed 10%");
        _burnFeeBasisPoints = newBurnFee;
        _stakingPoolFeeBasisPoints = newStakingFee;
        emit FeeBasisPointsUpdated(newBurnFee, newStakingFee);
    }

    function setStakingRewardRate(uint256 newRate) public onlyOwner {
        stakingRewardRate = newRate;
    }

    function getContractVersion() public pure returns (string memory) {
        return CONTRACT_VERSION;
    }
}

