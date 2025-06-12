// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract SafeHaven is ERC20Upgradeable, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable {
    using CountersUpgradeable for CountersUpgradeable.Counter;

    // Alamat burn yang tidak bisa diubah setelah inisialisasi
    address private _burnAddress;
    
    // Biaya burn dan biaya staking pool dalam basis poin (10000 basis poin = 100%)
    uint256 private _burnFeeBasisPoints;
    uint256 private _stakingPoolFeeBasisPoints;
    // Batas total biaya yang diizinkan (10% = 1000 basis poin)
    uint256 public constant MAX_TOTAL_FEE_BASIS_POINTS = 1000; 
    
    // URI untuk ikon token
    string private _tokenIconUri;

    // Struktur untuk menyimpan detail stake
    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 rewardClaimed;
    }

    // Mapping untuk melacak stake pengguna berdasarkan ID
    mapping(address => mapping(uint256 => Stake)) public userStakes;
    mapping(address => CountersUpgradeable.Counter) private _stakeIds;
    
    // Tingkat hadiah staking dan total jumlah yang di-stake
    uint256 public stakingRewardRate;
    uint256 public totalStakedAmount;
    // Durasi hari dalam detik (dapat diubah jika perlu fleksibilitas)
    uint256 public secondsInDay; 

    // Versi kontrak
    string public constant CONTRACT_VERSION = "7.0"; 

    // Event yang dipancarkan saat URI ikon token diperbarui
    event TokenIconUriUpdated(string newUri);
    // Event yang dipancarkan saat biaya diperbarui
    event FeeBasisPointsUpdated(uint256 newBurnFee, uint256 newStakingFee);
    // Event yang dipancarkan saat token dibakar
    event TokensBurned(address indexed burner, uint256 amount);
    // Event yang dipancarkan saat pengguna melakukan stake
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime);
    // Event yang dipancarkan saat pengguna melakukan unstake
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    // Event yang dipancarkan saat hadiah staking diklaim
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);
    // Event yang dipancarkan saat staking pool didanai (melalui biaya atau lainnya)
    event StakingPoolFunded(uint256 amount);
    // Event yang dipancarkan saat tingkat hadiah staking diperbarui
    event StakingRewardRateUpdated(uint256 newRate); // Tambahan dari rekomendasi

    /**
     * @dev Menginisialisasi kontrak.
     * @param ownerAddress Alamat pemilik awal kontrak.
     * @param initialSupply Jumlah token awal yang akan dicetak.
     */
    function initialize(address ownerAddress, uint256 initialSupply) public initializer {
        // Inisialisasi kontrak OpenZeppelin yang diwariskan
        __ERC20_init("BURN TOKEN", "BURN"); // Nama token diubah menjadi "BURN TOKEN"
        __Ownable_init(ownerAddress);
        __Pausable_init();
        __UUPSUpgradeable_init();

        // Inisialisasi alamat burn
        _burnAddress = 0x0000000000000000000000000000000000000000;
        
        // Atur biaya awal
        _burnFeeBasisPoints = 10;
        _stakingPoolFeeBasisPoints = 10;
        
        // Atur tingkat hadiah staking dan total staked amount awal
        stakingRewardRate = 100000000000000000; // Contoh: 0.1 ether per token per hari
        totalStakedAmount = 0;
        secondsInDay = 86400; // Inisialisasi durasi hari dalam detik

        // Cetak token awal ke pemilik
        _mint(ownerAddress, initialSupply);
    }

    /**
     * @dev Otorisasi untuk upgrade kontrak UUPS. Hanya pemilik yang diizinkan.
     * @param newImplementation Alamat implementasi kontrak yang baru.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Fungsi internal untuk memperbarui saldo token.
     * Menerapkan biaya burn dan biaya staking pool saat transfer.
     * @param from Alamat pengirim.
     * @param to Alamat penerima.
     * @param amount Jumlah token yang ditransfer.
     */
    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        // Hanya menerapkan biaya jika pengirim bukan alamat 0 dan bukan alamat burn, dan jumlahnya lebih dari 0
        if (from != address(0) && from != _burnAddress && amount > 0) {
            // Hitung jumlah yang akan dibakar dan dikirim ke staking pool
            uint256 burnAmount = amount * _burnFeeBasisPoints / 10000;
            uint256 stakingPoolAmount = amount * _stakingPoolFeeBasisPoints / 10000;
            uint256 amountAfterFees = amount - burnAmount - stakingPoolAmount; // Pengurangan langsung (Solidity 0.8+ aman)

            // Transfer jumlah setelah biaya ke penerima
            super._update(from, to, amountAfterFees);

            // Bakar token jika burnAmount > 0
            if (burnAmount > 0) {
                super._update(from, _burnAddress, burnAmount);
                emit TokensBurned(from, burnAmount);
            }

            // Transfer token ke staking pool jika stakingPoolAmount > 0
            if (stakingPoolAmount > 0) {
                super._update(from, address(this), stakingPoolAmount);
                emit StakingPoolFunded(stakingPoolAmount);
            }
        } else {
            // Jika tidak ada biaya yang diterapkan, lakukan transfer biasa
            super._update(from, to, amount);
        }
    }

    /**
     * @dev Menghentikan sementara transfer token dan fungsi staking. Hanya pemilik yang dapat memanggil.
     */
    function pause() public onlyOwner {
        _pause();
    }

    /**
     * @dev Melanjutkan transfer token dan fungsi staking. Hanya pemilik yang dapat memanggil.
     */
    function unpause() public onlyOwner {
        _unpause();
    }

    /**
     * @dev Membakar sejumlah token dari pengirim.
     * @param amount Jumlah token yang akan dibakar.
     */
    function burn(uint256 amount) public {
        _burn(_msgSender(), amount);
        emit TokensBurned(_msgSender(), amount);
    }

    /**
     * @dev Membakar sejumlah token dari akun tertentu yang telah disetujui.
     * @param account Alamat akun yang tokennya akan dibakar.
     * @param amount Jumlah token yang akan dibakar.
     */
    function burnFrom(address account, uint256 amount) public {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - amount); // Pengurangan langsung (Solidity 0.8+ aman)
        _burn(account, amount);
        emit TokensBurned(account, amount);
    }

    /**
     * @dev Memungkinkan pengguna untuk melakukan stake sejumlah token.
     * Token akan ditransfer ke kontrak ini dan pengguna akan menerima ID stake.
     * @param amount Jumlah token yang akan di-stake.
     */
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
        totalStakedAmount = totalStakedAmount + amount; // Penjumlahan langsung (Solidity 0.8+ aman)

        emit Staked(_msgSender(), newStakeId, amount, block.timestamp);
    }

    /**
     * @dev Menghitung potensi hadiah staking yang belum diklaim untuk stake tertentu.
     * @param user Alamat pengguna.
     * @param _stakeId ID stake yang akan dihitung hadiahnya.
     * @return uint256 Jumlah hadiah yang belum diklaim.
     */
    function calculateStakeRewards(address user, uint256 _stakeId) public view returns (uint256) {
        Stake memory _currentStake = userStakes[user][_stakeId];
        if (_currentStake.amount == 0) {
            return 0;
        }

        uint256 duration = block.timestamp - _currentStake.startTime; // Pengurangan langsung (Solidity 0.8+ aman)
        uint256 potentialReward = _currentStake.amount * stakingRewardRate * duration / secondsInDay / (10**18);
        return potentialReward - _currentStake.rewardClaimed; // Pengurangan langsung (Solidity 0.8+ aman)
    }

    /**
     * @dev Mengklaim hadiah staking untuk stake tertentu.
     * @param _stakeId ID stake yang akan diklaim hadiahnya.
     */
    function claimStakeRewards(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 rewards = calculateStakeRewards(_msgSender(), _stakeId);
        require(rewards > 0, "No rewards to claim");
        
        require(balanceOf(address(this)) >= rewards, "Insufficient funds in staking pool");

        _currentStake.rewardClaimed = _currentStake.rewardClaimed + rewards; // Penjumlahan langsung (Solidity 0.8+ aman)

        _transfer(address(this), _msgSender(), rewards);
        emit RewardsClaimed(_msgSender(), _stakeId, rewards);
    }

    /**
     * @dev Mengeluarkan stake token dan mengklaim hadiah yang belum diklaim.
     * @param _stakeId ID stake yang akan di-unstake.
     */
    function unstake(uint256 _stakeId) public whenNotPaused {
        Stake storage _currentStake = userStakes[_msgSender()][_stakeId];
        require(_currentStake.amount > 0, "No active stake found for this ID");

        uint256 amountToReturn = _currentStake.amount;
        uint256 pendingRewards = calculateStakeRewards(_msgSender(), _stakeId);

        totalStakedAmount = totalStakedAmount - amountToReturn; // Pengurangan langsung (Solidity 0.8+ aman)
        delete userStakes[_msgSender()][_stakeId]; // Hapus entri stake

        _transfer(address(this), _msgSender(), amountToReturn); // Kembalikan jumlah stake

        if (pendingRewards > 0) {
            require(balanceOf(address(this)) >= pendingRewards, "Insufficient funds in staking pool for pending rewards");
            _currentStake.rewardClaimed = _currentStake.rewardClaimed + pendingRewards; // Penjumlahan langsung (Solidity 0.8+ aman)
            _transfer(address(this), _msgSender(), pendingRewards); // Transfer hadiah yang belum diklaim
            emit RewardsClaimed(_msgSender(), _stakeId, pendingRewards);
        }

        emit Unstaked(_msgSender(), _stakeId, amountToReturn);
    }

    /**
     * @dev Mengembalikan URI ikon token.
     * @return string memory URI ikon token.
     */
    function tokenIconUri() public view returns (string memory) {
        return _tokenIconUri;
    }

    /**
     * @dev Mengembalikan basis poin biaya burn.
     * @return uint256 Basis poin biaya burn.
     */
    function burnFeeBasisPoints() public view returns (uint256) {
        return _burnFeeBasisPoints;
    }

    /**
     * @dev Mengembalikan basis poin biaya staking pool.
     * @return uint256 Basis poin biaya staking pool.
     */
    function stakingPoolFeeBasisPoints() public view returns (uint256) {
        return _stakingPoolFeeBasisPoints;
    }

    /**
     * @dev Mengatur URI ikon token. Hanya pemilik yang dapat memanggil.
     * @param uri_ URI baru untuk ikon token.
     */
    function setTokenIconUri(string memory uri_) public onlyOwner {
        _tokenIconUri = uri_;
        emit TokenIconUriUpdated(uri_);
    }

    /**
     * @dev Mengatur basis poin biaya burn dan biaya staking pool. Hanya pemilik yang dapat memanggil.
     * Memastikan total biaya tidak melebihi 10%.
     * @param newBurnFee Basis poin biaya burn yang baru.
     * @param newStakingFee Basis poin biaya staking pool yang baru.
     */
    function setFeesBasisPoints(uint256 newBurnFee, uint256 newStakingFee) public onlyOwner {
        require(newBurnFee + newStakingFee <= MAX_TOTAL_FEE_BASIS_POINTS, "Total fee cannot exceed 10%"); // Penjumlahan langsung (Solidity 0.8+ aman)
        _burnFeeBasisPoints = newBurnFee;
        _stakingPoolFeeBasisPoints = newStakingFee;
        emit FeeBasisPointsUpdated(newBurnFee, newStakingFee);
    }

    /**
     * @dev Mengatur tingkat hadiah staking. Hanya pemilik yang dapat memanggil.
     * @param newRate Tingkat hadiah staking yang baru.
     */
    function setStakingRewardRate(uint256 newRate) public onlyOwner {
        stakingRewardRate = newRate;
        emit StakingRewardRateUpdated(newRate); // Memancarkan event
    }

    /**
     * @dev Mengatur jumlah detik dalam sehari untuk perhitungan hadiah staking. Hanya pemilik yang dapat memanggil.
     * @param newSeconds Jumlah detik yang baru.
     */
    function setSecondsInDay(uint256 newSeconds) public onlyOwner {
        require(newSeconds > 0, "Duration must be greater than zero");
        secondsInDay = newSeconds;
        // Pertimbangkan event untuk ini jika pemantauan off-chain memerlukannya
    }

    /**
     * @dev Mengembalikan versi kontrak saat ini.
     * @return string memory Versi kontrak.
     */
    function getContractVersion() public pure returns (string memory) {
        return CONTRACT_VERSION;
    }
}

