// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol"; // Untuk operasi matematika yang aman

contract SmartBNBStaking is Ownable, ReentrancyGuard {
    using SafeMath for uint256; // Menggunakan SafeMath untuk mencegah overflow/underflow

    IERC20 public immutable stakingToken; // Jadikan immutable karena tidak akan berubah setelah konstruksi
    uint256 public totalStaked;
    uint256 public totalRewardsDistributed;

    // Gunakan konstanta dengan penamaan yang lebih eksplisit
    uint256 public constant MIN_STAKE = 0.01 ether;
    uint256 public constant MAX_STAKE = 100 ether;

    // Ubah fee menjadi basis per mil untuk presisi yang lebih baik dan penamaan yang jelas
    uint256 public constant WITHDRAWAL_FEE_BPS = 10; // 0.1% (10 basis poin dari 10000)
    uint256 public constant BASIS_POINTS_DIVISOR = 10000; // Pembagi untuk basis poin

    uint256 public APY; // APY tanpa `1e18` karena perhitungan reward sudah disesuaikan
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;

    // struct untuk menyimpan informasi staker
    struct Staker {
        uint256 balance;
        uint256 rewards; // Reward yang belum diklaim dan belum terkomposisi
        uint256 rewardPerTokenPaid; // Snapshot rewardPerToken saat terakhir di-update
        uint256 lastStakedTime; // Waktu terakhir user melakukan stake atau withdraw
    }

    mapping(address => Staker) public stakers;

    // Events untuk transparansi
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 rewardAmount, uint256 compoundedAmount);
    event APYUpdated(uint256 oldAPY, uint256 newAPY); // Tambahkan oldAPY untuk konteks

    // Konstruktor
    constructor(address _stakingToken, uint256 _initialAPY) {
        require(_stakingToken != address(0), "Alamat token staking tidak boleh nol");
        require(_initialAPY >= 1000 && _initialAPY <= 2000, "APY awal harus antara 10% dan 20%"); // Contoh validasi
        stakingToken = IERC20(_stakingToken);
        APY = _initialAPY; // Set APY awal di konstruktor
        lastUpdateTime = block.timestamp; // Inisialisasi lastUpdateTime
    }

    // Fungsi internal untuk memperbarui reward sebelum operasi state-changing
    function _updateReward(address account) internal {
        // Hitung rewardPerToken saat ini
        uint256 currentRewardPerToken = _calculateRewardPerToken();
        
        // Perbarui rewardPerTokenStored dan lastUpdateTime
        // Ini penting untuk konsistensi perhitungan reward di masa mendatang
        rewardPerTokenStored = currentRewardPerToken;
        lastUpdateTime = block.timestamp;
        
        // Jika ada akun yang valid, perbarui reward akun tersebut
        if (account != address(0)) {
            Staker storage staker = stakers[account];
            // Tambahkan reward yang baru didapat ke rewards yang sudah ada
            staker.rewards = earned(account);
            // Simpan rewardPerToken saat ini sebagai titik terakhir di mana reward dihitung untuk staker ini
            staker.rewardPerTokenPaid = currentRewardPerToken;
        }
    }

    // Fungsi internal untuk menghitung rewardPerToken
    function _calculateRewardPerToken() internal view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        // Pastikan tidak ada pembagian dengan nol
        uint256 timeElapsed = block.timestamp.sub(lastUpdateTime);
        // Perhitungan reward: (timeElapsed * APY * totalStaked * 1e18) / (365 days * BASIS_POINTS_DIVISOR * totalStaked)
        // Disimplifikasi menjadi: (timeElapsed * APY * 1e18) / (365 days * BASIS_POINTS_DIVISOR)
        // Kita menggunakan 1e18 karena APY dihitung dalam persentase * 100
        uint256 additionalReward = timeElapsed.mul(APY).mul(1e18).div(365 days).div(BASIS_POINTS_DIVISOR);
        return rewardPerTokenStored.add(additionalReward);
    }

    // Fungsi untuk melihat reward yang didapatkan oleh akun tertentu
    function earned(address account) public view returns (uint256) {
        Staker memory staker = stakers[account];
        // Perbarui rewardPerToken berdasarkan waktu saat ini
        uint256 currentRewardPerToken = _calculateRewardPerToken();
        
        // Hitung perbedaan reward per token sejak terakhir dibayar
        uint256 rewardDifference = currentRewardPerToken.sub(staker.rewardPerTokenPaid);
        
        // Hitung reward baru yang didapatkan
        uint256 newlyEarned = staker.balance.mul(rewardDifference).div(1e18); // Pembagian dengan 1e18 untuk menyesuaikan skala

        return staker.rewards.add(newlyEarned);
    }

    // Fungsi stake
    function stake(uint256 amount) external nonReentrant {
        require(amount >= MIN_STAKE, "SmartBNBStaking: Jumlah terlalu rendah");
        require(amount <= MAX_STAKE, "SmartBNBStaking: Jumlah melebihi batas stake");
        require(stakingToken.balanceOf(msg.sender) >= amount, "SmartBNBStaking: Saldo tidak cukup");

        _updateReward(msg.sender); // Perbarui reward sebelum state berubah

        // Transfer token dari pengirim ke kontrak
        stakingToken.transferFrom(msg.sender, address(this), amount);
        
        // Perbarui status staker dan total staked
        stakers[msg.sender].balance = stakers[msg.sender].balance.add(amount);
        stakers[msg.sender].lastStakedTime = block.timestamp;
        totalStaked = totalStaked.add(amount);

        emit Staked(msg.sender, amount);
    }

    // Fungsi withdraw
    function withdraw(uint256 amount) external nonReentrant {
        Staker storage staker = stakers[msg.sender];
        require(staker.balance >= amount, "SmartBNBStaking: Saldo stake tidak cukup");
        
        _updateReward(msg.sender); // Perbarui reward sebelum state berubah
        
        // Hitung fee penarikan
        uint256 fee = amount.mul(WITHDRAWAL_FEE_BPS).div(BASIS_POINTS_DIVISOR);
        uint256 amountAfterFee = amount.sub(fee);
        
        // Perbarui saldo staker dan total staked
        staker.balance = staker.balance.sub(amount);
        totalStaked = totalStaked.sub(amount);
        
        // Transfer token yang ditarik ke pengirim
        stakingToken.transfer(msg.sender, amountAfterFee);
        emit Withdrawn(msg.sender, amountAfterFee);
    }

    // Fungsi klaim reward
    function claimReward() external nonReentrant {
        _updateReward(msg.sender); // Perbarui reward sebelum state berubah
        uint256 reward = stakers[msg.sender].rewards;
        
        require(reward > 0, "SmartBNBStaking: Tidak ada reward untuk diklaim");

        // Set reward staker menjadi nol setelah diklaim
        stakers[msg.sender].rewards = 0;
        
        // Auto-compound 50% dari reward
        uint256 compoundAmount = reward.div(2);
        uint256 claimAmount = reward.sub(compoundAmount);
        
        // Tambahkan compoundAmount ke saldo stake
        stakers[msg.sender].balance = stakers[msg.sender].balance.add(compoundAmount);
        totalStaked = totalStaked.add(compoundAmount);
        
        // Transfer claimAmount ke pengirim
        stakingToken.transfer(msg.sender, claimAmount);
        
        totalRewardsDistributed = totalRewardsDistributed.add(reward); // Perbarui totalRewardDistributed dengan reward total (klaim + compound)

        emit RewardPaid(msg.sender, claimAmount, compoundAmount);
        emit Staked(msg.sender, compoundAmount); // Emit event Staked untuk auto-compound
    }

    // Fungsi exit yang lebih baik
    function exit() external nonReentrant {
        Staker storage staker = stakers[msg.sender];
        
        // Pastikan tidak ada masalah jika saldo 0
        require(staker.balance > 0 || staker.rewards > 0, "SmartBNBStaking: Tidak ada saldo stake atau reward");

        // Perbarui reward sebelum operasi
        _updateReward(msg.sender); 

        // Proses penarikan seluruh saldo stake
        uint256 stakedAmount = staker.balance;
        if (stakedAmount > 0) {
            uint256 fee = stakedAmount.mul(WITHDRAWAL_FEE_BPS).div(BASIS_POINTS_DIVISOR);
            uint256 amountAfterFee = stakedAmount.sub(fee);
            
            staker.balance = 0; // Set saldo stake menjadi 0
            totalStaked = totalStaked.sub(stakedAmount);
            
            stakingToken.transfer(msg.sender, amountAfterFee);
            emit Withdrawn(msg.sender, amountAfterFee);
        }

        // Proses klaim reward
        uint256 reward = staker.rewards;
        if (reward > 0) {
            staker.rewards = 0; // Set reward menjadi 0
            
            // Auto-compound 50% dari reward (meskipun di `exit`, ini bisa saja tidak diinginkan,
            // namun jika itu adalah fitur, maka tetap di sini)
            uint256 compoundAmount = reward.div(2);
            uint256 claimAmount = reward.sub(compoundAmount);
            
            // Jika ada sisa reward setelah compound, transfer ke user
            if (claimAmount > 0) {
                stakingToken.transfer(msg.sender, claimAmount);
            }
            
            // Jika ada compound, tambahkan ke totalStaked (meskipun user "exit", ini tetap menambahkan ke total staked pool)
            // Ini mungkin bukan perilaku yang diinginkan untuk "exit"
            // Pertimbangkan apakah compoundAmount harus ditambahkan ke totalStaked jika user "exit" sepenuhnya.
            // Untuk "exit" yang berarti keluar sepenuhnya, mungkin lebih baik semua reward ditarik tanpa compound.
            // Namun, jika auto-compound adalah fitur yang kuat, kita bisa mempertahankannya.
            // Untuk "exit" murni, saya akan menghapus auto-compound di sini dan hanya membayar semua reward yang didapat.
            // Saya akan mengubahnya untuk membayar semua reward, bukan mengkomposisi.
            
            // Pilihan 1: Bayar semua reward (untuk "exit" murni)
            // stakingToken.transfer(msg.sender, reward);
            // emit RewardPaid(msg.sender, reward, 0);

            // Pilihan 2: Tetap auto-compound jika ini adalah fitur inti
            // Saat ini, saya akan tetap pada perilaku auto-compound yang ada di `claimReward`
            // Namun, perlu dipertimbangkan ulang apakah `exit` harus melakukan auto-compound.
            // Jika `exit` dimaksudkan untuk menarik *semuanya*, maka compound tidak masuk akal.
            // Mari kita ubah `exit` untuk membayar semua reward yang belum diklaim.
            totalRewardsDistributed = totalRewardsDistributed.add(reward); // Perbarui totalRewardDistributed
            stakingToken.transfer(msg.sender, reward); // Bayar semua reward
            emit RewardPaid(msg.sender, reward, 0); // compoundAmount adalah 0 karena tidak ada compound
        }
    }

    // Fungsi untuk mengatur APY
    function setAPY(uint256 _newAPY) external onlyOwner {
        require(_newAPY >= 1000 && _newAPY <= 2000, "SmartBNBStaking: APY harus antara 10% (1000) dan 20% (2000)"); // 1000 = 10%, 2000 = 20%
        
        // Perbarui reward untuk address(0) untuk memastikan rewardPerTokenStored terbaru
        // Ini memastikan bahwa semua reward yang belum dibayar dihitung dengan APY lama sebelum perubahan
        _updateReward(address(0)); 
        
        uint256 oldAPY = APY;
        APY = _newAPY;
        emit APYUpdated(oldAPY, _newAPY); // Emit event dengan APY lama dan baru
    }

    // Fungsi untuk memulihkan token yang tidak sengaja terkirim ke kontrak
    function recoverTokens(address _tokenAddress, uint256 _amount) external onlyOwner {
        require(_tokenAddress != address(stakingToken), "SmartBNBStaking: Tidak dapat memulihkan token staking");
        require(_amount > 0, "SmartBNBStaking: Jumlah harus lebih dari nol");
        IERC20(_tokenAddress).transfer(owner(), _amount);
    }

    // Fungsi untuk mendapatkan informasi staking user
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
            APY, // APY saat ini
            staker.lastStakedTime
        );
    }
}
