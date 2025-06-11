// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20VotesUpgradeable.sol";

contract SafeHaven is 
    ERC20Upgradeable, 
    OwnableUpgradeable, 
    PausableUpgradeable, 
    UUPSUpgradeable,
    ERC20PermitUpgradeable,
    ERC20VotesUpgradeable 
{
    using SafeMathUpgradeable for uint256;
    using CountersUpgradeable for CountersUpgradeable.Counter;

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
    mapping(address => CountersUpgradeable.Counter) private _stakeIds;
    
    uint256 public stakingRewardRate;
    uint256 public totalStakedAmount;
    uint256 public constant SECONDS_IN_DAY = 86400;

    // Cross-chain support
    uint256 public chainId;
    mapping(uint256 => address) public bridgeContracts; // chainId => bridge contract address
    mapping(address => bool) public isBridgeContract;
    mapping(address => uint256) public nonces; // For cross-chain transactions

    string public constant CONTRACT_VERSION = "7.0-multichain"; 

    event TokenIconUriUpdated(string newUri);
    event FeeBasisPointsUpdated(uint256 newBurnFee, uint256 newStakingFee);
    event TokensBurned(address indexed burner, uint256 amount);
    event Staked(address indexed user, uint256 stakeId, uint256 amount, uint256 startTime);
    event Unstaked(address indexed user, uint256 stakeId, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 stakeId, uint256 amount);
    event StakingPoolFunded(uint256 amount);
    event BridgeContractUpdated(uint256 chainId, address bridgeAddress);
    event TokensLocked(address indexed sender, uint256 amount, uint256 targetChainId);
    event TokensUnlocked(address indexed recipient, uint256 amount, uint256 sourceChainId);

    function initialize(address ownerAddress, uint256 initialSupply, uint256 _chainId) public initializer {
        __ERC20_init("Safe Haven Coin", "BURN");
        __Ownable_init(ownerAddress);
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ERC20Permit_init("Safe Haven Coin");
        __ERC20Votes_init();

        _burnFeeBasisPoints = 10;
        _stakingPoolFeeBasisPoints = 10;
        
        stakingRewardRate = 100000000000000000;
        totalStakedAmount = 0;
        chainId = _chainId;

        _mint(ownerAddress, initialSupply);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // Overrides required by Solidity for ERC20Votes
    function _afterTokenTransfer(address from, address to, uint256 amount)
        internal
        override(ERC20Upgradeable, ERC20VotesUpgradeable)
    {
        super._afterTokenTransfer(from, to, amount);
    }

    function _mint(address to, uint256 amount)
        internal
        override(ERC20Upgradeable, ERC20VotesUpgradeable)
    {
        super._mint(to, amount);
    }

    function _burn(address account, uint256 amount)
        internal
        override(ERC20Upgradeable, ERC20VotesUpgradeable)
    {
        super._burn(account, amount);
    }

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
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

    // Cross-chain functions
    function lockTokens(uint256 amount, uint256 targetChainId) external whenNotPaused {
        require(bridgeContracts[targetChainId] != address(0), "No bridge configured for target chain");
        require(amount > 0, "Amount must be greater than zero");
        
        _burn(_msgSender(), amount);
        nonces[_msgSender()]++;
        
        emit TokensLocked(_msgSender(), amount, targetChainId);
    }

    function unlockTokens(address recipient, uint256 amount, uint256 sourceChainId, bytes calldata signature) external whenNotPaused {
        require(isBridgeContract[msg.sender], "Only bridge can unlock tokens");
        require(amount > 0, "Amount must be greater than zero");
        
        _mint(recipient, amount);
        
        emit TokensUnlocked(recipient, amount, sourceChainId);
    }

    function setBridgeContract(uint256 _chainId, address _bridgeContract) external onlyOwner {
        require(_chainId != chainId, "Cannot set bridge for current chain");
        bridgeContracts[_chainId] = _bridgeContract;
        isBridgeContract[_bridgeContract] = true;
        
        emit BridgeContractUpdated(_chainId, _bridgeContract);
    }

    // Existing functions (unchanged except where noted)
    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function burn(uint256 amount) public {
        _burn(_msgSender(), amount);
        emit TokensBurned(_msgSender(), amount);
    }

    function burnFrom(address account, uint256 amount) public {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance.sub(amount));
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