// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CoreV55.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract CoreV55Factory {
    using Create2 for bytes32;

    // ========== CONSTANTS ==========
    address public immutable ENTRY_POINT;
    address public immutable GAS_ORACLE;
    address public immutable LZ_ENDPOINT;
    uint64 public constant DEFAULT_GUARDIAN_THRESHOLD = 1;
    uint64 public constant DEFAULT_RECOVERY_COOLDOWN = 3 days;
    uint256 public constant MAX_INITIAL_OWNERS = 10;

    // ========== STORAGE ==========
    mapping(address => bool) public isWalletFromFactory;
    address public defaultPaymaster;
    uint16[] public supportedChainIds;
    mapping(uint16 => bytes) public trustedRemotes;

    // ========== EVENTS ==========
    event WalletCreated(
        address indexed wallet,
        address[] owners,
        address guardian,
        address indexed creator
    );
    event DefaultPaymasterUpdated(address oldPaymaster, address newPaymaster);
    event SupportedChainAdded(uint16 chainId, bytes remoteAddress);
    event SupportedChainRemoved(uint16 chainId);

    // ========== CONSTRUCTOR ==========
    constructor(
        IEntryPoint _entryPoint,
        address _gasOracle,
        address _lzEndpoint,
        uint16[] memory _initialChainIds,
        bytes[] memory _initialRemotes
    ) {
        require(address(_entryPoint) != address(0), "Invalid EntryPoint");
        require(_gasOracle != address(0), "Invalid GasOracle");
        require(_lzEndpoint != address(0), "Invalid LZEndpoint");
        require(_initialChainIds.length == _initialRemotes.length, "Mismatched chain config");

        ENTRY_POINT = address(_entryPoint);
        GAS_ORACLE = _gasOracle;
        LZ_ENDPOINT = _lzEndpoint;

        for (uint256 i = 0; i < _initialChainIds.length; i++) {
            _addSupportedChain(_initialChainIds[i], _initialRemotes[i]);
        }
    }

    // ========== MAIN FUNCTIONS ==========

    /**
     * @notice Deploy a new CoreV55 wallet with CREATE2
     * @param initialOwners Array of initial owners
     * @param initialGuardian Initial guardian address
     * @param salt Salt for CREATE2 deployment
     */
    function createWallet(
        address[] memory initialOwners,
        address initialGuardian,
        bytes32 salt
    ) public returns (address wallet) {
        require(initialOwners.length > 0, "No owners provided");
        require(initialOwners.length <= MAX_INITIAL_OWNERS, "Too many owners");
        require(initialGuardian != address(0), "Invalid guardian");
    
        // Encode the constructor arguments
        bytes memory constructorArgs = abi.encode(
            IEntryPoint(ENTRY_POINT),
            GAS_ORACLE
        );
    
        // Dapatkan bytecode dari CoreV55 (tanpa constructor args)
        bytes memory bytecode = abi.encodePacked(
            type(CoreV55).creationCode,
            constructorArgs
        );
    
        // Deploy dengan CREATE2
        wallet = Create2.deploy(0, salt, bytecode);
    
        // Encode initialization data
        bytes memory initData = abi.encodeWithSelector(
            CoreV55.__CoreV55_init.selector,
            initialOwners,
            initialGuardian,
            DEFAULT_GUARDIAN_THRESHOLD,
            DEFAULT_RECOVERY_COOLDOWN,
            LZ_ENDPOINT,
            supportedChainIds,
            _getTrustedRemotes()
        );
    
        // Initialize the wallet
        (bool success, ) = wallet.call(initData);
        require(success, "Initialization failed");
    
        // Set paymaster if configured
        if (defaultPaymaster != address(0)) {
            CoreV55(payable(wallet)).initializeForUserOp(
                IEntryPoint(ENTRY_POINT),
                defaultPaymaster
            );
        }
    
        isWalletFromFactory[wallet] = true;
        emit WalletCreated(wallet, initialOwners, initialGuardian, msg.sender);
    }
    
    function predictWalletAddress(
        address[] memory initialOwners,
        address initialGuardian,
        bytes32 salt
    ) public view returns (address) {
        bytes memory constructorArgs = abi.encode(
            IEntryPoint(ENTRY_POINT),
            GAS_ORACLE
        );
    
        bytes memory bytecode = abi.encodePacked(
            type(CoreV55).creationCode,
            constructorArgs
        );
    
        return Create2.computeAddress(salt, keccak256(bytecode), address(this));
    }

    // ========== ADMIN FUNCTIONS ==========

    function setDefaultPaymaster(address newPaymaster) external {
        require(msg.sender == address(ENTRY_POINT), "Only EntryPoint can set paymaster");
        emit DefaultPaymasterUpdated(defaultPaymaster, newPaymaster);
        defaultPaymaster = newPaymaster;
    }

    function addSupportedChain(uint16 chainId, bytes memory remoteAddress) external {
        require(msg.sender == address(ENTRY_POINT), "Only EntryPoint can add chains");
        _addSupportedChain(chainId, remoteAddress);
    }

    function removeSupportedChain(uint16 chainId) external {
        require(msg.sender == address(ENTRY_POINT), "Only EntryPoint can remove chains");
        require(trustedRemotes[chainId].length != 0, "Chain not supported");
        
        delete trustedRemotes[chainId];
        for (uint256 i = 0; i < supportedChainIds.length; i++) {
            if (supportedChainIds[i] == chainId) {
                supportedChainIds[i] = supportedChainIds[supportedChainIds.length - 1];
                supportedChainIds.pop();
                break;
            }
        }
        
        emit SupportedChainRemoved(chainId);
    }

    // ========== INTERNAL FUNCTIONS ==========

    function _addSupportedChain(uint16 chainId, bytes memory remoteAddress) internal {
        require(chainId != 0, "Invalid chainId");
        require(remoteAddress.length > 0, "Invalid remote address");
        require(trustedRemotes[chainId].length == 0, "Chain already supported");

        trustedRemotes[chainId] = remoteAddress;
        supportedChainIds.push(chainId);
        emit SupportedChainAdded(chainId, remoteAddress);
    }

    function _getTrustedRemotes() internal view returns (bytes[] memory) {
        bytes[] memory remotes = new bytes[](supportedChainIds.length);
        for (uint256 i = 0; i < supportedChainIds.length; i++) {
            remotes[i] = trustedRemotes[supportedChainIds[i]];
        }
        return remotes;
    }
}

