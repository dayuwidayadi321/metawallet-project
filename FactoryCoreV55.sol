// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./CoreV55.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract CoreV55Factory {
    using Create2 for bytes32;

    event DefaultPaymasterUpdated(address indexed previousPaymaster, address indexed newPaymaster);
    event SupportedChainAdded(uint16 indexed chainId, bytes remoteAddress);
    event SupportedChainRemoved(uint16 indexed chainId);
    event WalletCreated(address indexed wallet, address[] owners, address guardian, address indexed creator);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    address public immutable ENTRY_POINT;
    address public immutable GAS_ORACLE;
    address public immutable LZ_ENDPOINT;
    address public owner;
    
    uint64 public constant DEFAULT_GUARDIAN_THRESHOLD = 1;
    uint64 public constant DEFAULT_RECOVERY_COOLDOWN = 3 days;
    uint256 public constant MAX_INITIAL_OWNERS = 10;

    mapping(address => bool) public isWalletFromFactory;
    address public defaultPaymaster;
    uint16[] public supportedChainIds;
    mapping(uint16 => bytes) public trustedRemotes;

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
        owner = msg.sender;

        for (uint256 i = 0; i < _initialChainIds.length; i++) {
            _addSupportedChain(_initialChainIds[i], _initialRemotes[i]);
        }
    }

    function createWallet(
        address[] memory initialOwners,
        address initialGuardian,
        bytes32 salt
    ) public returns (address wallet) {
        require(initialOwners.length > 0 && initialOwners.length <= MAX_INITIAL_OWNERS, "Invalid owners");
        require(initialGuardian != address(0), "Invalid guardian");
    
        // Fixed: Using alternative deployment method
        wallet = address(new CoreV55{salt: salt}(
            IEntryPoint(ENTRY_POINT),
            GAS_ORACLE
        ));
        
        bytes[] memory remotes = new bytes[](supportedChainIds.length);
        for (uint i = 0; i < supportedChainIds.length; i++) {
            remotes[i] = trustedRemotes[supportedChainIds[i]];
        }
        
        CoreV55(payable(wallet)).__CoreV55_init(
            initialOwners,
            initialGuardian,
            DEFAULT_GUARDIAN_THRESHOLD,
            DEFAULT_RECOVERY_COOLDOWN,
            LZ_ENDPOINT,
            supportedChainIds,
            remotes
        );
        
        if (defaultPaymaster != address(0)) {
            CoreV55(payable(wallet)).initializeForUserOp(
                IEntryPoint(ENTRY_POINT),
                defaultPaymaster
            );
        }
        
        isWalletFromFactory[wallet] = true;
        emit WalletCreated(wallet, initialOwners, initialGuardian, msg.sender);
    }

    function getExpectedAddress(
        address[] calldata initialOwners,
        address initialGuardian,
        bytes32 salt
    ) public view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(
                    abi.encodePacked(
                        type(CoreV55).creationCode,
                        abi.encode(IEntryPoint(ENTRY_POINT), GAS_ORACLE)
                    )
                )
            )
        );
        return address(uint160(uint256(hash)));
    }

    // Admin functions
    function setDefaultPaymaster(address newPaymaster) external onlyOwner {
        emit DefaultPaymasterUpdated(defaultPaymaster, newPaymaster);
        defaultPaymaster = newPaymaster;
    }

    function addSupportedChain(uint16 chainId, bytes memory remoteAddress) external onlyOwner {
        _addSupportedChain(chainId, remoteAddress);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
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

    // Internal functions
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

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}