// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "./CoreV55.sol";

contract BundlerWallet is CoreV55 {
    event BundledOpsExecuted(bytes32 bundleHash, uint256 opsCount);

    struct BundledOp {
        address to;
        uint256 value;
        bytes data;
    }

    // Constructor untuk menginisialisasi parent contract
    constructor(IEntryPoint _entryPoint, address _gasOracle) CoreV55(_entryPoint, _gasOracle) {}

    // Fungsi untuk inisialisasi bundler wallet
    function initializeBundler(
        address[] calldata owners,
        address guardian,
        uint64 threshold,
        bytes calldata lzConfig,
        IEntryPoint _entryPoint
    ) external initializer {
        // Decode LayerZero config
        (address lzEndpoint, uint16[] memory supportedChains, bytes[] memory trustedRemotes) = 
            abi.decode(lzConfig, (address, uint16[], bytes[]));
            
        // Panggil fungsi initialize dari parent contract
        __CoreV55_init(
            owners,
            guardian,
            threshold,
            1 days, // Default cooldown
            lzEndpoint,
            supportedChains,
            trustedRemotes
        );
        
        // Inisialisasi untuk UserOps
        initializeForUserOp(_entryPoint, address(0));
    }

    // Override validateUserOp untuk bundle support
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        BundledOp[] memory ops = abi.decode(userOp.callData[4:], (BundledOp[]));
        bytes32 bundleHash = keccak256(abi.encode(ops, block.chainid));
        
        require(
            _verifySignature(bundleHash, userOp.signature),
            "Invalid bundle signature"
        );

        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Gas payment failed");
        }
        return 0;
    }

    function executeBundledOps(BundledOp[] calldata ops) external onlyEntryPoint {
        for (uint i = 0; i < ops.length; i++) {
            (bool success, bytes memory result) = ops[i].to.call{
                value: ops[i].value
            }(ops[i].data);
            require(success, string(abi.encodePacked("Op failed: ", result)));
        }
        emit BundledOpsExecuted(keccak256(abi.encode(ops)), ops.length);
    }
}

/**
 * @title CoreV55Factory - Enhanced with Bundler Support
 * @dev Deploys both regular and BundlerWallet instances
 */
contract CoreV55Factory {
    address public immutable coreV55Implementation;
    address public immutable bundlerWalletImplementation;
    address public upgradeAdmin;
    IEntryPoint public entryPoint;
    
    // Tambahkan variabel VERSION
    uint16 public constant VERSION = 1;
    
    // Tambahkan event yang diperlukan
    event WalletCreated(address indexed proxy, bool isBundler, address[] owners);
    event UpgradePathRegistered(address indexed newImplementation, uint16 version, bool isBundler);

    constructor(
        address _coreV55Impl,
        address _bundlerImpl,
        IEntryPoint _entryPoint
    ) {
        coreV55Implementation = _coreV55Impl;
        bundlerWalletImplementation = _bundlerImpl;
        upgradeAdmin = msg.sender;
        entryPoint = _entryPoint;
    }

    // ======== Original CoreV55 Deployment ========
    function createWallet(
        address[] calldata owners,
        address guardian,
        uint64 threshold,
        uint64 recoveryCooldown,
        address lzEndpoint,
        uint16[] calldata supportedChains,
        bytes[] calldata trustedRemotes
    ) public returns (address) {
        require(owners.length > 0, "No owners");
        require(lzEndpoint != address(0), "Invalid LZ endpoint");
        
        ERC1967Proxy proxy = new ERC1967Proxy(
            coreV55Implementation,
            abi.encodeWithSelector(
                CoreV55.__CoreV55_init.selector,
                owners,
                guardian,
                threshold,
                recoveryCooldown,
                lzEndpoint,
                supportedChains,
                trustedRemotes
            )
        );
    
        // Auto-initialize for UserOps if called from EntryPoint
        if (msg.sender == address(entryPoint)) {
            CoreV55(payable(address(proxy))).initializeForUserOp(entryPoint, address(0));
        }
    
        emit WalletCreated(address(proxy), false, owners);
        return address(proxy);
    }

    // ======== Bundler-Specific Deployment ========
    function createBundlerWallet(
        address[] calldata owners,
        address guardian,
        uint64 threshold,
        bytes calldata lzConfig // [lzEndpoint, chainIds, remotes]
    ) public returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy(
            bundlerWalletImplementation,
            abi.encodeWithSelector(
                BundlerWallet.initializeBundler.selector,
                owners,
                guardian,
                threshold,
                lzConfig,
                entryPoint
            )
        );
        emit WalletCreated(address(proxy), true, owners);
        return address(proxy);
    }

    // ======== Batch Deployment ========
    function batchCreateWallets(
        address[][] calldata ownersList,
        address[] calldata guardians,
        uint64[] calldata thresholds,
        bool[] calldata isBundler,
        bytes[] calldata configs // [lzConfig|bundlerConfig]
    ) external returns (address[] memory) {
        require(ownersList.length == guardians.length, "Length mismatch");
        
        address[] memory wallets = new address[](ownersList.length);
        for (uint i = 0; i < ownersList.length; i++) {
            if (isBundler[i]) {
                wallets[i] = createBundlerWallet(
                    ownersList[i],
                    guardians[i],
                    thresholds[i],
                    configs[i]
                );
            } else {
                (address lzEndpoint, uint16[] memory chains, bytes[] memory remotes) = 
                    abi.decode(configs[i], (address, uint16[], bytes[]));
                
                wallets[i] = createWallet(
                    ownersList[i],
                    guardians[i],
                    thresholds[i],
                    1 days, // Default cooldown
                    lzEndpoint,
                    chains,
                    remotes
                );
            }
        }
        return wallets;
    }
    
    // ======== Upgrade Management ========
    function registerImplementation(
        address newImplementation,
        uint16 version,
        bool isBundler
    ) external onlyAdmin {
        require(version > VERSION, "Version must increase");
        
        bytes4 interfaceId = isBundler ? 
            type(BundlerWallet).interfaceId : 
            type(CoreV55).interfaceId;
        
        (bool success,) = newImplementation.staticcall(
            abi.encodeWithSignature("supportsInterface(bytes4)", interfaceId)
        );
        require(success, "Invalid implementation");
        
        emit UpgradePathRegistered(newImplementation, version, isBundler);
    }
    
    // ======== Admin Utilities ========
    function setEntryPoint(IEntryPoint _entryPoint) external onlyAdmin {
        entryPoint = _entryPoint;
    }
    
    function migrateWallet(
        address walletProxy,
        address newImplementation,
        bytes calldata migrationData
    ) external onlyAdmin {
        require(walletProxy != address(0), "Invalid wallet");
        
        (bool success,) = walletProxy.call(
            abi.encodeWithSelector(
                CoreV55.upgradeToAndCall.selector,
                newImplementation,
                migrationData
            )
        );
        require(success, "Migration failed");
    }
    
    // ======== Wallet Helpers ========
    function encodeLayerZeroConfig(
        address endpoint,
        uint16[] calldata chainIds,
        bytes[] calldata remotes
    ) external pure returns (bytes memory) {
        return abi.encode(endpoint, chainIds, remotes);
    }
    
    function getWalletBytecode(bool isBundler) external view returns (bytes memory) {
        return isBundler ? 
            type(BundlerWallet).creationCode : 
            type(CoreV55).creationCode;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == upgradeAdmin, "Unauthorized");
        _;
    }
}

TypeError: No arguments passed to the base constructor. Specify the arguments or mark "BundlerWallet" as abstract.
  --> FactoryCoreV55.sol:12:1:
   |
12 | contract BundlerWallet is CoreV55 {
   | ^ (Relevant source part starts here and spans across multiple lines).
Note: Base constructor parameters:
   --> CoreV55.sol:179:16:
    |
179 |     constructor(IEntryPoint _entryPoint, address _gasOracle) 
    |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TypeError: Member "__CoreV55_init" not found or not visible after argument-dependent lookup in type(contract CoreV55).
  --> FactoryCoreV55.sol:97:17:
   |
97 |                 CoreV55.__CoreV55_init.selector,
   |                 ^^^^^^^^^^^^^^^^^^^^^^

