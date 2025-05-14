// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

abstract contract PluginManager is EIP712Upgradeable, ReentrancyGuardUpgradeable, OwnableUpgradeable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
    using AddressUpgradeable for address;

    struct Plugin {
        address implementation;
        bytes4[] enabledSelectors;
        bool isWhitelisted;
        uint48 installTimestamp;
        uint48 lastUpdated;
    }

    struct PluginSystem {
        bool reentrancyLock;
        mapping(bytes4 => address) selectorToPlugin;
        mapping(address => Plugin) installedPlugins;
        mapping(address => uint256) pluginUninstallTimestamps;
        mapping(bytes32 => bool) usedUninstallNonces;
    }

    PluginSystem private _pluginSystem;
    EnumerableSetUpgradeable.AddressSet private _installedPluginAddresses;

    // Events
    event PluginInstalled(address indexed plugin, bytes4[] selectors, bool whitelisted, address indexed installedBy);
    event PluginUninstallScheduled(address indexed plugin, uint256 uninstallTime, address indexed initiatedBy);
    event PluginForceUninstalled(address indexed plugin, address indexed executedBy, uint256 nonce);
    event PluginUpgraded(address indexed oldPlugin, address indexed newPlugin, address indexed upgradedBy);
    event PluginExecuted(address indexed plugin, bytes4 indexed selector, address indexed caller, uint256 value);
    event PluginInitialized(address indexed plugin, bool success, bytes result);
    event PluginWhitelistUpdated(address indexed plugin, bool isWhitelisted);
    event PluginSelectorAdded(address indexed plugin, bytes4 selector);
    event PluginSelectorRemoved(address indexed plugin, bytes4 selector);

    // Errors
    error PluginUpgradeFailed(bytes revertReason);
    error PluginInitializationFailed();
    error PluginMigrationFailed();
    error PluginExecutionFailed();
    error InvalidPluginAddress();
    error SelectorAlreadyRegistered(bytes4 selector);
    error PluginSizeExceeded(uint256 size);
    error PluginNotInstalled(address plugin);
    error PluginPendingUninstall(address plugin);
    error InvalidSelector(bytes4 selector);
    error DangerousOpcodeDetected(bytes4 opcode);
    error CallerNotOwner(address caller);
    error ContractIsLocked();

    // Constants
    uint256 public constant MAX_PLUGIN_SIZE = 24_576; // 24KB
    uint256 public constant MIN_PLUGIN_SIZE = 512; // 0.5KB
    uint256 public constant MAX_INIT_DATA_SIZE = 1024; // 1KB
    uint256 public constant MAX_SELECTORS_PER_PLUGIN = 50;
    uint256 public constant PLUGIN_EXECUTION_GAS_LIMIT = 1_000_000;

    // State variables
    bool public isLocked;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function __PluginManager_init() internal onlyInitializing {
        __EIP712_init("CoreV55", "5.5");
        __ReentrancyGuard_init();
        __Ownable_init();
    }

    modifier whenNotLocked() {
        if (isLocked) revert ContractIsLocked();
        _;
    }

    /**
     * @dev Install a new plugin
     */
    function installPlugin(
        address plugin,
        bytes4[] calldata selectors,
        bytes calldata initData,
        bool whitelist
    ) external virtual onlyOwner whenNotLocked nonReentrant {
        if (selectors.length > MAX_SELECTORS_PER_PLUGIN) revert("Too many selectors");
        _beforePluginInstall(plugin, selectors);
        _validatePlugin(plugin, selectors);
        
        if (_pluginSystem.pluginUninstallTimestamps[plugin] != 0) {
            revert PluginPendingUninstall(plugin);
        }
    
        Plugin storage p = _pluginSystem.installedPlugins[plugin];
        p.implementation = plugin;
        p.enabledSelectors = selectors;
        p.isWhitelisted = whitelist;
        p.installTimestamp = uint48(block.timestamp);
        p.lastUpdated = uint48(block.timestamp);
        
        _installedPluginAddresses.add(plugin);
    
        for (uint256 i = 0; i < selectors.length; ) {
            bytes4 selector = selectors[i];
            if (_pluginSystem.selectorToPlugin[selector] != address(0)) {
                revert SelectorAlreadyRegistered(selector);
            }
            _pluginSystem.selectorToPlugin[selector] = plugin;
            emit PluginSelectorAdded(plugin, selector);
            unchecked { ++i; }
        }
    
        if (initData.length > 0) {
            _initializePlugin(plugin, initData);
        }
    
        emit PluginInstalled(plugin, selectors, whitelist, msg.sender);
        _afterPluginInstall(plugin);
    }

    /**
     * @dev Uninstall a plugin after security delay
     */
    function uninstallPlugin(address plugin) external virtual onlyOwner {
        if (_pluginSystem.installedPlugins[plugin].installTimestamp == 0) {
            revert PluginNotInstalled(plugin);
        }
        if (_pluginSystem.pluginUninstallTimestamps[plugin] != 0) {
            revert PluginPendingUninstall(plugin);
        }
        
        _pluginSystem.pluginUninstallTimestamps[plugin] = block.timestamp + env.securityDelay;
        emit PluginUninstallScheduled(plugin, block.timestamp + env.securityDelay, msg.sender);
    }

    /**
     * @dev Force uninstall a plugin with guardian approval
     */
    function forceUninstallPlugin(
        address plugin,
        bytes[] calldata guardianSignatures,
        uint256 uninstallNonce,
        uint256 deadline
    ) external virtual nonReentrant {
        if (block.timestamp > deadline) revert("Signature expired");
        if (_pluginSystem.installedPlugins[plugin].installTimestamp == 0) {
            revert PluginNotInstalled(plugin);
        }
    
        bytes32 nonceKey = keccak256(abi.encodePacked(plugin, uninstallNonce));
        if (_pluginSystem.usedUninstallNonces[nonceKey]) revert("Nonce used");
        _pluginSystem.usedUninstallNonces[nonceKey] = true;
    
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("ForceUninstall(address plugin,uint256 nonce,uint256 deadline)"),
            plugin,
            uninstallNonce,
            deadline
        )));
    
        uint256 validSignatures = _verifyGuardianSignatures(hash, guardianSignatures);
        if (validSignatures < _guardianConfig.threshold) {
            revert("Insufficient guardians");
        }
    
        _removePlugin(plugin);
        delete _pluginSystem.pluginUninstallTimestamps[plugin];
        emit PluginForceUninstalled(plugin, msg.sender, uninstallNonce);
    }

    /**
     * @dev Upgrade a plugin to new version
     */
    function upgradePlugin(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) external virtual onlyOwner nonReentrant {
        _validatePluginUpgrade(oldPlugin, newPlugin);
        
        (bool success, bytes memory result) = address(this).call{gas: PLUGIN_EXECUTION_GAS_LIMIT}(
            abi.encodeWithSelector(
                this.externalMigratePluginState.selector,
                oldPlugin,
                newPlugin,
                migrationData
            )
        );
        
        if (!success) {
            revert PluginUpgradeFailed(result);
        }
        
        _updatePluginMappings(oldPlugin, newPlugin);
        _cleanupOldPlugin(oldPlugin);
        emit PluginUpgraded(oldPlugin, newPlugin, msg.sender);
    }
    
    /**
     * @dev External function for plugin state migration
     */
    function externalMigratePluginState(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) external {
        if (msg.sender != address(this)) revert("Internal only");
        if (oldPlugin == address(0)) revert InvalidPluginAddress();
        _migratePluginState(oldPlugin, newPlugin, migrationData);
    }

    /**
     * @dev Update plugin whitelist status
     */
    function setPluginWhitelist(address plugin, bool isWhitelisted) external onlyOwner {
        if (_pluginSystem.installedPlugins[plugin].installTimestamp == 0) {
            revert PluginNotInstalled(plugin);
        }
        _pluginSystem.installedPlugins[plugin].isWhitelisted = isWhitelisted;
        _pluginSystem.installedPlugins[plugin].lastUpdated = uint48(block.timestamp);
        emit PluginWhitelistUpdated(plugin, isWhitelisted);
    }

    /**
     * @dev Get all installed plugin addresses
     */
    function getAllPlugins() external view returns (address[] memory) {
        return _installedPluginAddresses.values();
    }

    // ================== INTERNAL FUNCTIONS ================== //

    function _validatePlugin(address plugin, bytes4[] calldata selectors) internal view {
        if (!plugin.isContract()) revert InvalidPluginAddress();
        
        uint256 size;
        assembly { size := extcodesize(plugin) }
        if (size < MIN_PLUGIN_SIZE || size > MAX_PLUGIN_SIZE) {
            revert PluginSizeExceeded(size);
        }
        
        bytes memory code = plugin.code;
        bytes4[3] memory dangerousOpcodes = [hex"f0", hex"f5", hex"ff"];
        for (uint i = 0; i < dangerousOpcodes.length; i++) {
            if (_containsBytes(code, dangerousOpcodes[i])) {
                revert DangerousOpcodeDetected(dangerousOpcodes[i]);
            }
        }

        for (uint i = 0; i < selectors.length; i++) {
            if (selectors[i] == bytes4(0)) {
                revert InvalidSelector(selectors[i]);
            }
        }
    }

    function _initializePlugin(address plugin, bytes calldata initData) internal {
        if (initData.length > MAX_INIT_DATA_SIZE) revert("Init data too large");
        
        uint256 gasBefore = gasleft();
        (bool success, bytes memory result) = plugin.delegatecall(initData);
        if (gasBefore - gasleft() > PLUGIN_EXECUTION_GAS_LIMIT) {
            revert("Initialization gas too high");
        }
        
        emit PluginInitialized(plugin, success, result);
        if (!success) {
            if (result.length > 0) {
                assembly { revert(add(result, 32), mload(result)) }
            }
            revert PluginInitializationFailed();
        }
    }

    function _removePlugin(address plugin) internal {
        bytes4[] memory selectors = _pluginSystem.installedPlugins[plugin].enabledSelectors;
        
        for (uint i = 0; i < selectors.length; ) {
            delete _pluginSystem.selectorToPlugin[selectors[i]];
            emit PluginSelectorRemoved(plugin, selectors[i]);
            unchecked { ++i; }
        }
        
        delete _pluginSystem.installedPlugins[plugin];
        _installedPluginAddresses.remove(plugin);
    }
  
    function _validatePluginUpgrade(
        address oldPlugin,
        address newPlugin
    ) internal view virtual {
        require(newPlugin.code.length > 0, "Invalid plugin");
        require(
            _pluginSystem.installedPlugins[oldPlugin].installTimestamp > 0,
            "Plugin not installed"
        );
        require(oldPlugin != newPlugin, "Cannot upgrade to same plugin");
        require(
            _pluginSystem.pluginUninstallTimestamps[oldPlugin] == 0,
            "Plugin pending uninstall"
        );
        
        // Validasi ukuran plugin baru
        uint256 size;
        assembly {
            size := extcodesize(newPlugin)
        }
        require(size > 0 && size < 24576, "Invalid new plugin size");
    }
    
    function _migratePluginState(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) internal virtual {
        if (migrationData.length > 0) {
            require(migrationData.length <= 1024, "Migration data too large");
            
            uint256 gasBefore = gasleft();
            (bool success, bytes memory result) = newPlugin.delegatecall(migrationData);
            require(gasBefore - gasleft() < 1_000_000, "Migration used too much gas");
            
            if (!success) {
                if (result.length > 0) {
                    assembly {
                        revert(add(result, 32), mload(result))
                    }
                }
                revert PluginMigrationFailed();
            }
        }
    }
    
    function _updatePluginMappings(
        address oldPlugin,
        address newPlugin
    ) internal virtual {
        Plugin storage oldData = _pluginSystem.installedPlugins[oldPlugin];
        bytes4[] memory selectors = oldData.enabledSelectors;
        
        _pluginSystem.installedPlugins[newPlugin] = Plugin({
            implementation: newPlugin,
            enabledSelectors: selectors,
            isWhitelisted: oldData.isWhitelisted,
            installTimestamp: uint48(block.timestamp)
        });
    
        for (uint256 i = 0; i < selectors.length; ) {
            _pluginSystem.selectorToPlugin[selectors[i]] = newPlugin;
            unchecked { ++i; }
        }
    }
    
    function _cleanupOldPlugin(address oldPlugin) internal virtual {
        delete _pluginSystem.installedPlugins[oldPlugin];
    }
    
    function _executePlugin(address plugin, bytes calldata data) internal {
        require(!_pluginSystem.reentrancyLock, "Reentrancy detected");
        _pluginSystem.reentrancyLock = true;
        
        // Pertama cek dengan staticcall
        (bool safe, ) = plugin.staticcall(data);
        require(safe, "Plugin pre-check failed");
    
        // Jika aman, lanjut delegatecall
        (bool success, bytes memory result) = plugin.delegatecall(data);
        
        _pluginSystem.reentrancyLock = false;
        
        if (!success) {
            if (result.length > 0) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            revert("Plugin execution failed");
        }
    }
}    

