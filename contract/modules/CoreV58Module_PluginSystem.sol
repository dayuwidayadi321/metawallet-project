// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/IERC165Upgradeable.sol";
import "./interface/IStorageCheck.sol";

/**
 * @title CoreV58Module_PluginSystem
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Modul 4 dari CoreV58: Sistem Plugin Modular
 */
abstract contract CoreV58Module_PluginSystem is Initializable, ReentrancyGuardUpgradeable {
    using AddressUpgradeable for address;

    /* ========== STRUCTS ========== */
    struct Plugin {
        address implementation;
        bytes4[] enabledSelectors;
        bool isWhitelisted;
        uint48 installTimestamp;
        bool isUninstalling;
    }

    /* ========== SHARED STATE ========== */
    mapping(bytes4 => address) public selectorToPlugin;
    mapping(address => Plugin) public installedPlugins;
    mapping(address => uint256) public pluginUninstallTimestamps;
    mapping(bytes32 => bool) public usedUninstallNonces;

    /* ========== CONSTANTS ========== */
    uint256 public constant MAX_PLUGIN_UNINSTALL_DELAY = 7 days;
    uint256 internal constant MAX_SELECTORS_PER_PLUGIN = 50;
    uint256 internal constant MAX_INIT_DATA_SIZE = 1024;
    uint256 internal constant MAX_PLUGIN_SIZE = 24576;
    uint256 internal constant MIN_PLUGIN_SIZE = 512;
    uint256 internal constant PLUGIN_GAS_LIMIT = 1_000_000;

    /* ========== CUSTOM ERRORS ========== */
    error PluginInitializationFailed(bytes revertData);
    error PluginUpgradeFailed(bytes revertReason);
    error PluginMigrationFailed();
    error PluginExecutionFailed();
    error InvalidPluginAddress();
    error SelectorAlreadyRegistered();
    error PluginSizeExceeded();
    error TooManySelectors();
    error InitDataTooLarge();
    error PluginNotInstalled();
    error UninstallAlreadyScheduled();
    error SelectorNotWhitelisted();
    error DangerousOpcodesDetected();
    error PluginPendingUninstall();
    error DuplicateSignature();
    error InsufficientGuardians();
    error NonExistentSelector(bytes4 selector);

    /* ========== EVENTS ========== */
    event PluginInstalled(address indexed plugin, bytes4[] selectors, bool whitelisted, address indexed installedBy);
    event PluginUninstallScheduled(address indexed plugin, uint256 uninstallTime, address indexed initiatedBy);
    event PluginForceUninstalled(address indexed plugin, address indexed executedBy, uint256 nonce);
    event PluginUpgraded(address indexed oldPlugin, address indexed newPlugin, address indexed upgradedBy);
    event PluginExecuted(address indexed plugin, bytes4 indexed selector, address indexed caller, uint256 value);
    event PluginInitialized(address indexed plugin, bool success, bytes result);
    event PluginStateMigrated(address indexed oldPlugin, address indexed newPlugin, bool success);

    /* ========== INITIALIZER ========== */
    /**
     * @dev Initializes the Plugin System module.
     */
    function __PluginSystemModule_init() internal virtual onlyInitializing {
        __ReentrancyGuard_init();
    }

    /* ========== EXTERNAL FUNCTIONS (Plugin Management) ========== */
    /**
     * @dev Installs a new plugin. Only owners can call this.
     * @param plugin The address of the plugin contract.
     * @param selectors Array of function selectors that this plugin will handle.
     * @param initData Optional initialization data to be passed to the plugin.
     * @param whitelist Whether to whitelist all selectors of this plugin (for direct call via fallback).
     */
    function installPlugin(
        address plugin,
        bytes4[] calldata selectors,
        bytes calldata initData,
        bool whitelist
    ) external virtual onlyOwner whenNotLocked {
        if (!plugin.isContract()) revert InvalidPluginAddress();
        if (selectors.length > MAX_SELECTORS_PER_PLUGIN) revert TooManySelectors();
        if (initData.length > MAX_INIT_DATA_SIZE) revert InitDataTooLarge();
        if (installedPlugins[plugin].installTimestamp > 0) revert PluginAlreadyInstalled(plugin);
        if (pluginUninstallTimestamps[plugin] > 0) revert PluginPendingUninstall();

        _validatePlugin(plugin, selectors);

        Plugin storage p = installedPlugins[plugin];
        p.implementation = plugin;
        p.enabledSelectors = selectors;
        p.isWhitelisted = whitelist;
        p.installTimestamp = uint48(block.timestamp);
        p.isUninstalling = false;

        for (uint256 i = 0; i < selectors.length; ) {
            if (selectorToPlugin[selectors[i]] != address(0)) revert SelectorAlreadyRegistered();
            selectorToPlugin[selectors[i]] = plugin;
            unchecked { ++i; }
        }

        if (initData.length > 0) {
            _initializePlugin(plugin, initData);
        }

        emit PluginInstalled(plugin, selectors, whitelist, msg.sender);
    }

    /**
     * @dev Schedules a plugin for uninstallation. Only owners can call this.
     * @param plugin The address of the plugin to uninstall.
     */
    function uninstallPlugin(address plugin) external virtual onlyOwner {
        if (installedPlugins[plugin].installTimestamp == 0) revert PluginNotInstalled();
        if (pluginUninstallTimestamps[plugin] > 0) revert UninstallAlreadyScheduled();

        installedPlugins[plugin].isUninstalling = true;
        pluginUninstallTimestamps[plugin] = block.timestamp + env.securityDelay; // Assuming env.securityDelay is accessible
        emit PluginUninstallScheduled(plugin, block.timestamp + env.securityDelay, msg.sender);
    }

    /**
     * @dev Forces the uninstallation of a plugin, bypassing the security delay, with guardian approval.
     * @param plugin The address of the plugin to force uninstall.
     * @param guardianSignatures Array of guardian signatures.
     * @param uninstallNonce A unique nonce for this uninstallation.
     * @param deadline The timestamp after which the signatures are no longer valid.
     */
    function forceUninstallPlugin(
        address plugin,
        bytes[] calldata guardianSignatures,
        uint256 uninstallNonce,
        uint256 deadline
    ) external virtual {
        if (block.timestamp > deadline) revert SignatureExpired(); // Assuming SignatureExpired error exists
        if (installedPlugins[plugin].installTimestamp == 0) revert PluginNotInstalled();

        bytes32 nonceKey = keccak256(abi.encodePacked(plugin, uninstallNonce));
        if (usedUninstallNonces[nonceKey]) revert NonceAlreadyUsed(); // Assuming NonceAlreadyUsed error exists
        usedUninstallNonces[nonceKey] = true;

        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("ForceUninstall(address plugin,uint256 nonce,uint256 deadline)"),
            plugin,
            uninstallNonce,
            deadline
        )));

        uint256 validSignatures;
        address[] memory seenGuardians = new address[](_getGuardianCount()); // Assuming _getGuardianCount() exists
        for (uint i = 0; i < guardianSignatures.length; ) {
            address signer = _verifySignature(hash, guardianSignatures[i]); // Assuming _verifySignature exists
            bool isDuplicate = false;
            for (uint j = 0; j < validSignatures; ) {
                if (seenGuardians[j] == signer) {
                    isDuplicate = true;
                    break;
                }
                unchecked { ++j; }
            }
            if (!isDuplicate && _isGuardian(signer)) { // Assuming _isGuardian exists
                seenGuardians[validSignatures] = signer;
                unchecked { ++validSignatures; }
                if (validSignatures >= _getGuardianThreshold()) break; // Assuming _getGuardianThreshold() exists
            }
            unchecked { ++i; }
        }

        if (validSignatures < _getGuardianThreshold()) revert InsufficientGuardians();

        _removePlugin(plugin);
        delete pluginUninstallTimestamps[plugin];
        emit PluginForceUninstalled(plugin, msg.sender, uninstallNonce);
    }

    /**
     * @dev Upgrades a plugin to a new implementation, optionally migrating state. Only owners can call this.
     * @param oldPlugin The address of the plugin to upgrade.
     * @param newPlugin The address of the new plugin implementation.
     * @param migrationData Optional calldata to be executed on the new plugin for state migration.
     */
    function upgradePlugin(
        address oldPlugin,
        address newPlugin,
        bytes calldata migrationData
    ) external virtual onlyOwner whenNotLocked {
        if (oldPlugin == newPlugin) revert PluginUpgradeFailed("Cannot upgrade to the same plugin");
        if (installedPlugins[oldPlugin].installTimestamp == 0) revert PluginNotInstalled();
        if (!newPlugin.isContract()) revert InvalidPluginAddress();
        if (pluginUninstallTimestamps[oldPlugin] > 0) revert PluginPendingUninstall();

        _validatePluginUpgrade(oldPlugin, newPlugin);

        if (IERC165Upgradeable(newPlugin).supportsInterface(type(IStorageCheck).interfaceId)) {
            if (!IStorageCheck(newPlugin).isStorageCompatible(oldPlugin)) {
                revert PluginUpgradeFailed("Storage layout mismatch");
            }
        }

        _migratePluginState(oldPlugin, newPlugin, migrationData);
        _updatePluginMappings(oldPlugin, newPlugin);
        _cleanupOldPlugin(oldPlugin);

        emit PluginUpgraded(oldPlugin, newPlugin, msg.sender);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    /**
     * @dev Validates basic properties of a plugin before installation.
     * @param plugin The address of the plugin.
     * @param selectors The function selectors the plugin intends to handle.
     */
    function _validatePlugin(address plugin, bytes4[] memory selectors) internal view virtual {
        bytes memory code = plugin.code;
        uint256 size = code.length;
        if (size < MIN_PLUGIN_SIZE || size > MAX_PLUGIN_SIZE) revert PluginSizeExceeded();

        for (uint256 i = 0; i < selectors.length; ) {
            bool selectorFound = false;
            for (uint256 j = 0; j < size - 3; ) {
                if (bytes4(code[j]) == selectors[i]) {
                    selectorFound = true;
                    break;
                }
                unchecked { ++j; }
            }
            if (!selectorFound) revert NonExistentSelector(selectors[i]);
            unchecked { ++i; }
        }

        // Detect dangerous opcodes (simplified check)
        bytes memory dangerousOpcodes = hex"f0f5ff"; // CREATE, CREATE2, SELFDESTRUCT
        if (_containsBytes(code, dangerousOpcodes)) revert DangerousOpcodesDetected();
    }

    /**
     * @dev Executes the initialization function of a plugin.
     * @param plugin The address of the plugin.
     * @param initData The initialization data.
     */
    function _initializePlugin(address plugin, bytes memory initData) internal virtual {
        (bool success, bytes memory result) = AddressUpgradeable.functionDelegateCall(plugin, initData);
        emit PluginInitialized(plugin, success, result);
        if (!success) revert PluginInitializationFailed(result);
    }

    /**
     * @dev Removes a plugin and its mappings.
     * @param plugin The address of the plugin to remove.
     */
    function _removePlugin(address plugin) internal virtual {
        Plugin storage p = installedPlugins[plugin];
        for (uint256 i = 0; i < p.enabledSelectors.length; ) {
            delete selectorToPlugin[p.enabledSelectors[i]];
            unchecked { ++i; }
        }
        delete installedPlugins[plugin];
        delete pluginUninstallTimestamps[plugin];
    }

    /**
     * @dev Validates the upgrade of a plugin.
     * @param oldPlugin The address of the old plugin.
     * @param newPlugin The address of the new plugin.
     */
    function _validatePluginUpgrade(address oldPlugin, address newPlugin) internal view virtual {
        bytes memory code = newPlugin.code;
        uint256 size = code.length;
        if (size < MIN_PLUGIN_SIZE || size > MAX_PLUGIN_SIZE) revert PluginSizeExceeded();
        // Potentially add more upgrade-specific checks
    }

    /**
     * @dev Migrates the state from an old plugin to a new plugin.
     * @param oldPlugin The address of the old plugin.
     * @param newPlugin The address of the new plugin.
     * @param migrationData The calldata for the migration function on the new plugin.
     */
    function _migratePluginState(address oldPlugin, address newPlugin, bytes memory migrationData) internal virtual {
        if (migrationData.length > 0) {
            (bool success, bytes memory result) = AddressUpgradeable.functionDelegateCall(newPlugin, migrationData);
            emit PluginStateMigrated(oldPlugin, newPlugin, success);
            if (!success) revert PluginMigrationFailed(); // Revert data not propagated for simplicity
        }
    }

    /**
     * @dev Updates the selector to plugin mappings after an upgrade.
     * @param oldPlugin The address of the old plugin.
     * @param newPlugin The address of the new plugin.
     */
    function _updatePluginMappings(address oldPlugin, address newPlugin) internal virtual {
        Plugin storage oldP = installedPlugins[oldPlugin];
        Plugin storage newP = installedPlugins[newPlugin];
        newP.implementation = newPlugin;
        newP.enabledSelectors = oldP.enabledSelectors;
        newP.isWhitelisted = oldP.isWhitelisted;
        newP.installTimestamp = uint48(block.timestamp);
        newP.isUninstalling = false;

        for (uint256 i = 0; i < oldP.enabledSelectors.length; ) {
            selectorToPlugin[oldP.enabledSelectors[i]] = newPlugin;
            unchecked { ++i; }
        }
    }

    /**
     * @dev Cleans up the storage associated with the old plugin after an upgrade.
     * @param oldPlugin The address of the old plugin.
     */
    function _cleanupOldPlugin(address oldPlugin) internal virtual {
        delete installedPlugins[oldPlugin];
    }

    /**
     * @dev Executes a plugin function via delegatecall.
     * @param plugin The address of the plugin to call.
     * @param data The calldata to pass to the plugin.
     */
    function _executePlugin(address plugin, bytes memory data) internal nonReentrant {
        Plugin storage p = installedPlugins[plugin];
        if (p.installTimestamp == 0) revert PluginNotInstalled();
        if (p.isUninstalling || pluginUninstallTimestamps[plugin] > 0) revert PluginPendingUninstall();

        bytes4 selector = bytes4(data[:4]);
        bool allowed = false;
        for (uint256 i = 0; i < p.enabledSelectors.length; ) {
            if (p.enabledSelectors[i] == selector) {
                allowed = true;
                break;
            }
            unchecked { ++i; }
        }
        if (!allowed) revert SelectorNotWhitelisted();

        (bool success, bytes memory result) = AddressUpgradeable.functionDelegateCall(plugin, data);
        emit PluginExecuted(plugin, selector, msg.sender, msg.value);
        if (!success) {
            if (result.length > 0) {
                assembly { revert(add(result, 32), mload(result)) }
            }
            revert PluginExecutionFailed();
        }
    }

    /**
     * @dev Handles the fallback call, delegating execution to the registered plugin if a selector matches.
     */
    function _executePluginFallback() internal virtual nonReentrant {
        address plugin = selectorToPlugin[msg.sig];
        if (plugin == address(0)) revert NonExistentSelector(msg.sig);
        _executePlugin(plugin, msg.data);
    }

    /**
     * @dev Internal helper function to check if a byte sequence contains any of the patterns.
     * @param data The byte sequence to check.
     * @param patterns The byte patterns to search for.
     * @return True if any pattern is found, false otherwise.
     */
    function _containsBytes(bytes memory data, bytes memory patterns) internal pure returns (bool) {
        for (uint256 i = 0; i <= data.length - patterns.length; ) {
            bool match = true;
            for (uint256 j = 0; j < patterns.length; ) {
                if (data[i + j] != patterns[j]) {
                    match = false;
                    break;
                }
                unchecked { ++j; }
            }
            if (match) return true;
            unchecked { ++i; }
        }
        return false;
    }

    /* ========== EXTERNAL VIEW FUNCTIONS ========== */
    /**
     * @dev Returns the implementation address of a given plugin.
     * @param plugin The address of the plugin.
     * @return The implementation address, or address(0) if not installed.
     */
    function getPluginImplementation(address plugin) external view virtual returns (address) {
        return installedPlugins[plugin].implementation;
    }

    /**
     * @dev Returns the list of enabled selectors for a given plugin.
     * @param plugin The address of the plugin.
     * @return An array of function selectors.
     */
    function getPluginSelectors(address plugin) external view virtual returns (bytes4[] memory) {
        return installedPlugins[plugin].enabledSelectors;
    }

    /**
     * @dev Checks if a selector is handled by any installed plugin.
     * @param selector The function selector to check.
     * @return The address of the plugin handling the selector, or address(0) if none.
     */
    function getPluginForSelector(bytes4 selector) external view virtual returns (address) {
        return selectorToPlugin[selector];
    }

    /**
     * @dev Checks if a plugin is whitelisted for direct fallback calls.
     * @param plugin The address of the plugin.
     * @return True if whitelisted, false otherwise.
     */
    function isPluginWhitelisted(address plugin) external view virtual returns (bool) {
        return installedPlugins[plugin].isWhitelisted;
    }

    /**
     * @dev Returns the timestamp when a plugin was installed.
     * @param plugin The address of the plugin.
     * @return The installation timestamp, or 0 if not installed.
     */
    function getPluginInstallTimestamp(address plugin) external view virtual returns (uint256) {
        return uint256(installedPlugins[plugin].installTimestamp);
    }

    /**
     * @dev Returns the scheduled uninstallation timestamp for a plugin.
     * @param plugin The address of the plugin.
     * @return The uninstallation timestamp, or 0 if not scheduled.
     */
    function getPluginUninstallTimestamp(address plugin) external view virtual returns (uint256) {
        return pluginUninstallTimestamps[plugin];
    }

    /**
     * @dev Checks if a plugin is currently in the process of being uninstalled.
     * @param plugin The address of the plugin.
     * @return True if uninstalling, false otherwise.
     */
    function isPluginUninstalling(address plugin) external view virtual returns (bool) {
        return installedPlugins[plugin].isUninstalling;
    }
}
