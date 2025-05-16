// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";

/**
 * @title CoreV58Module_Ownership
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Modul 1 dari CoreV58: Manajemen Kepemilikan dan Kontrol Akses Dasar
 */
abstract contract CoreV58Module_Ownership is Initializable {
    using AddressUpgradeable for address;
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    /* ========== SHARED STATE (Internal) ========== */
    EnumerableSetUpgradeable.AddressSet private _owners;

    /* ========== IMMUTABLES (Set saat inisialisasi) ========== */
    address public immutable self;

    /* ========== EVENTS ========== */
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);

    /* ========== MODIFIERS ========== */
    /**
     * @dev Modifier untuk membatasi akses hanya kepada pemilik.
     */
    modifier onlyOwner() virtual {
        require(_owners.contains(msg.sender), "Unauthorized: Not owner");
        _;
    }

    /* ========== INITIALIZER ========== */
    /**
     * @dev Initializes the ownership module with the initial set of owners.
     * @param initialOwners Array of initial owner addresses.
     */
    function __OwnershipModule_init(address[] memory initialOwners) internal virtual onlyInitializing {
        require(initialOwners.length > 0, "No owners provided");
        self = address(this); // Set immutable self pada inisialisasi modul

        for (uint256 i = 0; i < initialOwners.length; i++) {
            require(initialOwners[i] != address(0), "Invalid owner address");
            _owners.add(initialOwners[i]);
            emit OwnerAdded(initialOwners[i]);
        }
    }

    /* ========== EXTERNAL FUNCTIONS (Manajemen Pemilik) ========== */
    /**
     * @dev Adds a new owner to the wallet. Only existing owners can call this function.
     * @param newOwner The address of the new owner to add.
     */
    function addOwner(address newOwner) external virtual onlyOwner {
        require(newOwner != address(0), "Invalid owner address");
        require(!_owners.contains(newOwner), "Address is already an owner");
        _owners.add(newOwner);
        emit OwnerAdded(newOwner);
    }

    /**
     * @dev Removes an owner from the wallet. Only existing owners can call this function.
     * @param ownerToRemove The address of the owner to remove.
     */
    function removeOwner(address ownerToRemove) external virtual onlyOwner {
        require(_owners.contains(ownerToRemove), "Address is not an owner");
        require(_owners.length() > 1, "Cannot remove the last owner");
        _owners.remove(ownerToRemove);
        emit OwnerRemoved(ownerToRemove);
    }

    /* ========== VIEW FUNCTIONS ========== */
    /**
     * @dev Returns the list of current owners.
     * @return An array of owner addresses.
     */
    function getOwners() external view virtual returns (address[] memory) {
        uint256 length = _owners.length();
        address[] memory result = new address[](length);
        for (uint256 i = 0; i < length; ) {
            result[i] = _owners.at(i);
            unchecked { ++i; }
        }
        return result;
    }

    /**
     * @dev Checks if a given address is an owner.
     * @param account The address to check.
     * @return True if the address is an owner, false otherwise.
     */
    function isOwner(address account) external view virtual returns (bool) {
        return _owners.contains(account);
    }
}
