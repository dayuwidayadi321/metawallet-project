// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title EIP-1967 Upgradeable Proxy
/// @notice Proxy contract dengan standar penyimpanan dan keamanan yang sesuai EIP-1967

contract EIP1967Proxy {
    /// @dev Slot untuk alamat kontrak implementasi (EIP-1967)
    bytes32 internal constant _IMPLEMENTATION_SLOT = 
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Slot untuk alamat admin (EIP-1967)
    bytes32 internal constant _ADMIN_SLOT = 
        0xb53127684a568b3173ae13b9f8a6016e019ccc4ac29f4b5bdfc0b7c7c5abf3af;

    /// @notice Event saat implementasi di-upgrade
    event Upgraded(address indexed newImplementation);

    /// @notice Event saat admin diganti
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    /// @param _implementation Alamat kontrak implementasi awal
    constructor(address _implementation) {
        require(_implementation.code.length > 0, "Bukan contract");
        assembly {
            sstore(_IMPLEMENTATION_SLOT, _implementation)
            sstore(_ADMIN_SLOT, caller())
        }
    }

    /// @dev Modifier untuk membatasi akses hanya untuk admin
    modifier onlyAdmin() {
        address admin;
        assembly {
            admin := sload(_ADMIN_SLOT)
        }
        require(msg.sender == admin, "Anda bukan admin");
        _;
    }

    /// @notice Upgrade ke kontrak implementasi baru
    /// @param _newImplementation Alamat kontrak baru
    function upgrade(address _newImplementation) external onlyAdmin {
        require(_newImplementation.code.length > 0, "Bukan contract");
        assembly {
            sstore(_IMPLEMENTATION_SLOT, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    /// @notice Ganti admin proxy
    /// @param newAdmin Alamat admin baru
    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Admin tidak boleh nol");
        address oldAdmin;
        assembly {
            oldAdmin := sload(_ADMIN_SLOT)
            sstore(_ADMIN_SLOT, newAdmin)
        }
        emit AdminChanged(oldAdmin, newAdmin);
    }

    /// @notice Lihat alamat kontrak implementasi
    function getImplementation() external view returns (address impl) {
        assembly {
            impl := sload(_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Lihat alamat admin saat ini
    function getAdmin() external view returns (address adm) {
        assembly {
            adm := sload(_ADMIN_SLOT)
        }
    }

    /// @dev Fallback function: meneruskan semua call ke kontrak implementasi
    fallback() external payable {
        assembly {
            let impl := sload(_IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            let size := returndatasize()
            returndatacopy(0, 0, size)
            switch result
                case 0 { revert(0, size) }
                default { return(0, size) }
        }
    }

    /// @dev Terima ETH langsung
    receive() external payable {}
}