// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "./interface/ILayerZeroEndpoint.sol";
import "./interface/ILayerZeroReceiver.sol";
import "./interface/ILayerZeroUserApplicationConfig.sol";

/**
 * @title CoreV58Module_CrossChain
 * @author DFXC IndonesiaSecurity Web3 Team - Developed by Dayu Widayadi
 * @notice Modul 3 dari CoreV58: Implementasi Komunikasi Lintas Rantai dengan LayerZero
 */
abstract contract CoreV58Module_CrossChain is Initializable {
    using AddressUpgradeable for address;

    /* ========== IMMUTABLES (Ditetapkan saat inisialisasi) ========== */
    ILayerZeroEndpoint internal _lzEndpoint;

    /* ========== SHARED STATE ========== */
    mapping(uint16 => bytes) public trustedRemoteLookup; // chainId => remote address
    mapping(uint16 => bool) public supportedChains;

    /* ========== CONSTANTS ========== */
    uint16 public constant LZ_VERSION = 1;
    uint256 internal constant MAX_PAYLOAD_SIZE = 10_000;
    uint256 internal constant MAX_GAS_LIMIT = 5_000_000;
    uint256 internal constant GAS_LIMIT_BUFFER_PERCENT = 120; // 120%

    /* ========== CUSTOM ERRORS ========== */
    error InvalidEndpoint(address endpoint);
    error ChainNotSupported(uint16 chainId);
    error InsufficientGasFee(uint256 required, uint256 provided);
    error RemoteAddressMismatch(bytes remote);
    error TransferFailed(address token, address from, uint256 amount);
    error FailedCrossChainCall(uint16 chainId, bytes reason);
    error PayloadTooLarge(uint256 size, uint256 max);
    error GasLimitTooHigh(uint256 limit, uint256 max);

    /* ========== EVENTS ========== */
    event LZMessageSent(uint16 indexed dstChainId, bytes indexed payload);
    event LZMessageReceived(uint16 indexed srcChainId, bytes indexed payload);

    /* ========== INITIALIZER ========== */
    /**
     * @dev Initializes the Cross-Chain module.
     * @param lzEndpointAddress The address of the LayerZero Endpoint contract.
     * @param _supportedChainIds Array of supported destination chain IDs.
     * @param _trustedRemotes Array of trusted remote addresses corresponding to the chain IDs.
     */
    function __CrossChainModule_init(
        ILayerZeroEndpoint lzEndpointAddress,
        uint16[] memory _supportedChainIds,
        bytes[] memory _trustedRemotes
    ) internal virtual onlyInitializing {
        require(address(lzEndpointAddress) != address(0), "Invalid LZ endpoint");
        _lzEndpoint = lzEndpointAddress;

        require(_supportedChainIds.length == _trustedRemotes.length, "Mismatched chain config");
        for (uint256 i = 0; i < _supportedChainIds.length; i++) {
            trustedRemoteLookup[_supportedChainIds[i]] = _trustedRemotes[i];
            supportedChains[_supportedChainIds[i]] = true;
        }
    }

    /* ========== EXTERNAL FUNCTIONS (Configuration) ========== */
    /**
     * @dev Sets the LayerZero Endpoint address. Only owners can call this.
     * @param _endpoint The address of the new LayerZero Endpoint.
     */
    function setLZEndpoint(address _endpoint) external virtual onlyOwner {
        if (_endpoint.code.length == 0) revert InvalidEndpoint(_endpoint);
        _lzEndpoint = ILayerZeroEndpoint(_endpoint);
    }

    /**
     * @dev Sets the trusted remote address for a specific chain ID. Only owners can call this.
     * @param _chainId The ID of the chain to set the remote address for.
     * @param _remoteAddress The trusted remote address on the specified chain.
     */
    function setTrustedRemote(uint16 _chainId, bytes calldata _remoteAddress) external virtual onlyOwner {
        address remoteAddr;
        assembly {
            remoteAddr := calldataload(_remoteAddress.offset)
        }
        (bool success, bytes memory data) = remoteAddr.staticcall(abi.encodeWithSignature("supportsInterface(bytes4)", type(ILayerZeroReceiver).interfaceId));
        require(success && abi.decode(data, (bool)), "Invalid remote: does not implement ILayerZeroReceiver");
        trustedRemoteLookup[_chainId] = _remoteAddress;
    }

    /**
     * @dev Adds support for a new destination chain. Only owners can call this.
     * @param _chainId The ID of the new supported chain.
     */
    function addSupportedChain(uint16 _chainId) external virtual onlyOwner {
        supportedChains[_chainId] = true;
    }

    /**
     * @dev Removes support for a destination chain. Only owners can call this.
     * @param _chainId The ID of the chain to remove support for.
     */
    function removeSupportedChain(uint16 _chainId) external virtual onlyOwner {
        delete supportedChains[_chainId];
        delete trustedRemoteLookup[_chainId];
    }

    /* ========== EXTERNAL FUNCTIONS (Sending Messages) ========== */
    /**
     * @dev Sends a cross-chain message via LayerZero. Only owners can call this.
     * @param _dstChainId Destination chain ID.
     * @param _payload Encoded function call data.
     * @param _refundAddress Address to receive any gas refund.
     * @param _gasPaymentToken Token address for gas payment (address(0) for native).
     */
    function sendCrossChain(
        uint16 _dstChainId,
        bytes calldata _payload,
        address payable _refundAddress,
        address _gasPaymentToken
    ) external payable virtual onlyOwner {
        if (!supportedChains[_dstChainId]) revert ChainNotSupported(_dstChainId);
        if (_payload.length > MAX_PAYLOAD_SIZE) revert PayloadTooLarge(_payload.length, MAX_PAYLOAD_SIZE);

        uint256 gasLimit = (gasleft() * GAS_LIMIT_BUFFER_PERCENT) / 100;
        if (gasLimit > MAX_GAS_LIMIT) revert GasLimitTooHigh(gasLimit, MAX_GAS_LIMIT);

        (uint256 gasFee,) = _lzEndpoint.estimateFees(
            _dstChainId,
            address(this),
            _payload,
            false,
            abi.encodePacked(LZ_VERSION, gasLimit)
        );

        if (_gasPaymentToken == address(0)) {
            if (msg.value < gasFee) revert InsufficientGasFee(gasFee, msg.value);
            _lzEndpoint.send{value: gasFee}(
                _dstChainId,
                trustedRemoteLookup[_dstChainId],
                _payload,
                _refundAddress,
                address(0),
                abi.encodePacked(LZ_VERSION, gasLimit)
            );
            if (msg.value > gasFee) {
                (bool success, ) = msg.sender.call{
                    value: msg.value - gasFee
                }("");
                if (!success) revert TransferFailed(address(0), msg.sender, msg.value - gasFee);
            }
        } else {
            IERC20Upgradeable token = IERC20Upgradeable(_gasPaymentToken);
            uint256 allowance = token.allowance(msg.sender, address(_lzEndpoint));
            if (allowance < gasFee) revert InsufficientGasFee(gasFee, allowance);
            bool transferSuccess = token.transferFrom(msg.sender, address(this), gasFee);
            if (!transferSuccess) revert TransferFailed(_gasPaymentToken, msg.sender, gasFee);
            bool approveSuccess = token.approve(address(_lzEndpoint), gasFee);
            if (!approveSuccess) revert TransferFailed(_gasPaymentToken, address(this), gasFee);
            _lzEndpoint.send(
                _dstChainId,
                trustedRemoteLookup[_dstChainId],
                _payload,
                _refundAddress,
                _gasPaymentToken,
                abi.encodePacked(LZ_VERSION, gasLimit)
            );
        }

        emit LZMessageSent(_dstChainId, _payload);
    }

    /* ========== EXTERNAL FUNCTIONS (LayerZero Callback) ========== */
    /**
     * @dev Callback function called by LayerZero when a message is received.
     * @param _srcChainId The ID of the source chain.
     * @param _srcAddress The address of the sender on the source chain.
     * @param _payload The received message payload.
     */
    function _nonblockingLzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        bytes calldata _payload
    ) internal virtual {
        bytes memory trustedRemote = trustedRemoteLookup[_srcChainId];
        if (trustedRemote.length == 0) revert ChainNotSupported(_srcChainId);
        if (_srcAddress.length != trustedRemote.length || keccak256(_srcAddress) != keccak256(trustedRemote))
            revert RemoteAddressMismatch(trustedRemote);
        if (_payload.length == 0) return; // Silently ignore empty payloads

        (bool success, bytes memory reason) = address(this).delegatecall(_payload);
        if (!success) revert FailedCrossChainCall(_srcChainId, reason);

        emit LZMessageReceived(_srcChainId, _payload);
    }
}
