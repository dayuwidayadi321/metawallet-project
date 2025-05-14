// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./interface/ILayerZeroEndpoint.sol";
import "./interface/ILayerZeroReceiver.sol";

abstract contract CrossChainHandler is Initializable, ILayerZeroReceiver, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    /* ========== CUSTOM ERRORS ========== */
    error InvalidEndpoint(address endpoint);
    error ChainNotSupported(uint16 chainId);
    error InsufficientGasFee(uint256 required, uint256 provided);
    error RemoteAddressMismatch(bytes remote);
    error TransferFailed(address token, address from, uint256 amount);
    error FailedCrossChainCall(uint16 chainId, bytes reason);
    error InvalidPayload(bytes payload);

    /* ========== CONSTANTS ========== */
    uint16 public constant LZ_VERSION = 1;
    uint256 public constant MAX_GAS_LIMIT = 5_000_000;
    uint256 public constant GAS_BUFFER_PERCENT = 20;

    /* ========== STATE VARIABLES ========== */
    ILayerZeroEndpoint public lzEndpoint;
    mapping(uint16 => bytes) public trustedRemoteLookup;
    mapping(uint16 => uint256) public minGasLimits;
    mapping(uint16 => bool) public isChainActive;

    /* ========== EVENTS ========== */
    event LZEndpointUpdated(address newEndpoint);
    event TrustedRemoteSet(uint16 chainId, bytes remoteAddress);
    event MinGasLimitUpdated(uint16 chainId, uint256 minGas);
    event ChainStatusChanged(uint16 chainId, bool active);
    event LZMessageSent(uint16 indexed dstChainId, bytes payload);
    event LZMessageReceived(uint16 indexed srcChainId, bytes payload);
    event GasReserved(uint16 indexed chainId, uint256 amount);

    /* ========== MODIFIERS ========== */
    modifier onlyActiveChain(uint16 chainId) {
        if (!isChainActive[chainId]) revert ChainNotSupported(chainId);
        _;
    }

    /* ========== INITIALIZATION ========== */
    function __CrossChainHandler_init(
        address _endpoint,
        uint16[] memory _chainIds,
        bytes[] memory _remotes
    ) internal onlyInitializing {
        __ReentrancyGuard_init();
        _setLZEndpoint(_endpoint);
        
        require(_chainIds.length == _remotes.length, "Mismatched input");
        for (uint i = 0; i < _chainIds.length; i++) {
            _setTrustedRemote(_chainIds[i], _remotes[i]);
        }
    }

    /* ========== OWNER FUNCTIONS ========== */
    function setLZEndpoint(address _endpoint) external virtual onlyOwner {
        _setLZEndpoint(_endpoint);
    }

    function setTrustedRemote(
        uint16 _chainId,
        bytes calldata _remoteAddress
    ) external virtual onlyOwner {
        _setTrustedRemote(_chainId, _remoteAddress);
    }

    function setMinGasLimit(
        uint16 _chainId,
        uint256 _minGas
    ) external virtual onlyOwner {
        if (_minGas > MAX_GAS_LIMIT) revert("Exceeds max gas");
        minGasLimits[_chainId] = _minGas;
        emit MinGasLimitUpdated(_chainId, _minGas);
    }

    function setChainStatus(
        uint16 _chainId,
        bool _active
    ) external virtual onlyOwner {
        isChainActive[_chainId] = _active;
        emit ChainStatusChanged(_chainId, _active);
    }

    /* ========== PUBLIC FUNCTIONS ========== */
    function estimateFees(
        uint16 _dstChainId,
        bytes calldata _payload,
        bool _payInZRO,
        bytes calldata _adapterParams
    ) public view returns (uint256 nativeFee, uint256 zroFee) {
        return lzEndpoint.estimateFees(
            _dstChainId,
            address(this),
            _payload,
            _payInZRO,
            _adapterParams
        );
    }

    /* ========== CROSS-CHAIN OPERATIONS ========== */
    function sendCrossChain(
        uint16 _dstChainId,
        bytes calldata _payload,
        address payable _refundAddress,
        address _gasPaymentToken,
        bytes calldata _adapterParams
    ) external payable virtual onlyOwner onlyActiveChain(_dstChainId) nonReentrant {
        if (_payload.length == 0) revert InvalidPayload(_payload);
        
        bytes memory remote = trustedRemoteLookup[_dstChainId];
        if (remote.length == 0) revert ChainNotSupported(_dstChainId);

        uint256 gasLimit = _calculateGasLimit(_adapterParams);
        (uint256 gasFee,) = _estimateGasFee(_dstChainId, _payload, gasLimit);

        _handleGasPayment(_gasPaymentToken, gasFee, _refundAddress);

        lzEndpoint.send{value: _gasPaymentToken == address(0) ? gasFee : msg.value}(
            _dstChainId,
            remote,
            _payload,
            _refundAddress,
            address(0),
            _adapterParams
        );

        emit LZMessageSent(_dstChainId, _payload);
    }

    /* ========== LAYERZERO CALLBACK ========== */
    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64,
        bytes calldata _payload
    ) external override nonReentrant {
        if (msg.sender != address(lzEndpoint)) revert InvalidEndpoint(msg.sender);
        _validateRemote(_srcChainId, _srcAddress);
        _nonblockingLzReceive(_srcChainId, _srcAddress, _payload);
    }

    /* ========== INTERNAL FUNCTIONS ========== */
    function _setLZEndpoint(address _endpoint) internal {
        if (_endpoint.code.length == 0) revert InvalidEndpoint(_endpoint);
        lzEndpoint = ILayerZeroEndpoint(_endpoint);
        emit LZEndpointUpdated(_endpoint);
    }

    function _setTrustedRemote(uint16 _chainId, bytes memory _remoteAddress) internal {
        (bool success, bytes memory data) = address(bytes20(_remoteAddress)).staticcall(
            abi.encodeWithSignature("supportsInterface(bytes4)", type(ILayerZeroReceiver).interfaceId)
        );
        require(success && abi.decode(data, (bool)), "Invalid remote");
        trustedRemoteLookup[_chainId] = _remoteAddress;
        emit TrustedRemoteSet(_chainId, _remoteAddress);
    }

    function _validateRemote(uint16 _srcChainId, bytes calldata _srcAddress) internal view {
        bytes memory trustedRemote = trustedRemoteLookup[_srcChainId];
        if (
            trustedRemote.length == 0 ||
            _srcAddress.length != trustedRemote.length ||
            keccak256(_srcAddress) != keccak256(trustedRemote)
        ) {
            revert RemoteAddressMismatch(_srcAddress);
        }
    }

    function _calculateGasLimit(bytes memory _adapterParams) internal pure returns (uint256) {
        if (_adapterParams.length == 0) {
            return (gasleft() * (100 + GAS_BUFFER_PERCENT)) / 100;
        }
        return abi.decode(_adapterParams, (uint256));
    }

    function _estimateGasFee(
        uint16 _dstChainId,
        bytes calldata _payload,
        uint256 _gasLimit
    ) internal view returns (uint256 nativeFee, uint256 zroFee) {
        bytes memory adapterParams = abi.encodePacked(LZ_VERSION, _gasLimit);
        return lzEndpoint.estimateFees(
            _dstChainId,
            address(this),
            _payload,
            false,
            adapterParams
        );
    }

    function _handleGasPayment(
        address _token,
        uint256 _amount,
        address payable _refundAddress
    ) internal {
        if (_token == address(0)) {
            if (msg.value < _amount) revert InsufficientGasFee(_amount, msg.value);
            if (msg.value > _amount) {
                (bool success, ) = _refundAddress.call{value: msg.value - _amount}("");
                if (!success) revert TransferFailed(address(0), _refundAddress, msg.value - _amount);
            }
        } else {
            IERC20Upgradeable(_token).safeTransferFrom(msg.sender, address(this), _amount);
            IERC20Upgradeable(_token).safeApprove(address(lzEndpoint), _amount);
        }
    }

    /* ========== ABSTRACT FUNCTIONS ========== */
    function _nonblockingLzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        bytes calldata _payload
    ) internal virtual;

    /* ========== STORAGE GAP ========== */
    uint256[50] private __gap;
}