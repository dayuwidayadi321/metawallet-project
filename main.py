#!/usr/bin/env python3
from web3 import Web3
from eth_account import Account
import json
from datetime import datetime
from eth_account.messages import encode_typed_data
import time

# ======================
# CONFIGURATION
# ======================
RPC_URL = "https://testnet-rpc.monad.xyz"  # Monad testnet
CONTRACT_ADDRESS = "0x6be0e1CC075D3D1CE7AB55A357ecd3cb690410fA"
PRIVATE_KEY = "0x652ca882ab2bcad153381c091076659a75da586d86d6105092f5a44a69351f60"  # OWNER
RELAYER_PRIVATE_KEY = "0x519c75cdf5e03bf7c02a3a598e99ce49364bba472db0db4e64cbf91e41c900b3"  # RELAYER

# ======================
# INITIAL SETUP
# ======================
print("\n" + "="*60)
print(" SAFE REVOKER SYSTEM INITIALIZATION ".center(60))
print("="*60)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
print(f"[CONFIG] Connecting to RPC at {RPC_URL}...")
assert w3.is_connected(), "❌ Failed to connect to RPC"
print(f"✅ Connected to chain ID: {w3.eth.chain_id}")

# Convert to checksum addresses
CONTRACT_ADDRESS = Web3.to_checksum_address(CONTRACT_ADDRESS)

# Contract ABI (updated for SafeRevoker)
ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "_initialRelayer", "type": "address"},
            {"internalType": "address[]", "name": "_initialOwners", "type": "address[]"}
        ],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "owner", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "token", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "spender", "type": "address"}
        ],
        "name": "ApprovalRevoked",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "newOwner", "type": "address"}
        ],
        "name": "OwnerAdded",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "removedOwner", "type": "address"}
        ],
        "name": "OwnerRemoved",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "newRelayer", "type": "address"}
        ],
        "name": "RelayerChanged",
        "type": "event"
    },
    {
        "inputs": [{"internalType": "address", "name": "_newOwner", "type": "address"}],
        "name": "addOwner",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "_newRelayer", "type": "address"}],
        "name": "changeRelayer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "DOMAIN_SEPARATOR",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getOwners",
        "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "_address", "type": "address"}],
        "name": "isOwner",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "_ownerToRemove", "type": "address"}],
        "name": "removeOwner",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "relayer",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "owner", "type": "address"},
            {"internalType": "address", "name": "token", "type": "address"},
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"}
        ],
        "name": "revokeApproval",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

print("\n[CONFIG] Initializing contract...")
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

# Initialize accounts
try:
    print("\n[ACCOUNT] Loading owner account...")
    owner_account = Account.from_key(PRIVATE_KEY)
    print(f"✅ Owner account loaded: {owner_account.address}")
    print(f"   Balance: {w3.from_wei(w3.eth.get_balance(owner_account.address), 'ether')} ETH")
except Exception as e:
    print(f"❌ Failed to load owner account: {e}")
    exit(1)

try:
    print("\n[ACCOUNT] Loading relayer account...")
    relayer_account = Account.from_key(RELAYER_PRIVATE_KEY)
    print(f"✅ Relayer account loaded: {relayer_account.address}")
    print(f"   Balance: {w3.from_wei(w3.eth.get_balance(relayer_account.address), 'ether')} ETH")
    
    # Verify relayer matches contract
    contract_relayer = contract.functions.relayer().call()
    if relayer_account.address.lower() != contract_relayer.lower():
        print(f"⚠️ Warning: Configured relayer doesn't match contract's relayer")
        print(f"   Configured: {relayer_account.address}")
        print(f"   Contract:   {contract_relayer}")
except Exception as e:
    print(f"❌ Failed to load relayer account: {e}")
    exit(1)

# ======================
# UTILITY FUNCTIONS
# ======================
def log_action(action, message, is_error=False):
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    header = f"[{timestamp}] {action.upper()}"
    print("\n" + header)
    print("-" * len(header))
    print(message)
    if is_error:
        print("❌ ACTION FAILED")
    else:
        print("✅ ACTION COMPLETED")
    print("-" * len(header))

def get_current_owners():
    return contract.functions.getOwners().call()

def show_contract_info():
    owners = get_current_owners()
    info = f"""
Contract Address: {CONTRACT_ADDRESS}
Network: Monad Testnet (Chain ID: {w3.eth.chain_id})
Current Relayer: {contract.functions.relayer().call()}
Registered Owners ({len(owners)}):
""" + "\n".join([f"  - {owner}" + (" (YOU)" if owner.lower() == owner_account.address.lower() else "") for owner in owners])
    log_action("contract info", info)

def check_allowance(token_addr, owner_addr, spender_addr):
    """Check current token allowance with detailed logging"""
    log_action("allowance check", 
        f"""Checking allowance:
Token:  {token_addr}
Owner:  {owner_addr}
Spender: {spender_addr}""")
    
    # Minimal ERC-20 ABI for allowance check
    abi = json.dumps([
        {
            "constant": True,
            "inputs": [
                {"name": "_owner", "type": "address"},
                {"name": "_spender", "type": "address"}
            ],
            "name": "allowance",
            "outputs": [{"name": "", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function"
        }
    ])
    
    try:
        token_contract = w3.eth.contract(
            address=Web3.to_checksum_address(token_addr), 
            abi=abi)
        
        allowance = token_contract.functions.allowance(
            Web3.to_checksum_address(owner_addr),
            Web3.to_checksum_address(spender_addr)
        ).call()
        
        balance = token_contract.functions.balanceOf(
            Web3.to_checksum_address(owner_addr)
        ).call()
        
        log_action("allowance result", 
            f"""Current Allowance: {allowance}
Owner's Token Balance: {balance}""")
        return allowance, balance
        
    except Exception as e:
        log_action("allowance error", f"Failed to check allowance/balance: {str(e)}", is_error=True)
        return 0, 0

def generate_revoke_signature(owner, token, spender):
    """Generate EIP-712 signature for revokeApproval"""
    try:
        # Get contract constants
        domain_separator = contract.functions.DOMAIN_SEPARATOR().call()
        
        # Prepare EIP-712 data
        domain_data = {
            "name": "SafeRevoker",
            "version": "1",
            "chainId": w3.eth.chain_id,
            "verifyingContract": CONTRACT_ADDRESS
        }

        message_types = {
            "RevokeApproval": [
                {"name": "owner", "type": "address"},
                {"name": "token", "type": "address"},
                {"name": "spender", "type": "address"}
            ]
        }

        message_data = {
            "owner": Web3.to_checksum_address(owner),
            "token": Web3.to_checksum_address(token),
            "spender": Web3.to_checksum_address(spender)
        }

        # Debug output
        log_action("signature generation", 
            f"""🔏 EIP-712 Signature Data:
Primary Type: RevokeApproval
Domain Separator: 0x{domain_separator.hex()}
Message Data: {json.dumps(message_data, indent=2)}""")

        # Sign the message
        signed_msg = w3.eth.account.sign_typed_data(
            private_key=owner_account.key,
            domain_data=domain_data,
            message_types=message_types,
            message_data=message_data
        )

        # Validate signature
        if len(signed_msg.signature) != 65:
            raise ValueError("Invalid signature length")

        log_action("signature generated", 
            f"""Signature Details:
R: 0x{signed_msg.r:064x}
S: 0x{signed_msg.s:064x}
V: {signed_msg.v}
Full Signature: 0x{signed_msg.signature.hex()}""")

        return signed_msg.signature

    except Exception as e:
        log_action("signature error", f"Failed to generate signature: {str(e)}", is_error=True)
        return None

def execute_owner_transaction(func, action_name):
    log_action("owner transaction",
        f"""Preparing {action_name} transaction:
Function: {func.fn_name}
From:     {owner_account.address}""")
    try:
        gas_estimate = func.estimate_gas({'from': owner_account.address})
        log_action("gas estimation", f"Estimated gas: {gas_estimate}")

        tx = func.build_transaction({
            'from': owner_account.address,
            'nonce': w3.eth.get_transaction_count(owner_account.address),
            'gas': int(gas_estimate * 1.1),
            'maxFeePerGas': w3.to_wei('55', 'gwei'),
            'maxPriorityFeePerGas': w3.to_wei('1', 'gwei')
        })

        log_action("transaction built", f"Transaction details:\n{json.dumps(tx, indent=2)}")

        signed_tx = owner_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        log_action("transaction sent",
            f"""Transaction submitted:
Tx Hash: {tx_hash.hex()}
Waiting for confirmation...""")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300) # Wait for receipt

        if receipt.status == 1:
            log_action("transaction success",
                f"""✅ Transaction successful!
Tx Hash: {tx_hash.hex()}
Block: {receipt.blockNumber}
Gas Used: {receipt.gasUsed}
Explorer: https://explorer.monad.xyz/tx/{tx_hash.hex()}""")
            return tx_hash.hex()
        else:
            # Tambahkan logika penanganan revert reason di sini jika diperlukan
            log_action("transaction failed",
                f"""❌ Transaction failed!
Tx Hash: {tx_hash.hex()}
Block: {receipt.blockNumber}
Status: {receipt.status}""", is_error=True) # Anda bisa menambahkan is_error ke log_action
            return None

    except Exception as e:
        log_action("transaction failed", f"❌ Failed to execute owner transaction: {str(e)}")
        return None


# ======================
# MAIN EXECUTION FLOW
# ======================
def main():
    print("\n" + "="*60)
    print(" SAFE REVOKER MANAGEMENT SYSTEM ".center(60)) 
    print("="*60)
    
    show_contract_info()
    
    while True:
        print("\nAvailable Actions:")
        print("1. Revoke Token Approval")
        print("2. Add Owner")
        print("3. Remove Owner")
        print("4. Change Relayer")
        print("5. Show Contract Info")
        print("6. Exit")
        
        choice = input("\nSelect action (1-6): ").strip()
        
        if choice == "1":  # Revoke Token Approval
            token = input("Token address: ").strip()
            spender = input("Spender address: ").strip()
            
            allowance, _ = check_allowance(token, owner_account.address, spender)
            if allowance == 0:
                log_action("revoke aborted", "No allowance to revoke", is_error=True)
                continue
                
            signature = generate_revoke_signature(owner_account.address, token, spender)
            if not signature:
                continue
                
            func = contract.functions.revokeApproval(
                Web3.to_checksum_address(owner_account.address),
                Web3.to_checksum_address(token),
                Web3.to_checksum_address(spender),
                signature
            )
            execute_relayer_transaction(func, "revoke approval")
            
        elif choice == "2":  # Add Owner
            new_owner = input("New owner address: ").strip()
            if not Web3.is_address(new_owner):
                log_action("invalid input", "Invalid Ethereum address", is_error=True)
                continue
                
            if Web3.to_checksum_address(new_owner) in get_current_owners():
                log_action("owner exists", "Address is already an owner", is_error=True)
                continue
                
            func = contract.functions.addOwner(Web3.to_checksum_address(new_owner))
            execute_owner_transaction(func, "add owner")
            
        elif choice == "3":  # Remove Owner
            owners = get_current_owners()
            if len(owners) <= 1:
                log_action("remove aborted", "Cannot remove last owner", is_error=True)
                continue
                
            print("\nCurrent Owners:")
            for i, owner in enumerate(owners, 1):
                print(f"{i}. {owner}")
                
            owner_to_remove = input("\nSelect owner to remove (number) or enter address: ").strip()
            
            try:
                if owner_to_remove.isdigit():
                    index = int(owner_to_remove) - 1
                    if 0 <= index < len(owners):
                        owner_to_remove = owners[index]
                    else:
                        raise ValueError("Invalid selection")
                elif not Web3.is_address(owner_to_remove):
                    raise ValueError("Invalid address")
                    
                if Web3.to_checksum_address(owner_to_remove) not in owners:
                    log_action("not owner", "Address is not an owner", is_error=True)
                    continue
                    
                if Web3.to_checksum_address(owner_to_remove) == owner_account.address:
                    log_action("self remove", "Cannot remove yourself", is_error=True)
                    continue
                    
                func = contract.functions.removeOwner(Web3.to_checksum_address(owner_to_remove))
                execute_owner_transaction(func, "remove owner")
                
            except Exception as e:
                log_action("input error", f"Invalid input: {str(e)}", is_error=True)
            
        elif choice == "4":  # Change Relayer
            new_relayer = input("New relayer address: ").strip()
            if not Web3.is_address(new_relayer):
                log_action("invalid input", "Invalid Ethereum address", is_error=True)
                continue
                
            func = contract.functions.changeRelayer(Web3.to_checksum_address(new_relayer))
            execute_owner_transaction(func, "change relayer")
            
        elif choice == "5":  # Show Contract Info
            show_contract_info()
            
        elif choice == "6":  # Exit
            print("\nExiting SafeRevoker management system...")
            break
            
        else:
            log_action("invalid choice", "Please select a valid option (1-6)", is_error=True)

if __name__ == "__main__":
    main()
    
    
    

            