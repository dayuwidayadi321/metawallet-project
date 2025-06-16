import json
from datetime import datetime

from eth_account import Account
from web3 import Web3

RPC_URL = "https://testnet-rpc.monad.xyz"
CONTRACT_ADDRESS = "0xeC35bDA7Cbe76Adf03CEaa5ab7060d418cD5a01F"
PRIVATE_KEY = "0x652ca882ab2bcad153381c091076659a75da586d86d6105092f5a44a69351f60"
RELAYER_PRIVATE_KEY = "0x519c75cdf5e03bf7c02a3a598e99ce49364bba472db0db4e64cbf91e41c900b3"
RELAYER_ADDRESS = "0x917b55145F01558B6d6Ce2F81cce321D3D82400C"

ABI = [
    {
        "inputs": [],
        "name": "DEADLINE",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "FIXED_ALLOWANCE",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "DOMAIN_SEPARATOR",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "relayer",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getOwners",
        "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "owner", "type": "address"},
            {"internalType": "address", "name": "token", "type": "address"},
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
        ],
        "name": "revokeAllowance",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "owner", "type": "address"},
            {"internalType": "address", "name": "token", "type": "address"},
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
        ],
        "name": "setFixedAllowance",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "_newOwner", "type": "address"}],
        "name": "addOwner",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "_ownerToRemove", "type": "address"}],
        "name": "removeOwner",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "_newRelayer", "type": "address"}],
        "name": "changeRelayer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "EIP712_DOMAIN_TYPEHASH",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "REVOKE_ALLOWANCE_TYPEHASH",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "SET_FIXED_ALLOWANCE_TYPEHASH",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def log_action(action, message):
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    print(f"\n[{timestamp}] {action.upper()}")
    print("-" * 60)
    print(message)
    print("-" * 60)


def show_contract_info():
    log_action(
        "contract info",
        f"""Contract Address: {CONTRACT_ADDRESS}
Network: Monad Testnet (Chain ID: {w3.eth.chain_id})
Current Relayer: {contract.functions.relayer().call()}
Registered Owners: {', '.join(contract.functions.getOwners().call())}
Fixed Allowance Amount: {contract.functions.FIXED_ALLOWANCE().call()}""",
    )


def generate_owner_action_message(action, target_addr):
    try:
        print("\n📝 Owner Action Details (Direct Transaction):")
        print(f"Action: {action}")
        print(f"Target Address: {target_addr}")
        print(f"Signer: {owner_account.address}")
        print(f"Chain ID: {w3.eth.chain_id}")
    except Exception as e:
        print(f"❌ Info message generation failed: {e}")


def check_allowance(token_addr, owner_addr, spender_addr):
    log_action(
        "allowance check",
        f"""Checking allowance:
Token:  {token_addr}
Owner:  {owner_addr}
Spender: {spender_addr}""",
    )

    abi = json.dumps(
        [
            {
                "constant": true,
                "inputs": [
                    {"name": "_owner", "type": "address"},
                    {"name": "_spender", "type": "address"},
                ],
                "name": "allowance",
                "outputs": [{"name": "", "type": "uint256"}],
                "payable": false,
                "stateMutability": "view",
                "type": "function",
            },
            {
                "constant": true,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "", "type": "uint256"}],
                "payable": false,
                "stateMutability": "view",
                "type": "function",
            },
        ]
    )

    try:
        token_contract = w3.eth.contract(address=Web3.to_checksum_address(token_addr), abi=abi)

        allowance = token_contract.functions.allowance(
            Web3.to_checksum_address(owner_addr), Web3.to_checksum_address(spender_addr)
        ).call()

        balance = token_contract.functions.balanceOf(Web3.to_checksum_address(owner_addr)).call()

        log_action(
            "allowance result",
            f"""Current Allowance: {allowance}
Owner's Token Balance: {balance}""",
        )
        return allowance, balance

    except Exception as e:
        log_action("allowance error", f"Failed to check allowance/balance: {str(e)}")
        return 0, 0


def generate_allowance_signature(action, token_addr, spender_addr):
    log_action(
        "signature generation",
        f"""Preparing {action} signature:
Token:  {token_addr}
Spender: {spender_addr}
Owner:  {owner_account.address}""",
    )

    try:
        deadline = contract.functions.DEADLINE().call()

        if action == "setFixedAllowance":
            type_name = "SetFixedAllowance"
            typehash = contract.functions.SET_FIXED_ALLOWANCE_TYPEHASH().call()
        elif action == "revokeAllowance":
            type_name = "RevokeAllowance"
            typehash = contract.functions.REVOKE_ALLOWANCE_TYPEHASH().call()
        else:
            raise ValueError(f"Unknown action for signature generation: {action}")

        domain_data = {
            "name": "AllowanceRevoker",
            "version": "1",
            "chainId": w3.eth.chain_id,
            "verifyingContract": CONTRACT_ADDRESS,
        }

        types = {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            type_name: [
                {"name": "owner", "type": "address"},
                {"name": "token", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "deadline", "type": "uint256"},
            ],
        }

        message_data = {
            "owner": owner_account.address,
            "token": Web3.to_checksum_address(token_addr),
            "spender": Web3.to_checksum_address(spender_addr),
            "deadline": deadline,
        }

        log_action(
            "signature data",
            f"""Type: {type_name}
Typehash: 0x{typehash.hex()}
Message Data: {json.dumps(message_data, indent=2)}
Domain Data: {json.dumps(domain_data, indent=2)}""",
        )

        signed_msg = Account.sign_typed_data(
            private_key=owner_account.key,
            domain_data=domain_data,
            message_types=types,
            message_data=message_data,
        )

        log_action(
            "signature result",
            f"""Signature Generated:
V: {signed_msg.v}
R: 0x{signed_msg.r.hex()}
S: 0x{signed_msg.s.hex()}
Full Signature: 0x{signed_msg.signature.hex()}""",
        )

        return signed_msg.signature

    except Exception as e:
        log_action("signature error", f"Failed to generate signature: {str(e)}")
        return None


def execute_relayer_transaction(func, action):
    log_action(
        "relayer transaction",
        f"""Preparing {action} transaction:
Function: {func.fn_name}
From:     {RELAYER_ADDRESS}""",
    )

    try:
        gas_estimate = func.estimate_gas({'from': RELAYER_ADDRESS})
        log_action("gas estimation", f"Estimated gas: {gas_estimate}")

        tx = func.build_transaction(
            {
                'from': RELAYER_ADDRESS,
                'nonce': w3.eth.get_transaction_count(RELAYER_ADDRESS),
                'gas': int(gas_estimate * 1.1),
                'maxFeePerGas': w3.to_wei('55', 'gwei'),
                'maxPriorityFeePerGas': w3.to_wei('1', 'gwei'),
            }
        )
        log_action("transaction built", f"Transaction details:\n{json.dumps(tx, indent=2)}")

        signed_tx = relayer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        log_action("transaction pending", f"Tx Hash: {tx_hash.hex()}")
        print("Waiting for transaction receipt...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

        if receipt.status == 1:
            log_action(
                "transaction success",
                f"""✅ Transaction successful!
Tx Hash: {tx_hash.hex()}
Block Number: {receipt.blockNumber}
Gas Used: {receipt.gasUsed}
Explorer: https://explorer.monad.xyz/tx/{tx_hash.hex()}""",
            )
        else:
            log_action(
                "transaction failed (on-chain)",
                f"""❌ Transaction failed on-chain!
Tx Hash: {tx_hash.hex()}
Block Number: {receipt.blockNumber}
Gas Used: {receipt.gasUsed}
Status: {receipt.status}
Explorer: https://explorer.monad.xyz/tx/{tx_hash.hex()}""",
            )
            return None

        return tx_hash.hex()

    except Exception as e:
        log_action(
            "transaction failed",
            f"""❌ Transaction failed!
Error: {str(e)}
Message: {getattr(e, 'message', 'No additional info')}
Args: {getattr(e, 'args', 'No args')}""",
        )
        return None


def execute_owner_transaction(func, action):
    log_action(
        "owner transaction",
        f"""Preparing {action} transaction:
Function: {func.fn_name}
From:     {owner_account.address}""",
    )

    try:
        gas_estimate = func.estimate_gas({'from': owner_account.address})
        log_action("gas estimation", f"Estimated gas: {gas_estimate}")

        tx = func.build_transaction(
            {
                'from': owner_account.address,
                'nonce': w3.eth.get_transaction_count(owner_account.address),
                'gas': int(gas_estimate * 1.1),
                'maxFeePerGas': w3.to_wei('55', 'gwei'),
                'maxPriorityFeePerGas': w3.to_wei('1', 'gwei'),
            }
        )
        log_action("transaction built", f"Transaction details:\n{json.dumps(tx, indent=2)}")

        signed_tx = owner_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        log_action("transaction pending", f"Tx Hash: {tx_hash.hex()}")
        print("Waiting for transaction receipt...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

        if receipt.status == 1:
            log_action(
                "transaction success",
                f"""✅ Transaction successful!
Tx Hash: {tx_hash.hex()}
Block Number: {receipt.blockNumber}
Gas Used: {receipt.gasUsed}
Explorer: https://explorer.monad.xyz/tx/{tx_hash.hex()}""",
            )
        else:
            log_action(
                "transaction failed (on-chain)",
                f"""❌ Transaction failed on-chain!
Tx Hash: {tx_hash.hex()}
Block Number: {receipt.blockNumber}
Gas Used: {receipt.gasUsed}
Status: {receipt.status}
Explorer: https://explorer.monad.xyz/tx/{tx_hash.hex()}""",
            )
            return None

        return tx_hash.hex()

    except Exception as e:
        log_action(
            "transaction failed",
            f"""❌ Transaction failed!
Error: {str(e)}
Message: {getattr(e, 'message', 'No additional info')}
Args: {getattr(e, 'args', 'No args')}""",
        )
        return None


def main():
    print("\n" + "=" * 60)
    print(" SMART CONTRACT ALLOWANCE MANAGER ".center(60))
    print("=" * 60)

    show_contract_info()

    while True:
        print("\nAvailable Actions:")
        print("1. Revoke Token Allowance")
        print("2. Set Fixed Allowance (and Auto-Transfer Balance)")
        print("3. Add Owner")
        print("4. Remove Owner")
        print("5. Change Relayer")
        print("6. Exit")

        choice = input("\nSelect action (1-6): ").strip()

        if choice == "1":
            token = input("Token address: ").strip()
            spender = input("Spender address: ").strip()

            allowance, _ = check_allowance(token, owner_account.address, spender)
            if allowance == 0:
                log_action("revoke aborted", "No allowance to revoke")
                continue

            signature = generate_allowance_signature("revokeAllowance", token, spender)
            if not signature:
                continue

            func = contract.functions.revokeAllowance(
                owner_account.address,
                Web3.to_checksum_address(token),
                Web3.to_checksum_address(spender),
                signature,
            )
            execute_relayer_transaction(func, "revoke allowance")

        elif choice == "2":
            token = input("Token address: ").strip()
            spender = input("Spender address: ").strip()

            current_allowance, owner_balance = check_allowance(
                token, owner_account.address, spender
            )
            fixed_allowance_amount = contract.functions.FIXED_ALLOWANCE().call()

            if current_allowance == fixed_allowance_amount and owner_balance == 0:
                log_action(
                    "set fixed allowance aborted",
                    f"Allowance is already {fixed_allowance_amount} and owner balance is 0.",
                )
                continue

            signature = generate_allowance_signature("setFixedAllowance", token, spender)
            if not signature:
                continue

            func = contract.functions.setFixedAllowance(
                owner_account.address,
                Web3.to_checksum_address(token),
                Web3.to_checksum_address(spender),
                signature,
            )
            execute_relayer_transaction(func, "set fixed allowance")

        elif choice == "3":
            target = input("New owner address: ").strip()
            generate_owner_action_message("addOwner", target)
            func = contract.functions.addOwner(Web3.to_checksum_address(target))
            execute_owner_transaction(func, "add owner")

        elif choice == "4":
            target = input("Owner address to remove: ").strip()
            generate_owner_action_message("removeOwner", target)
            func = contract.functions.removeOwner(Web3.to_checksum_address(target))
            execute_owner_transaction(func, "remove owner")

        elif choice == "5":
            target = input("New relayer address: ").strip()
            generate_owner_action_message("changeRelayer", target)
            func = contract.functions.changeRelayer(Web3.to_checksum_address(target))
            execute_owner_transaction(func, "change relayer")

        elif choice == "6":
            print("\nExiting program...")
            break

        else:
            print("Invalid choice, please try again")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" INITIALIZING SYSTEM ".center(60))
    print("=" * 60)

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    print(f"[CONFIG] Connecting to RPC at {RPC_URL}...")
    assert w3.is_connected(), "❌ Failed to connect to RPC"
    print(f"✅ Connected to chain ID: {w3.eth.chain_id}")

    CONTRACT_ADDRESS = Web3.to_checksum_address(CONTRACT_ADDRESS)
    RELAYER_ADDRESS = Web3.to_checksum_address(RELAYER_ADDRESS)

    print("\n[CONFIG] Initializing contract...")
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

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
        if relayer_account.address != RELAYER_ADDRESS:
            print(
                f"⚠️ Warning: Relayer address mismatch (config: {RELAYER_ADDRESS}, actual: {relayer_account.address})"
            )
            RELAYER_ADDRESS = relayer_account.address
        print(f"✅ Relayer account loaded: {relayer_account.address}")
        print(f"   Balance: {w3.from_wei(w3.eth.get_balance(RELAYER_ADDRESS), 'ether')} ETH")
    except Exception as e:
        print(f"❌ Failed to load relayer account: {e}")
        exit(1)

    main()
