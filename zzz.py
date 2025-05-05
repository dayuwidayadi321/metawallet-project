#!/usr/bin/env python3
from web3 import Web3
import os
from art import *
import json
from colorama import Fore, Style, init

# Inisialisasi colorama
init(autoreset=True)

# Konfigurasi awal
CONTRACT_ADDRESS = "0xYourContractAddressHere"
CONTRACT_ABI = json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},...]')  # Isi dengan ABI lengkap
RPC_URL = "https://mainnet.infura.io/v3/YOUR_INFURA_KEY"

# Tampilan banner
def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    tprint("SecureSmartWallet", font="block")
    print(f"{Fore.RED}┌──────────────────────────────────────────────────────────────┐")
    print(f"│ {Fore.YELLOW}⚡ Web3 Smart Wallet Console Author DFXC Indonesia {Fore.RED}           │")
    print(f"└──────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

# Koneksi ke Web3
def init_web3(private_key):
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        if not w3.is_connected():
            raise ConnectionError("Gagal terhubung ke node RPC")
        
        account = w3.eth.account.from_key(private_key)
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        
        return w3, account, contract
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return None, None, None

# Ambil info dasar dari smart contract
def get_contract_info(contract):
    try:
        name = contract.functions.NAME().call()
        version = contract.functions.VERSION().call()
        description = contract.functions.DESCRIPTION().call()
        return name, version, description
    except:
        return "SecureSmartWallet", "4.48", "EIP-4337 Smart Wallet with Emergency Recovery"

# Tampilkan menu utama
def show_menu():
    print(f"\n{Fore.CYAN}Core Commands{Style.RESET_ALL}")
    print(f"{Fore.GREEN}============={Style.RESET_ALL}")
    print(f"    Command              Description")
    print(f"    -------              -----------")
    print(f"    {Fore.YELLOW}wallet_info{Style.RESET_ALL}         Tampilkan info wallet")
    print(f"    {Fore.YELLOW}owners{Style.RESET_ALL}              Kelola daftar pemilik")
    print(f"    {Fore.YELLOW}guardians{Style.RESET_ALL}           Kelola guardian")
    print(f"    {Fore.YELLOW}scheduled_ops{Style.RESET_ALL}       Operasi terjadwal")
    print(f"    {Fore.YELLOW}emergency{Style.RESET_ALL}           Fungsi darurat")
    print(f"    {Fore.YELLOW}transactions{Style.RESET_ALL}        Transaksi & tanda tangan")
    print(f"    {Fore.YELLOW}admin{Style.RESET_ALL}               Fungsi admin")
    print(f"    {Fore.YELLOW}exit{Style.RESET_ALL}                Keluar dari console")

# Main function
def main():
    show_banner()
    
    # Input private key
    private_key = input(f"\n{Fore.GREEN}Masukkan private key (atau kosongkan untuk demo): {Style.RESET_ALL}")
    if not private_key:
        private_key = "0xYourTestPrivateKeyHere"  # Hanya untuk demo, jangan dipakai di production!
    
    w3, account, contract = init_web3(private_key)
    if not w3:
        return
    
    # Ambil info kontrak
    name, version, desc = get_contract_info(contract)
    
    # Tampilkan info wallet
    balance = w3.from_wei(w3.eth.get_balance(account.address), 'ether')
    print(f"\n{Fore.GREEN}┌──[{Fore.RED}Wallet Info{Fore.GREEN}]{Style.RESET_ALL}")
    print(f"│ Contract: {Fore.YELLOW}{name} v{version}{Style.RESET_ALL}")
    print(f"│ Desc:     {desc}")
    print(f"│ Address:  {Fore.CYAN}{account.address}{Style.RESET_ALL}")
    print(f"│ Balance:  {Fore.GREEN}{balance} ETH{Style.RESET_ALL}")
    print(f"│ Network:  {RPC_URL.split('//')[1].split('/')[0]}")
    print(f"└───────────────────────────────────────")
    
    # Main loop
    while True:
        cmd = input(f"\n{Fore.RED}wallet{Style.RESET_ALL}({Fore.YELLOW}main{Style.RESET_ALL}) > ").strip().lower()
        
        if cmd == "help" or cmd == "?":
            show_menu()
        elif cmd == "wallet_info":
            print(f"\n{Fore.GREEN}Wallet Info:{Style.RESET_ALL}")
            print(f"Address: {account.address}")
            print(f"Balance: {balance} ETH")
        elif cmd == "exit":
            print(f"{Fore.YELLOW}Keluar dari console...{Style.RESET_ALL}")
            break
        elif cmd in ["owners", "guardians", "scheduled_ops", "emergency", "transactions", "admin"]:
            print(f"\n{Fore.YELLOW}[!] Fitur '{cmd}' masih dalam pengembangan (Coming Soon){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Perintah tidak dikenali. Ketik 'help' untuk melihat menu.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()