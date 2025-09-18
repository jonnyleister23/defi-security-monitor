import os
import streamlit as st
from web3 import Web3
from dotenv import load_dotenv
import time

# Getting API key securely
load_dotenv()
try:
    infura_key = st.secrets["INFURA_KEY"]
except (KeyError, AttributeError):
    infura_key = os.getenv("INFURA_KEY")

# Build full Infura URL
infura_url = f"https://mainnet.infura.io/v3/{infura_key}"

# Create Web3 connection
w3 = Web3(Web3.HTTPProvider(infura_url))

if not w3.is_connected():
    raise ConnectionError("Failed to connect to Infura. Check your INFURA_KEY and network.")
# TEST CONNECTION
print("🔗 Connecting to Ethereum mainnet...")
print(f"✅ Connected: {w3.is_connected()}")
print(f"📊 Latest block number: {w3.eth.block_number}")
print(f"⛽ Current gas price: {w3.eth.gas_price} wei")


#Checks if address is a smart contract
def is_smart_contract(address):
    try:
        code = w3.eth.get_code(address) #Only smart contracts have bytecodes so if its a user account it will be 0
        time.sleep(0.1)  
        return len(code) > 0
    except Exception as e:
        print(f"⚠️ API error checking {address}: {e}")
        return False  # Must not be a contract
#Gets the number of decimal places for token
def get_token_decimals(contract_address):
    try:
        # Standard ERC20 decimals function signature
        decimals_data = w3.eth.call({
            'to': contract_address,
            'data': '0x313ce567'  # Hex signature for decimals()
        })
        time.sleep(0.1)
        decimals = int(decimals_data.hex(), 16)
        return decimals
    except Exception as e:
        print(f"⚠️ Could not get decimals for {contract_address}: {e}")
        return 18  # Keep it 18 if we can't determine

# ------------ MAIN MONITORING FUNCTIONS -----------------
 
#Detects unusually large ETH transfers that could indicate scams
def monitor_large_transactions():
    print("\n🔍 Scanning latest block for large transactions...")
    
    latest_block = w3.eth.get_block('latest', full_transactions=True)
    LARGE_TX_THRESHOLD = w3.to_wei(100, 'ether')
    suspicious_txs = []
    #For each transaction in latest block, if the amouth of ETH is larger than 100, its suspicious
    for tx in latest_block.transactions:
        if tx.value > LARGE_TX_THRESHOLD:
            suspicious_txs.append({
                'hash': tx.hash.hex(),
                'from': tx['from'],
                'to': tx.to,
                'value_eth': float(w3.from_wei(tx.value, 'ether')),
                'gas_price': tx.gasPrice
            })
    
    return suspicious_txs

#Find transactions interacting with smart contracts"""

def monitor_smart_contract_interactions():
    print("\n🤖 Scanning for smart contract interactions...")

    latest_block = w3.eth.get_block('latest', full_transactions=True)
    smart_contract_txs = []

    for tx in latest_block.transactions[:10]:
        if tx.to and is_smart_contract(tx.to): #tx.to makes sure not creating new contract
            smart_contract_txs.append({
                'hash': tx.hash.hex(),
                'from': tx['from'],
                'to': tx.to,
                'value_eth': float(w3.from_wei(tx.value, 'ether'))
            })
    return smart_contract_txs
#Check if a transaction has token transfer events
def detect_token_transfers(tx_hash):
    
    receipt = w3.eth.get_transaction_receipt(tx_hash) #Finds all the event logs for transaction

    if receipt.logs:
        print(f"📋 Transaction {tx_hash.hex()} has {len(receipt.logs)} events")
        return True
    else:
        print(f"📋 Transaction {tx_hash.hex()} has no events")
        return False

def decode_token_transfer_event(tx_hash):
    receipt = w3.eth.get_transaction_receipt(tx_hash)

    if receipt.logs:
        print(f"🔍 Found {len(receipt.logs)} events, checking each one...")
        
        for i, event in enumerate(receipt.logs): #Goes through events
            print(f"\n--- Event {i+1} ---")
            
            hex_amount = event['data'].hex()
            
            if hex_amount and len(hex_amount) > 0:
                try:
                    decimal_amount = int(hex_amount, 16) #Converts to dec
                    if decimal_amount > 0:
                        contract_address = event['address']
                        decimals = get_token_decimals(contract_address)
                        divisor = 10 ** decimals
                        
                        
                        token_amount = decimal_amount / divisor
                        
                        # Get addresses
                        if len(event['topics']) >= 3:
                            from_hex = event['topics'][1].hex()
                            to_hex = event['topics'][2].hex()
                            from_address = "0x" + from_hex[-40:]
                            to_address = "0x" + to_hex[-40:]

                            print(f"💰 {token_amount:,.6f} tokens transferred")
                            print(f"🔢 Token uses {decimals} decimal places")
                            print(f"📤 From: {from_address}")
                            print(f"📥 To: {to_address}")
                            print(f"🏦 Contract: {contract_address}")
                        break
                except ValueError:
                    print("Not a valid amount")
            else:
                print("No amount data")
    else:
        print("No events in this transaction")

#Continuously monitor new blocks for suspicious activity
    
def real_time_monitor():
    
    print("🚀 Starting real-time DeFi security monitor...")
    print("Press Ctrl+C to stop\n")
    
    # Get the current block number
    last_checked_block = w3.eth.block_number
    print(f"📊 Starting from block {last_checked_block}")
    
    while True:  # Run forever
        try:
            # Check if there's a new block
            current_block = w3.eth.block_number
            
            if current_block > last_checked_block:
                print(f"\n🆕 New block detected: {current_block}")
                
               # Check for large ETH transfers
                large_txs = monitor_large_transactions()
    
                    # Check for smart contract activity  
                contract_txs = monitor_smart_contract_interactions()
    
                # Shows findings
                if large_txs:
                     print(f"🚨 ALERT: {len(large_txs)} large transactions!")
                if len(contract_txs) > 20:  # Lots of DeFi activity
                    print(f"📈 High DeFi activity: {len(contract_txs)} transactions")
                    last_checked_block = current_block
                else:
                    print("⏳ Waiting for new block...", end="\r")
            
            time.sleep(8)  
            
        except KeyboardInterrupt:
            print("\n🛑 Monitor stopped by user")
            break
#Finds transactions with failed contracts which could be suspicious
def monitor_failed_transactions():
    try:
        
        latest_block = w3.eth.get_block('latest', full_transactions=True)
        failed_contracts = {}
        
        
        for tx in latest_block.transactions[:10]:
            # Get receipt to see if transaction failed
            receipt = w3.eth.get_transaction_receipt(tx.hash)
            
            # If transaction failed
            if receipt.status == 0:
                contract_address = tx.to
                if contract_address:  
                    if contract_address in failed_contracts:
                        failed_contracts[contract_address] += 1
                    else:
                        failed_contracts[contract_address] = 1
        
        # contracts with multiple failures 
        suspicious_contracts = []
        for contract, fail_count in failed_contracts.items():
            if fail_count >= 2:
                suspicious_contracts.append({
                    'contract': contract,
                    'failed_count': fail_count
                })
        
        return suspicious_contracts
        
    except Exception as e:
        print(f"Error: {e}")
        return []
            
#Checks for valid eth addresses   
def is_valid_eth_address(address):
    """Validate Ethereum address format"""
    import re
    if not address:
        return False
    # Check if it matches Ethereum address pattern
    pattern = re.compile(r'^0x[a-fA-F0-9]{40}$')
    return bool(pattern.match(address))




# ============ RUN TESTS ============

if __name__ == "__main__":
    real_time_monitor()
