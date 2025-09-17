import streamlit as st
from defi_monitor import w3, monitor_large_transactions, monitor_smart_contract_interactions, monitor_failed_transactions, is_valid_eth_address
from threat_map import display_threat_map
import plotly.graph_objects as go
# Add these imports
from collections import defaultdict
import time

# Add Content Security Policy
st.markdown("""
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
""", unsafe_allow_html=True)



# Simple rate limiter class - add after imports
class RateLimiter:
    def __init__(self, max_calls, time_frame):
        self.max_calls = max_calls
        self.time_frame = time_frame  # in seconds
        self.calls = defaultdict(list)
        
    def is_allowed(self, key):
        current_time = time.time()
        # Remove old calls
        self.calls[key] = [t for t in self.calls[key] if current_time - t < self.time_frame]
        # Check if under limit
        if len(self.calls[key]) < self.max_calls:
            self.calls[key].append(current_time)
            return True
        return False

# Create limiter instances
wallet_limiter = RateLimiter(max_calls=10, time_frame=60)  # 5 calls per minute





# Add custom CSS for centered text
st.markdown("""
<style>
    .centered {
        text-align: center;
    }
    .stSuccess, .stError, .stWarning, .stInfo {
        text-align: center !important;
    }
    div[data-testid="stExpander"] div[data-testid="stExpanderContent"] p {
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Add a professional header with logo and description
st.markdown("""
<div style="margin-bottom: 20px;">
    <div style="display: flex; align-items: center; justify-content: center;">
        <h1 style="margin: 0; font-size: 42px; display: flex; align-items: center;">
            <span style="font-size: 32px; margin-right: 10px;">🔒</span>
            DeFi Security Monitor
            <span style="font-size: 32px; margin-left: 10px;">🔒</span>
        </h1>
    </div>
    <p style="color: gray; margin: 0; text-align: center;">
        Real-time blockchain security monitoring and threat detection
    </p>
</div>
""", unsafe_allow_html=True)

# Connection status
if w3.is_connected():
    st.write("🟢 Connected to Ethereum")
else:
    st.write("🔴 Not Connected")

# Get blockchain data
current_block = w3.eth.block_number
gas_price = w3.eth.gas_price/1000000000

# Store gas price history

# Store gas price history - FIXED VERSION
if 'gas_prices' not in st.session_state:
    st.session_state.gas_prices = []
    st.session_state.last_update_time = time.time()
    st.session_state.gas_prices.append(gas_price)
else:
    # Only update every 30 seconds
    current_time = time.time()
    if current_time - st.session_state.last_update_time > 30:
        st.session_state.gas_prices.append(gas_price)
        st.session_state.last_update_time = current_time
# Get monitoring data
large_txs = monitor_large_transactions()
contract_txs = monitor_smart_contract_interactions()
failed_tx_alerts = monitor_failed_transactions()

# Suspicious patterns detection
address_counts = {}
for tx in contract_txs:
    address = tx['from']
    if address in address_counts:
        address_counts[address] += 1
    else:
        address_counts[address] = 1
suspicious_addresses = []
for address, count in address_counts.items():
    if count > 2:
        suspicious_addresses.append({'address': address, 'count': count})

# Sandwich attack detection
if 'transaction_history' not in st.session_state:
    st.session_state.transaction_history = []

# Only keep transactions from last 3 blocks
current_block = w3.eth.block_number
recent_transactions = []
for tx in st.session_state.transaction_history:
    if tx['block'] >= current_block - 2:  # Keep last 3 blocks
        recent_transactions.append(tx)
st.session_state.transaction_history = recent_transactions

# Detect sandwich attacks
sandwich_attacks = []
for tx1 in recent_transactions:
    for tx2 in recent_transactions:
        if (tx1['address'] == tx2['address'] and tx1['token'] == tx2['token'] and tx2['block'] == tx1['block'] + 1):     
            sandwich_attacks.append({'address': tx1['address'], 'token': tx1['token'],'blocks': [tx1['block'], tx2['block']]})

# Detect potential rug pulls
rug_pull_alerts = []
for tx in contract_txs:
    eth_amount = tx['value_eth']
    if eth_amount >= 100:  # Critical risk
        risk_level = "🔴 CRITICAL"
        rug_pull_alerts.append({'address': tx['from'], 'amount': eth_amount, 'risk': risk_level})
    elif eth_amount >= 50:  # High risk  
        risk_level = "🟠 HIGH"
        rug_pull_alerts.append({'address': tx['from'], 'amount': eth_amount, 'risk': risk_level})
    elif eth_amount >= 10:  # Medium risk
        risk_level = "🟡 MEDIUM"
        rug_pull_alerts.append({'address': tx['from'], 'amount': eth_amount, 'risk': risk_level})

# Token Traps detection
contract_activity = {}
for tx in contract_txs:
    from_address = tx['from']
    to_address = tx['to']
    if from_address not in contract_activity:
        contract_activity[from_address] = {'incoming': 0, 'outgoing': 0}
    if to_address not in contract_activity:
        contract_activity[to_address] = {'incoming': 0, 'outgoing': 0}
    contract_activity[from_address]['outgoing'] += 1
    contract_activity[to_address]['incoming'] += 1

# Find suspicious contracts (only receive, never send)
token_traps = []
for address, activity in contract_activity.items():
    incoming = activity['incoming']
    outgoing = activity['outgoing']
    if incoming >= 3 and outgoing == 0:  # Gets 3+ transactions but sends 0
        token_traps.append({
            'contract': address,
            'incoming': incoming,
            'outgoing': outgoing
        })

# Calculate risk score
risk_score = 0
risk_factors = []
if suspicious_addresses:
    risk_score += len(suspicious_addresses) * 10
    risk_factors.append(f"High-frequency activity: +{len(suspicious_addresses) * 10}")
if sandwich_attacks:
    risk_score += len(sandwich_attacks) * 15
    risk_factors.append(f"Sandwich attacks: +{len(sandwich_attacks) * 15}")
if rug_pull_alerts:
    risk_score += len(rug_pull_alerts) * 20
    risk_factors.append(f"Potential rug pulls: +{len(rug_pull_alerts) * 20}")
if failed_tx_alerts:
    risk_score += len(failed_tx_alerts) * 5
    risk_factors.append(f"Honeypot contracts: +{len(failed_tx_alerts) * 5}")
if token_traps:
    risk_score += len(token_traps) * 15
    risk_factors.append(f"Token traps: +{len(token_traps) * 15}")

# Sidebar content
st.sidebar.title("🚨Security Alerts🚨")

# Display alerts in sidebar
if suspicious_addresses:
    st.sidebar.warning(f"🚨 Alert! Found {len(suspicious_addresses)} suspicious addresses")
    for item in suspicious_addresses:
        st.sidebar.write(f"Suspicious Address: {item['address']} Tx Count: {item['count']}")
else:
    st.sidebar.success("✅ No Suspicious Activity Detected") 

if sandwich_attacks:
    st.sidebar.error(f"🥪 {len(sandwich_attacks)} Potential Sandwich Attacks!")
    for attack in sandwich_attacks:
        st.sidebar.write(f"⚠️ {attack['address'][:10]}... in blocks {attack['blocks']}")
else:
    st.sidebar.success("✅ No Sandwhich Attacks Detected")

if rug_pull_alerts:
    st.sidebar.warning(f"🚨 Alert! Found {len(rug_pull_alerts)} Potential Rug Pull Activities")
    for alert in rug_pull_alerts:
        st.sidebar.write(f"{alert['risk']} {alert['address'][:10]}... withdrew {alert['amount']:.2f} ETH")
else:
    st.sidebar.success("✅ No Rug Pulls Detected")

st.sidebar.title("🎣Phishing Alerts🎣")

if failed_tx_alerts:
    st.sidebar.error(f"🎣 {len(failed_tx_alerts)} Potential Honeypots Detected!")
    for alert in failed_tx_alerts:
        st.sidebar.write(f"⚠️ {alert['contract'][:10]}... ({alert['failed_count']} failures)")
else:
    st.sidebar.success("✅ No Honeypot Contracts Detected")

if token_traps:
    st.sidebar.error(f"🕳️ {len(token_traps)} Potential Token Traps Detected!")
    for trap in token_traps:
        st.sidebar.write(f"⚠️ {trap['contract'][:10]}... (In: {trap['incoming']}, Out: {trap['outgoing']})")
else:
    st.sidebar.success("✅ No Token Traps Detected")

with st.sidebar.expander("ℹ️ What are these alerts?"):
    st.markdown("""
    **Suspicious Activity:** Addresses making multiple transactions in a short time, which may indicate bot activity or market manipulation.
    
    **Sandwich Attacks:** When a malicious actor places transactions before and after a victim's transaction, manipulating prices to profit.
    
    **Rug Pulls:** When developers suddenly withdraw all liquidity, leaving investors with worthless tokens.
    
    **Honeypot Contracts:** Smart contracts that allow deposits but prevent withdrawals, trapping users' funds.
    
    **Token Traps:** Contracts that receive tokens but never send any out, indicating a potential scam.
    """)









# Create tabs for different dashboard sections
tab1, tab2, tab3, tab4,tab5 = st.tabs(["🔍 Monitoring", "🛡️ Security Analysis", "🌐 Threat Map", "👛 Wallet Scanner","📚 Security Resources"])

with tab1:
    # Gas price chart
    st.subheader("Real-Time Gas Prices")
    if len(st.session_state.gas_prices) > 1:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            y=st.session_state.gas_prices,
            mode='lines+markers',
            name='Gas Price (Gwei)'
        ))
        fig.update_layout(height=300, margin={"r":0,"t":0,"l":0,"b":0})
        st.plotly_chart(fig, use_container_width=True)
    
    # Key metrics
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Current Block", f"{current_block:,}")
    with col2:
        st.metric("Gas Price", f"{gas_price:.2f} Gwei")
    with col3:
        st.metric("Large Transactions", len(large_txs))
    with col4:
        st.metric("Smart Contract Interactions", len(contract_txs))
    
    # Recent activity
    st.markdown("<br>", unsafe_allow_html=True)
    st.subheader("Recent Activity")
    if contract_txs:
        tx_data = []
        for i, tx in enumerate(contract_txs[:5]):
            tx_type = "Token Transfer" if tx['value_eth'] == 0 else "ETH Transfer"
            tx_data.append({
                "Time": "Just now" if i == 0 else f"{i} min ago",
                "Type": tx_type,
                "Amount": f"{tx['value_eth']:.4f} ETH" if tx['value_eth'] > 0 else "Token",
                "Address": f"{tx['to'][:6]}...{tx['to'][-4:]}"
            })
        st.table(tx_data)
    else:
        st.info("No recent transactions")
    
if st.button("Refresh Data"):
    st.session_state["do_refresh"] = True
    st.experimental_rerun()  # restart the script

# --- On rerun, check the flag ---
if st.session_state.get("do_refresh", False):
    # 👇 Refresh logic goes here
    st.write("Refreshing all data at", time.strftime("%X"))

    # Reset flag so it doesn’t loop
    st.session_state["do_refresh"] = False

with tab2:
    # Security metrics
    st.subheader("Security Analysis")
    security_col1, security_col2, security_col3, security_col4 = st.columns(4)
    with security_col1:
        if risk_score == 0:
            st.metric("Risk Score", "0", "Low")
        elif risk_score < 30:
            st.metric("Risk Score", str(risk_score), "Medium")
        else:
            st.metric("Risk Score", str(risk_score), "HIGH", delta_color="inverse")
    
    with security_col2:
        gas_congestion = "Low" if gas_price < 15 else "Medium" if gas_price < 50 else "High"
        st.metric("Network Congestion", gas_congestion)
        
    with security_col3:
        tx_volume = len(contract_txs)
        st.metric("Transaction Volume", tx_volume)
        
    with security_col4:
        total_alerts = len(suspicious_addresses) + len(sandwich_attacks) + len(rug_pull_alerts) + len(failed_tx_alerts) + len(token_traps)
        alert_status = "None" if total_alerts == 0 else "Low" if total_alerts < 3 else "High"
        st.metric("Security Alerts", total_alerts, alert_status)
    
    # Risk factors
    if risk_factors:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("View Risk Factor Details"):
            for factor in risk_factors:
                st.write(factor)
    
    # Add token prices section here if you have it
    # display_token_prices()

with tab3:
    # Your existing threat map code
    display_threat_map(suspicious_addresses, sandwich_attacks, rug_pull_alerts, failed_tx_alerts, token_traps)
    
    # Add interactive threat details
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 🔍 Threat Intelligence")
    threat_tabs = st.tabs(["Recent Threats", "Historical Data", "Known Attackers"])
    
    with threat_tabs[0]:
        st.markdown("#### Most Recent Security Threats")
        
        # Combine all threats for display
        all_threats = []
        
        # Add suspicious addresses
        for item in suspicious_addresses:
            all_threats.append({
                "Type": "High-Frequency Activity",
                "Address": item['address'][:10] + "...",
                "Details": f"{item['count']} transactions",
                "Risk": "Medium",
                "Time": "Just now"
            })
            
        # Add sandwich attacks
        for attack in sandwich_attacks:
            all_threats.append({
                "Type": "Sandwich Attack",
                "Address": attack['address'][:10] + "...",
                "Details": f"Blocks {attack['blocks']}",
                "Risk": "High",
                "Time": "2 min ago"
            })
            
        # Add rug pulls
        for alert in rug_pull_alerts:
            all_threats.append({
                "Type": "Rug Pull",
                "Address": alert['address'][:10] + "...",
                "Details": f"{alert['amount']:.2f} ETH withdrawn",
                "Risk": alert['risk'].split()[1],
                "Time": "5 min ago"
            })
            
        # Add honeypots
        for alert in failed_tx_alerts:
            all_threats.append({
                "Type": "Honeypot Contract",
                "Address": alert['contract'][:10] + "...",
                "Details": f"{alert['failed_count']} failed transactions",
                "Risk": "Medium",
                "Time": "10 min ago"
            })
            
        # Add token traps
        for trap in token_traps:
            all_threats.append({
                "Type": "Token Trap",
                "Address": trap['contract'][:10] + "...",
                "Details": f"In: {trap['incoming']}, Out: {trap['outgoing']}",
                "Risk": "High",
                "Time": "15 min ago"
            })
        
        # Display threats as a table
        if all_threats:
            import pandas as pd
            threat_df = pd.DataFrame(all_threats)
            st.table(threat_df)
        else:
            st.info("No threats detected in the current monitoring session")
        
    with threat_tabs[1]:
        st.markdown("#### Historical Threat Patterns")
        
        # Simulated historical data
        st.markdown("""
        Historical threat data shows patterns of activity over time. In a production system, 
        this would display trends from your threat database.
        """)
        
        # Create sample historical data
        import numpy as np
        import pandas as pd
        
        # Generate dates for the past 7 days
        import datetime
        dates = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7, 0, -1)]
        
        # Generate random threat counts
        np.random.seed(42)  # For reproducibility
        threat_types = ["High-Frequency", "Sandwich Attack", "Rug Pull", "Honeypot", "Token Trap"]
        historical_data = {}
        
        for threat in threat_types:
            historical_data[threat] = np.random.randint(0, 10, size=7)
        
        # Create DataFrame
        hist_df = pd.DataFrame(historical_data, index=dates)
        
        # Plot historical data
        st.line_chart(hist_df)
        
    with threat_tabs[2]:
        st.markdown("#### Known Malicious Addresses")
    
        # Import the requests library
        import requests
        import pandas as pd
        import math
    
        # Function to fetch MEW darklist
        def fetch_mew_darklist():
            """Fetch the MyEtherWallet darklist of malicious addresses"""
            url = "https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json"
        
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                
                    # Process the data into our format
                    formatted_data = []
                    for item in data:
                        formatted_data.append({
                            "Address": item.get("address", "Unknown"),
                            "Comment": item.get("comment", ""),
                            "Date Added": item.get("date", "Unknown")
                        })
                
                    return formatted_data
                else:
                    return []
            except Exception as e:
                st.error(f"Error fetching data: {e}")
                return []
    
        # Fetch data button
        if 'mew_addresses' not in st.session_state:
            st.session_state.mew_addresses = []
        
        if st.button("Load Malicious Addresses") or st.session_state.mew_addresses:
            if not st.session_state.mew_addresses:
                with st.spinner("Fetching malicious addresses from MyEtherWallet..."):
                    st.session_state.mew_addresses = fetch_mew_darklist()
        
            # Show stats and data
            if st.session_state.mew_addresses:
                st.success(f"Loaded {len(st.session_state.mew_addresses)} known malicious addresses")
            
                # Pagination
                items_per_page = 10
                total_pages = math.ceil(len(st.session_state.mew_addresses) / items_per_page)
            
                # Initialize current page if not exists
                if 'current_page' not in st.session_state:
                    st.session_state.current_page = 1
            
                # Page navigation
                col1, col2, col3 = st.columns([1, 3, 1])
            
                with col1:
                    if st.button("← Previous") and st.session_state.current_page > 1:
                        st.session_state.current_page -= 1
                        st.rerun()
            
                with col2:
                    page_numbers = []
                    start_page = max(1, st.session_state.current_page - 2)
                    end_page = min(total_pages, st.session_state.current_page + 2)
                
                    # Create page number buttons
                    page_cols = st.columns(end_page - start_page + 1)
                    for i, page in enumerate(range(start_page, end_page + 1)):
                        with page_cols[i]:
                            if st.button(str(page), key=f"page_{page}"):
                                st.session_state.current_page = page
                                st.rerun()
            
                with col3:
                    if st.button("Next →") and st.session_state.current_page < total_pages:
                        st.session_state.current_page += 1
                        st.rerun()
            
                # Display current page info
                st.markdown(f"**Page {st.session_state.current_page} of {total_pages}**")
            
                #   Calculate slice for current page
                start_idx = (st.session_state.current_page - 1) * items_per_page
                end_idx = min(start_idx + items_per_page, len(st.session_state.mew_addresses))
            
                # Display current page data
                current_page_data = st.session_state.mew_addresses[start_idx:end_idx]
                st.table(pd.DataFrame(current_page_data))
            else:
                st.error("Failed to fetch malicious addresses")
        else:
            st.info("Click the button to load the MyEtherWallet list of known malicious addresses")


with tab4:
    st.subheader("Wallet Risk Assessment")
    
    wallet_address = st.text_input("Enter Ethereum Address to Scan")
    
    # Now use the validation function here
    if wallet_address:
        if not is_valid_eth_address(wallet_address):
            st.error("Invalid Ethereum address format. Please enter a valid 42-character address starting with 0x.")
        else:
            with st.spinner("Scanning wallet..."):
                try:
                    # Check if address is in known malicious list
                    is_malicious = False
                    malicious_comment = ""
                    
                    if 'mew_addresses' in st.session_state and st.session_state.mew_addresses:
                        for addr in st.session_state.mew_addresses:
                            if addr["Address"].lower() == wallet_address.lower():
                                is_malicious = True
                                malicious_comment = addr.get("Comment", "Known malicious address")
                                break
                    
                    # Display results based on malicious check only
                    if is_malicious:
                        st.error("⚠️ HIGH RISK WALLET DETECTED!")
                        st.error(f"This address is flagged as malicious: {malicious_comment}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Risk Score", "95/100", "Critical", delta_color="inverse")
                        
                        st.warning("⚠️ DO NOT send funds to this address!")
                    else:
                        st.success("Wallet scan complete!")
                        st.info("No known malicious activity associated with this wallet.")
                    
                    # Link to Etherscan for more details
                    st.subheader("View Details")
                    st.info("To view detailed wallet information, check this address on Etherscan:")
                    # Sanitize the address for security
                    safe_address = wallet_address.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
                    st.markdown(f"[View on Etherscan](https://etherscan.io/address/{safe_address})")
                    
                except Exception as e:
                    st.error(f"Error scanning address: {str(e)}")
    else:
        st.info("Enter an Ethereum address to perform a security assessment")



with tab5:
    st.subheader("DeFi Security Resources")
    
    # Common scams section
    st.markdown("### Common DeFi Scams")
    st.markdown("""
    - **Phishing:** Fake websites that steal your private keys or seed phrases
    - **Rug Pulls:** Developers abandon a project and withdraw all funds
    - **Front-Running:** Bots that exploit pending transactions for profit
    - **Flash Loan Attacks:** Manipulating prices using borrowed funds
    - **Honeypot Contracts:** Smart contracts that allow deposits but prevent withdrawals
    """)
    
    # Security best practices
    st.markdown("### Security Best Practices")
    st.markdown("""
    - Use hardware wallets for large holdings
    - Never share your private keys or seed phrases
    - Verify smart contract addresses before interacting
    - Start with small transactions when using new protocols
    - Use multiple wallets to separate funds
    """)
    
    # Common attack vectors
    st.markdown("### Common Attack Vectors")
    
    attack_tab1, attack_tab2, attack_tab3 = st.tabs(["Smart Contract", "Social Engineering", "Protocol"])
    
    with attack_tab1:
        st.markdown("""
        #### Smart Contract Vulnerabilities
        
        - **Reentrancy:** Attackers call back into vulnerable contracts before state updates
        - **Integer Overflow/Underflow:** Mathematical operations exceed variable size limits
        - **Access Control Issues:** Missing or improper permission checks
        - **Logic Errors:** Flawed business logic in contract code
        - **Oracle Manipulation:** Tampering with price feed data
        """)
    
    with attack_tab2:
        st.markdown("""
        #### Social Engineering Attacks
        
        - **Phishing:** Fake websites, emails, or messages to steal credentials
        - **Impersonation:** Fake team members, support staff, or projects
        - **Airdrop Scams:** Malicious tokens sent to trick users into interacting
        - **Fake Projects:** Completely fabricated projects with stolen code
        - **Discord/Telegram Hacks:** Compromised community channels
        """)
    
    with attack_tab3:
        st.markdown("""
        #### Protocol-Level Attacks
        
        - **Flash Loan Attacks:** Borrowing large amounts to manipulate markets
        - **MEV Exploitation:** Extracting value by manipulating transaction order
        - **Governance Attacks:** Manipulating voting systems
        - **Economic Exploits:** Attacking tokenomics or incentive structures
        - **Bridge Hacks:** Exploiting cross-chain bridges
        """)
    
    # Major DeFi hacks
    st.markdown("### Notable DeFi Security Incidents")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        #### 2023-2024
        - **Euler Finance (2023):** $197M flash loan attack
        - **Multichain (2023):** $126M private key compromise
        - **Mixin Network (2023):** $200M database breach
        - **Curve Finance (2023):** $70M reentrancy vulnerability
        - **KyberSwap (2023):** $46M reentrancy exploit
        """)
    
    with col2:
        st.markdown("""
        #### 2021-2022
        - **Ronin Bridge (2022):** $625M private key compromise
        - **Wormhole (2022):** $325M bridge vulnerability
        - **Poly Network (2021):** $611M cross-chain exploit
        - **BadgerDAO (2021):** $120M front-end attack
        - **Cream Finance (2021):** $130M flash loan attack
        """)
    
    # Interactive case study
    st.markdown("### Case Study: Anatomy of a Flash Loan Attack")
    
    with st.expander("View Flash Loan Attack Breakdown"):
        st.markdown("""
        #### Step 1: Preparation
        Attacker identifies a vulnerability in a DeFi protocol's price oracle or liquidity pool.
        
        #### Step 2: Execution
        1. **Borrow:** Take out a massive flash loan (no collateral required)
        2. **Manipulate:** Use the borrowed funds to manipulate asset prices
        3. **Exploit:** Take advantage of the price discrepancy
        4. **Profit:** Extract value from the protocol
        5. **Repay:** Return the flash loan in the same transaction
        
        #### Step 3: Laundering
        Funds are often moved through mixers like Tornado Cash to obscure the trail.
        
        #### Example: Pancake Bunny Attack (May 2021)
        - Borrowed massive amounts of BNB via flash loan
        - Manipulated BUNNY price through complex swap operations
        - Minted large amounts of BUNNY at inflated price
        - Dumped BUNNY tokens on the market
        - Resulted in $45M loss and BUNNY price crash of 95%
        """)
    
    # Resources
    st.markdown("### Useful Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        #### Learning Resources
        - [Ethereum.org Security Guide](https://ethereum.org/en/security/)
        - [Smart Contract Weakness Registry](https://swcregistry.io/)
        - [DeFi Threat Matrix](https://github.com/defi-defense-dao/defi-risk-tools-list)
        - [Blockchain Security Database](https://consensys.github.io/blockchainSecurityDB/)
        """)
    
    with col2:
        st.markdown("""
        #### Monitoring Tools
        - [Etherscan](https://etherscan.io/)
        - [Tenderly](https://tenderly.co/)
        - [Forta Network](https://forta.org/)
        - [MistTrack](https://misttrack.io/)
        - [Chainalysis](https://www.chainalysis.com/)
        """)
    
    # Security checklist
    st.markdown("### DeFi Security Checklist")
    
    checklist_col1, checklist_col2 = st.columns(2)
    
    with checklist_col1:
        st.markdown("""
        #### Before Using a Protocol
        - [ ] Verify smart contract addresses
        - [ ] Check if code is audited
        - [ ] Research team background
        - [ ] Understand tokenomics
        - [ ] Check TVL history
        """)
    
    with checklist_col2:
        st.markdown("""
        #### Before Transactions
        - [ ] Double-check addresses
        - [ ] Verify transaction details
        - [ ] Start with small amounts
        - [ ] Set reasonable slippage
        - [ ] Check gas fees
        """)
    
    # Interactive quiz
    st.markdown("### Test Your Knowledge")
    
    with st.expander("Take the DeFi Security Quiz"):
        st.markdown("**Question 1:** What is the primary purpose of a flash loan?")
        q1 = st.radio(
            "Select one:",
            ["Long-term borrowing without collateral", 
             "Instant loan that must be repaid in the same transaction", 
             "Loan secured by NFTs",
             "Interest-free loan for 24 hours"],
            key="q1"
        )
        
        st.markdown("**Question 2:** Which of these is NOT a common sign of a rug pull?")
        q2 = st.radio(
            "Select one:",
            ["Anonymous team", 
             "Multiple security audits", 
             "Locked liquidity for only 1-2 days",
             "Excessive marketing with unrealistic promises"],
            key="q2"
        )
        
        if st.button("Check Answers"):
            score = 0
            if q1 == "Instant loan that must be repaid in the same transaction":
                st.success("Question 1: Correct! Flash loans must be borrowed and repaid within a single transaction.")
                score += 1
            else:
                st.error("Question 1: Incorrect. Flash loans must be borrowed and repaid within a single transaction.")
                
            if q2 == "Multiple security audits":
                st.success("Question 2: Correct! Multiple security audits are actually a positive sign.")
                score += 1
            else:
                st.error("Question 2: Incorrect. Multiple security audits are a positive sign, not a red flag for rug pulls.")
                
            st.write(f"Your score: {score}/2")



# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: gray; font-size: 12px;">
    <p>DeFi Security Monitor v1.0 | Last updated: September 2025</p>
    <p>Built for blockchain security</p>
</div>
""", unsafe_allow_html=True)
