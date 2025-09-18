# DeFi Security Monitor

##Live App    

https://defi-security-monitor-project.streamlit.app    



## Watch the demo    
[![Watch the demo](https://img.youtube.com/vi/BjWg1ltNm_Q/0.jpg)](https://youtu.be/BjWg1ltNm_Q)


## Overview

**DeFi Security Monitor** is a real-time blockchain security monitoring system that detects and visualizes potential threats on the Ethereum network.  

The dashboard provides **live monitoring, threat detection, and security insights** for DeFi users while also serving as an educational tool for blockchain security.

---

## ✨ Features

### 🔍 Real-Time Monitoring
- Live Ethereum blockchain connection via Infura
- Gas price tracking and visualization
- Smart contract interaction monitoring
- Large transaction detection

### 🛡️ Security Analysis
- Risk scoring system
- Network congestion monitoring
- Transaction volume analysis
- Security metrics dashboard

### 🚨 Threat Detection
- High-frequency activity alerts
- Sandwich attack detection
- Rug pull early warning system
- Token trap & honeypot contract detection

### 🌐 Visualization
- Global threat mapping
- Historical threat patterns
- Known malicious address database integration

### 👛 Wallet Scanner
- Address risk assessment
- Malicious address checking
- Etherscan API integration

### 📚 Security Resources
- DeFi security best practices
- Common attack vector explanations
- Security incident case studies
- Interactive security quiz

---

## 🛠 Technologies Used

- **Python**: Core programming language  
- **Web3.py**: Ethereum blockchain interaction  
- **Streamlit**: Dashboard interface & visualization  
- **Plotly**: Interactive charts & graphs  
- **MyEtherWallet API**: Malicious address database  

---

## 📂 Project Structure

```plaintext
defi-security-monitor/
├── dashboard.py          # Main Streamlit dashboard
├── defi_monitor.py       # Core blockchain monitoring logic
├── threat_map.py         # Threat Map functions
├── requirements.txt      # Python dependencies
├── .env.example          # Example environment file
└── README.md             # Project documentation
