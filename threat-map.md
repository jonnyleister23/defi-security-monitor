# 🗺️ Threat Map Tab

![DeFi Security Monitor Dashboard](screenshots/Threatmap.png)

## 📖 Overview  
The **Threat Map** tab provides a **global visualization of blockchain security threats**, offering geographical context to detected malicious activities and a comprehensive **threat intelligence dashboard**.

---

## 📊 Key Components  

### 1. Global Threat Map  
- 🌍 Interactive world map displaying detected security threats  
- 🎨 Color-coded indicators showing severity:  
  - 🔴 **Red dots** → High severity threats  
  - 🟠 **Orange dots** → Medium severity threats  
  - 🔵 **Blue dots** → Low severity threats
 
- 📌 **Geolocation is NOT accurate (Randomizes coordinates based on wallet address (Same wallet will show up at the same coordinates))  

---

### 2. Threat Intelligence Panels  
The intelligence section includes **three key tabs**:  

#### 🔹 Recent Threats  
- Displays the **most recently detected security incidents**  
- Shows: *“No threats detected in the current monitoring session”* when clean  
- When threats are detected, provides:  
  - Threat type (e.g., Sandwich Attack, Rug Pull, etc.)  
  - Associated addresses  
  - Risk level  
  - Detection time  

#### 🔹 Historical Data  
- Visualizes **threat patterns over time**  
- Tracks different categories of threats:  
  - High-Frequency Activity  
  - Sandwich Attacks  
  - Rug Pulls  
  - Honeypot Contracts  
  - Token Traps  
- **Only historical data (Does NOT update)
#### 🔹 Known Attackers  
- Database of **identified malicious addresses**  
- Sourced from **MyEtherWallet’s darklist**  
- Includes:  
  - Address details  
  - Comments  
  - Date added  

---

### 3. Threat Visualization Logic  
The **map** uses a **hash-based algorithm** to:  

- 🔑 Generate **consistent coordinates** for each unique address  
- 📍 Ensure the same address always appears at the same location  
- 🕸️ Create **visual patterns** of related malicious activities  

---

## ⚡ Security Applications  

- **Geographic Patterns:** Identify clusters of related threats  
- **Threat Intelligence:** Access a comprehensive database of known attackers  
- **Visual Monitoring:** Quickly assess the global threat landscape  
- **Historical Context:** Track how threats evolve over time  

---

