import random
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

def get_location_from_hash(hash_string):
    """
    Generate consistent geographic coordinates from a transaction hash or address.
    The same hash will always produce the same coordinates.
    """
    # Take the last 16 characters of the hash to use as our seed
    seed_hex = hash_string[-16:]
    
    # Convert hex to integer
    seed = int(seed_hex, 16)
    
    # Use the seed to create a deterministic random generator
    rng = random.Random(seed)
    
    # Generate latitude (-85 to +85, avoiding the poles)
    lat = rng.uniform(-85, 85)
    
    # Generate longitude (-180 to +180)
    lon = rng.uniform(-180, 180)
    
    return lat, lon

def collect_real_threat_data(suspicious_addresses, sandwich_attacks, rug_pull_alerts, failed_tx_alerts, token_traps):
    """Collect real threat data from our monitoring"""
    threats = []
    
    # Process suspicious addresses (high frequency activity)
    for address_data in suspicious_addresses:
        address = address_data['address']
        # Generate location from address
        lat, lon = get_location_from_hash(address)
        
        threats.append({
            'type': 'High-Frequency Activity',
            'address': address,
            'severity': 'Medium',
            'lat': lat,
            'lon': lon,
            'size': 10 + address_data['count'],  # Size based on transaction count
            'hover_data': f"High-Frequency: {address[:10]}... ({address_data['count']} txs)"
        })
    
    # Process sandwich attacks
    for attack in sandwich_attacks:
        address = attack['address']
        lat, lon = get_location_from_hash(address)
        
        threats.append({
            'type': 'Sandwich Attack',
            'address': address,
            'severity': 'High',
            'lat': lat,
            'lon': lon,
            'size': 15,
            'hover_data': f"Sandwich Attack: {address[:10]}..."
        })
    
    # Process rug pull alerts
    for alert in rug_pull_alerts:
        address = alert['address']
        lat, lon = get_location_from_hash(address)
        
        threats.append({
            'type': 'Rug Pull',
            'address': address,
            'severity': 'Critical',
            'lat': lat,
            'lon': lon,
            'size': 20,
            'hover_data': f"Rug Pull: {address[:10]}... ({alert['amount']:.2f} ETH)"
        })
    
    # Process honeypot contracts
    for alert in failed_tx_alerts:
        contract = alert['contract']
        lat, lon = get_location_from_hash(contract)
        
        threats.append({
            'type': 'Honeypot',
            'address': contract,
            'severity': 'Medium',
            'lat': lat,
            'lon': lon,
            'size': 10,
            'hover_data': f"Honeypot: {contract[:10]}... ({alert['failed_count']} failures)"
        })
    
    # Process token traps
    for trap in token_traps:
        contract = trap['contract']
        lat, lon = get_location_from_hash(contract)
        
        threats.append({
            'type': 'Token Trap',
            'address': contract,
            'severity': 'High',
            'lat': lat,
            'lon': lon,
            'size': 15,
            'hover_data': f"Token Trap: {contract[:10]}... (In: {trap['incoming']}, Out: {trap['outgoing']})"
        })
    
    return threats

def display_threat_map(suspicious_addresses, sandwich_attacks, rug_pull_alerts, failed_tx_alerts, token_traps):
    """Display the threat map in the Streamlit app"""
    # Store threats in session state to build history
    if 'threat_history' not in st.session_state:
        st.session_state.threat_history = []

    # Add current threats to history
    current_threats = collect_real_threat_data(
        suspicious_addresses, sandwich_attacks, rug_pull_alerts, failed_tx_alerts, token_traps
    )
    
    if current_threats:
        st.session_state.threat_history.extend(current_threats)
        
        # Keep only the last 50 threats
        if len(st.session_state.threat_history) > 50:
            st.session_state.threat_history = st.session_state.threat_history[-50:]

    # Add a threat map with real data
    st.markdown("### 🗺️ Global Threat Map")

    # If we have threat data, use it
    if st.session_state.threat_history:
        # Convert to DataFrame
        map_data = pd.DataFrame(st.session_state.threat_history)
        
        # Create the map
        fig = px.scatter_geo(map_data, lat='lat', lon='lon',
                            color='severity', size='size',
                            hover_name='hover_data',
                            color_discrete_map={
                                'Low': 'blue', 
                                'Medium': 'orange', 
                                'High': 'red',
                                'Critical': 'darkred'
                            },
                            projection='natural earth')
        fig.update_layout(height=400, margin={"r":0,"t":0,"l":0,"b":0})
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        # If no threats, show empty map with message
        st.info("No security threats detected - map is clear")
        
        # Show empty world map
        fig = go.Figure(go.Scattergeo())
        fig.update_layout(height=400, margin={"r":0,"t":0,"l":0,"b":0})
        
        st.plotly_chart(fig, use_container_width=True)