# AI Powered Intrusion Detection System (IDS)

## Overview
This **Intrusion Detection System (IDS)** is a **machine learning-based cybersecurity tool** that:

✔ **Captures live network traffic** to detect malicious activity.  
✔ **Analyzes & classifies threats** using a trained **Random Forest model**.  
✔ **Uses the NSL-KDD dataset** for training to detect cyberattacks.  
✔ **Logs intrusions in InfluxDB** for real-time monitoring.  
✔ **Visualizes attack data in Grafana dashboards**.  
✔ **Sends alerts** when threats are detected.  

---

## Tools & Frameworks
This project is built using the following tools and frameworks:

| **Tool/Framework**  | **Purpose** |
|-------------------|------------|
| `Scapy` | Packet sniffing & live network traffic capture |
| `Pandas` | Data manipulation & preprocessing |
| `Joblib` | Model saving/loading |
| `Scikit-learn` | Machine learning (Random Forest Classifier) |
| `InfluxDB` | Storing intrusion logs |
| `Grafana` | Visualization of IDS alerts and logs |
| `smtplib` | Email alert system |
| `Ubuntu` | Server framework for accessing **InfluxDB** & **Grafana** |

---

## ⚙️ Frameworks Installation
Run the following command to install the required dependencies:
```bash
pip install scapy pandas joblib scikit-learn influxdb tqdm
```

To set up **InfluxDB** and **Grafana** on Ubuntu, run:
```bash
sudo apt update && sudo apt install influxdb grafana
sudo systemctl enable --now influxdb grafana
```

---

## Project Phases

### **1️⃣ Capture Live Network Traffic**
#### **What this part is about?**
Captures real-time network traffic, extracting key features for intrusion detection.

#### **Main logic:**
- **Sniffs 200 packets** from the network.
- Extracts **IP addresses, ports, protocol type, and payload details**.
- Saves data for **machine learning classification**.

```python
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd

def process_packet(packet):
    if IP in packet:
        captured_data.append([
            packet[IP].src, packet[IP].dst, packet[IP].proto,
            packet[TCP].sport if TCP in packet else 0,
            packet[TCP].dport if TCP in packet else 0,
            len(packet), packet[IP].ttl, len(packet.payload)
        ])

captured_data = []
print("🔍 Capturing network traffic...")
sniff(prn=process_packet, count=200)
df_live = pd.DataFrame(captured_data, columns=["src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "ttl", "payload_length"])
print(f"✅ Captured {len(df_live)} packets!")
```

#### **Outcome:**
✅ Captures **200 network packets** for analysis.
✅ Extracts **IP addresses, ports, and protocols**.

💡 **Example Output:**
```
🔍 Capturing network traffic...
✅ Captured 200 packets!
```

---

### **6️⃣ Visualize Intrusion Logs in Grafana**
#### **What this part is about?**
Uses **Grafana** to visualize logged intrusion data from **InfluxDB**.

#### **Main logic:**
- **Connects Grafana to InfluxDB** as a data source.
- **Creates dashboards** to display network intrusion alerts.
- **Monitors live attack trends** using real-time graphs.

#### **Steps to Setup Grafana for IDS Logs:**
1. **Open Grafana Dashboard**: Navigate to `http://localhost:3000`.
2. **Add Data Source**: Choose **InfluxDB** and connect it to `http://localhost:8086`.
3. **Create Dashboards**: Use InfluxDB queries to display:
   - **Number of intrusions per hour**.
   - **Types of attacks detected**.
   - **Source IPs generating malicious traffic**.

#### **Outcome:**
✅ **Real-time visualization of network attacks**.
✅ **Monitor intrusion trends via dynamic dashboards**.

💡 **Example Grafana Dashboard:**
http://localhost:3000/d/ceeev455zvqpse/intrusions-detection-system?orgId=1&from=2024-03-07T08:48:05.971Z&to=2025-03-07T08:48:05.971Z&timezone=browser&tab=queries&viewPanel=panel-4&theme=light

---
