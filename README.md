# 🧠 PCAP Port Scan Detector

A Python-based tool that uses **machine learning classifiers** to detect **potential port scans** in `.pcap` files. Designed for network analysts, blue teamers, and cybersecurity students who want a lightweight ML-powered threat detector.

---

## 🚀 Features

- ✅ Parses PCAP files with `scapy`
- 🧠 Extracts meaningful features like SYN counts, port diversity, and protocol usage
- 📊 Trains and evaluates multiple classifiers:
  - Logistic Regression
  - Random Forest
  - Support Vector Machine (SVM)
- 🔍 Predicts if a capture contains scanning behavior or is benign
- 📝 Easily extensible for real-world traffic analysis or CTF use cases

---

## 📦 Dependencies

Install these via `pip`:

```bash
pip install scapy pandas scikit-learn
```
##🛠️ Usage
Clone the repo:

```bash

git clone https://github.com/yourusername/pcap-scan-detector.git
cd pcap-scan-detector
```
## Run the detector:

```bash
python scan_detector.py
```
Update this line in the script with your PCAP file path:
```

```python
file_path = "your_input.pcap"
```

Example output:

```csharp

[Logistic Regression] Prediction: SCAN DETECTED
[Random Forest] Prediction: SCAN DETECTED
[SVM] Prediction: SCAN DETECTED
```
## 📊 Sample Features Extracted

Feature	Description
syn_count	Count of SYN packets
unique_ports	Count of unique destination ports
unique_dst_ips	Number of unique destination IPs
tcp_count	Total TCP packets
udp_count	Total UDP packets
## 🖼️ Screenshots
Add screenshots of terminal output or logs here:
<TO DO>
## 🔎 Sample Detection Output
<TO DO>

## 📁 File Structure
```yaml
pcap-scan-detector/
├── scan_detector.py
├── sample_pcap_files/
│   └── nmap_scan.pcap
├── assets/
│   └── scan_output.png
└── README.md
```
## 🧠 Future Ideas
 Train on more labeled PCAPs!

 Add exportable JSON or CSV logs

 Build CLI flags for batch processing

 Integrate YARA or Suricata rule insights

 Add timestamped visualizations with Matplotlib

## 🧙🏽‍♂️ Author
Developed by Colin Torbett, cybersecurity enthusiast and pcap wrangler.
Contributions and suggestions welcome!

## 📜 License
This project is licensed under the MIT License. See LICENSE for details.