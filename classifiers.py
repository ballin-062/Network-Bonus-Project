import pandas as pd
from scapy.all import rdpcap, TCP, UDP, IP
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

# === 1. Feature Extraction ===

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    syn_count = 0
    unique_ports = set()
    dst_ip_set = set()
    udp_count = 0
    tcp_count = 0

    for pkt in packets:
        if IP in pkt:
            dst_ip_set.add(pkt[IP].dst)

        if TCP in pkt:
            tcp_count += 1
            if pkt[TCP].flags == 'S':  # SYN flag
                syn_count += 1
                unique_ports.add(pkt[TCP].dport)
        elif UDP in pkt:
            udp_count += 1
            unique_ports.add(pkt[UDP].dport)

    return {
        "syn_count": syn_count,
        "unique_ports": len(unique_ports),
        "unique_dst_ips": len(dst_ip_set),
        "udp_count": udp_count,
        "tcp_count": tcp_count
    }

# === 2. Example Dataset ===
# We'll simulate labeled data for now (you can extend this with real labeled PCAPs)

# Simulate multiple examples from multiple PCAPs
data = [
    {"syn_count": 3, "unique_ports": 2, "unique_dst_ips": 1, "udp_count": 0, "tcp_count": 3, "label": 0},  # benign
    {"syn_count": 100, "unique_ports": 90, "unique_dst_ips": 1, "udp_count": 2, "tcp_count": 102, "label": 1},  # scan
    {"syn_count": 2, "unique_ports": 2, "unique_dst_ips": 1, "udp_count": 5, "tcp_count": 2, "label": 0},
    {"syn_count": 80, "unique_ports": 80, "unique_dst_ips": 1, "udp_count": 0, "tcp_count": 80, "label": 1}
]

df = pd.DataFrame(data)

# === 3. Train Classifiers ===

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

models = {
    "Logistic Regression": LogisticRegression(),
    "Random Forest": RandomForestClassifier(),
    "SVM": SVC()
}

for name, model in models.items():
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[{name}] Accuracy: {acc:.2f}")

# === 4. Predict on Your PCAP ===

print("\n--- Scanning new PCAP file ---")
file_path = "bonus_project.pcapng"  # Replace with your pcap
features = extract_features(file_path)
input_df = pd.DataFrame([features])

for name, model in models.items():
    prediction = model.predict(input_df)[0]
    verdict = "\033[91mSCAN DETECTED\033[0m" if prediction == 1 else "\033[92mBenign\033[0m"
    print(f"\033[93m[{name}] Prediction for {file_path}:\033[0m {verdict}")
