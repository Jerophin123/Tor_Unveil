from scapy.all import sniff
import pandas as pd

def analyze_traffic(model):
    packets = sniff(count=100)  # Capture 100 packets
    packet_data = []

    for packet in packets:
        if packet.haslayer("IP"):
            packet_data.append({
                "src": packet["IP"].src,
                "dst": packet["IP"].dst,
                "len": len(packet),
                "protocol": packet["IP"].proto
            })

    df = pd.DataFrame(packet_data)
    predictions = model.predict(df[["len", "protocol"]])  # Use ML model
    return {"packets": packet_data, "predictions": predictions.tolist()}
