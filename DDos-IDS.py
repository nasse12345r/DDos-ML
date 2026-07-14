import joblib
import pandas as pd
import numpy as np
import subprocess
import os
import glob
import time
from nfstream import NFStreamer

# ─── CONFIG ───────────────────────────────────────────
MODEL_PATH   = '/home/DS/Desktop/FYP/models/'
PCAP_FILE    = '/tmp/capture.pcap'
INTERFACE    = 'eth0'
CAPTURE_TIME = 5
# ──────────────────────────────────────────────────────

# Load models
print("[*] Loading models...")
rf       = joblib.load(MODEL_PATH + 'random_forest.pkl')
xgb      = joblib.load(MODEL_PATH + 'xgboost.pkl')
iso      = joblib.load(MODEL_PATH + 'isolation_forest.pkl')
scaler   = joblib.load(MODEL_PATH + 'scaler.pkl')
features = joblib.load(MODEL_PATH + 'feature_names.pkl')
print("[+] Models loaded successfully\n")

def capture_traffic():
    """Capture live traffic for CAPTURE_TIME seconds"""
    print(f"[*] Capturing traffic on {INTERFACE} for {CAPTURE_TIME}s...")
    try:
        # Remove old pcap first
        if os.path.exists(PCAP_FILE):
            os.remove(PCAP_FILE)

        # Use simple tcpdump without -G and -W flags
        proc = subprocess.Popen([
            'tcpdump', '-i', INTERFACE,
            '-w', PCAP_FILE,
            '-B', '8192',  # Allocates an 8MB buffer to stop kernel drops
            '--immediate-mode'
        ])

        # Let it run for CAPTURE_TIME seconds then stop
        time.sleep(CAPTURE_TIME)
        proc.terminate()
        proc.wait()

        print("[+] Capture complete")
        return True
    except Exception as e:
        print(f"[-] Capture error: {e}")
        return False

def pcap_to_flows(pcap_path):
    """Convert pcap to flow features using NFStream"""
    print("[*] Converting packets to flows...")
    try:
        if not os.path.exists(pcap_path):
            print("[-] pcap file not found")
            return None

        streamer = NFStreamer(
            source=pcap_path,
            statistical_analysis=True,
            splt_analysis=0
        )

        df = streamer.to_pandas()

        if df is None or len(df) == 0:
            print("[-] No flows extracted")
            return None

        print(f"[+] Extracted {len(df)} flows")
        return df

    except Exception as e:
        print(f"[-] Flow extraction error: {e}")
        return None

def preprocess_flows(df):
    """Map NFStream columns to match training features"""

    # Direct mappings
    col_map = {
        'protocol':                      'Protocol',
        'bidirectional_duration_ms':     'Flow Duration',
        'src2dst_packets':               'Total Fwd Packets',
        'dst2src_packets':               'Total Backward Packets',
        'src2dst_bytes':                 'Total Length of Fwd Packets',
        'dst2src_bytes':                 'Total Length of Bwd Packets',
        'src2dst_max_ps':                'Fwd Packet Length Max',
        'src2dst_min_ps':                'Fwd Packet Length Min',
        'src2dst_mean_ps':               'Fwd Packet Length Mean',
        'src2dst_stddev_ps':             'Fwd Packet Length Std',
        'dst2src_max_ps':                'Bwd Packet Length Max',
        'dst2src_min_ps':                'Bwd Packet Length Min',
        'dst2src_mean_ps':               'Bwd Packet Length Mean',
        'dst2src_stddev_ps':             'Bwd Packet Length Std',
        'bidirectional_mean_ps':         'Packet Length Mean',
        'bidirectional_stddev_ps':       'Packet Length Std',
        'bidirectional_max_ps':          'Max Packet Length',
        'bidirectional_min_ps':          'Min Packet Length',
        'src2dst_mean_piat_ms':          'Fwd IAT Mean',
        'src2dst_stddev_piat_ms':        'Fwd IAT Std',
        'src2dst_max_piat_ms':           'Fwd IAT Max',
        'src2dst_min_piat_ms':           'Fwd IAT Min',
        'dst2src_mean_piat_ms':          'Bwd IAT Mean',
        'dst2src_stddev_piat_ms':        'Bwd IAT Std',
        'dst2src_max_piat_ms':           'Bwd IAT Max',
        'dst2src_min_piat_ms':           'Bwd IAT Min',
        'bidirectional_mean_piat_ms':    'Flow IAT Mean',
        'bidirectional_stddev_piat_ms':  'Flow IAT Std',
        'bidirectional_max_piat_ms':     'Flow IAT Max',
        'bidirectional_min_piat_ms':     'Flow IAT Min',
        'bidirectional_syn_packets':     'SYN Flag Count',
        'bidirectional_fin_packets':     'FIN Flag Count',
        'bidirectional_rst_packets':     'RST Flag Count',
        'bidirectional_psh_packets':     'PSH Flag Count',
        'bidirectional_ack_packets':     'ACK Flag Count',
        'bidirectional_urg_packets':     'URG Flag Count',
        'bidirectional_ece_packets':     'ECE Flag Count',
        'bidirectional_cwr_packets':     'CWE Flag Count',
        'src2dst_syn_packets':           'Fwd PSH Flags',
        'src2dst_fin_packets':           'Fwd URG Flags',
        'dst2src_syn_packets':           'Bwd PSH Flags',
        'dst2src_fin_packets':           'Bwd URG Flags',
        'src2dst_duration_ms':           'Fwd IAT Total',
        'dst2src_duration_ms':           'Bwd IAT Total',
        'bidirectional_packets':         'Subflow Fwd Packets',
        'bidirectional_bytes':           'Subflow Fwd Bytes',
    }

    df = df.rename(columns=col_map)

    # Calculate derived features
    duration_s = df['Flow Duration'] / 1000.0  # ms to seconds

    # Flow Bytes/s and Flow Packets/s
    df['Flow Bytes/s'] = (
        df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']
    ) / duration_s.replace(0, np.nan)

    df['Flow Packets/s'] = (
        df['Total Fwd Packets'] + df['Total Backward Packets']
    ) / duration_s.replace(0, np.nan)

    df['Fwd Packets/s'] = df['Total Fwd Packets'] / duration_s.replace(0, np.nan)
    df['Bwd Packets/s'] = df['Total Backward Packets'] / duration_s.replace(0, np.nan)

    # Packet length variance
    df['Packet Length Variance'] = df['Packet Length Std'] ** 2

    # Average packet size
    df['Average Packet Size'] = (
        df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']
    ) / (df['Total Fwd Packets'] + df['Total Backward Packets']).replace(0, np.nan)

    # Segment sizes same as mean packet lengths
    df['Avg Fwd Segment Size'] = df['Fwd Packet Length Mean']
    df['Avg Bwd Segment Size'] = df['Bwd Packet Length Mean']

    # Header lengths estimated
    df['Fwd Header Length']   = df['Total Fwd Packets'] * 20
    df['Bwd Header Length']   = df['Total Backward Packets'] * 20
    df['Fwd Header Length.1'] = df['Fwd Header Length']

    # Subflow bytes
    df['Subflow Bwd Packets'] = df['Total Backward Packets']
    df['Subflow Bwd Bytes']   = df['Total Length of Bwd Packets']

    # Down/Up ratio
    df['Down/Up Ratio'] = df['Total Backward Packets'] / \
                          df['Total Fwd Packets'].replace(0, np.nan)

    # Bulk features — set to 0 (not available in NFStream)
    for col in ['Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
                'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
                'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
                'act_data_pkt_fwd', 'min_seg_size_forward',
                'Active Mean', 'Active Std', 'Active Max', 'Active Min',
                'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Inbound']:
        df[col] = 0

    # Build final dataframe in exact training feature order
    final_df = pd.DataFrame()
    for col in features:
        if col in df.columns:
            final_df[col] = df[col].values
        else:
            final_df[col] = 0

    # Handle infinities and NaN
    final_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    final_df.fillna(0, inplace=True)

    return final_df

def detect(df, raw_df):
    """Run protocol rule-based filter then ML models (Volume rules removed)"""
    if df is None or len(df) == 0:
        print("[-] No flows to analyse")
        return

    total = len(df)
    print(f"\n[*] Analysing {total} flows...")

    # ── Protocol Rule-Based Detection ────────────────────────
    syn_ratio = (raw_df['bidirectional_syn_packets'] == 1).mean() \
                if 'bidirectional_syn_packets' in raw_df.columns else 0

    zero_dur_ratio = (raw_df['bidirectional_duration_ms'] == 0).mean() \
                     if 'bidirectional_duration_ms' in raw_df.columns else 0

    single_src = raw_df['src_ip'].nunique() \
                 if 'src_ip' in raw_df.columns else 99

    total_packets = raw_df['bidirectional_packets'].sum() \
                    if 'bidirectional_packets' in raw_df.columns else 0

    pkt_per_flow = total_packets / total if total > 0 else 0

    rule_ddos = False
    rule_reason = ""

    # Rule 1 — SYN flood: high SYN ratio + high zero duration 
    # (Kept minimum 1000 flows just to prevent false alarms on background noise)
    if syn_ratio >= 0.25 and zero_dur_ratio >= 0.25 and total > 1000:
        rule_ddos = True
        rule_reason = f"SYN flood (SYN: {syn_ratio:.1%}, zero-dur: {zero_dur_ratio:.1%})"

    print(f"\n[RULE] SYN: {syn_ratio:.1%} | Zero-Dur: {zero_dur_ratio:.1%} | "
          f"Srcs: {single_src} | Flows: {total:,} | Pkts/Flow: {pkt_per_flow:.1f}")

    if rule_ddos:
        print(f"  ⚠  Rule triggered: {rule_reason}")

    # ── ML Models ───────────────────────────────────────
    X = scaler.transform(df)
    rf_preds  = rf.predict(X)
    xgb_preds = xgb.predict(X)
    iso_raw   = iso.predict(X)
    iso_preds = [1 if x == -1 else 0 for x in iso_raw]

    rf_ddos  = int(sum(rf_preds))
    xgb_ddos = int(sum(xgb_preds))
    iso_ddos = int(sum(iso_preds))

    # ── Confidence Thresholds ────────────────────────────
    rf_ratio  = rf_ddos / total
    xgb_ratio = xgb_ddos / total
    iso_ratio = iso_ddos / total

    # Minimum flow threshold — results unreliable below this
    min_flows = 20
    enough_data = total >= min_flows

    supervised_alert = rf_ratio >= 0.30 and xgb_ratio >= 0.30 and enough_data
    rule_alert = rule_ddos
    high_confidence = rf_ratio >= 0.60 and xgb_ratio >= 0.60 and enough_data
    
    print(f"\n[STATS] RF: {rf_ratio:.1%} flagged | "
          f"XGB: {xgb_ratio:.1%} flagged | "
          f"ISO: {iso_ratio:.1%} flagged")

    print("\n" + "-"*55)

    # ── Final Verdict ────────────────────────────────────
    if rule_alert:
        print("  🚨 FINAL VERDICT: DDoS ATTACK DETECTED!")
        print(f"     Protocol Anomaly — {rule_reason}")
    elif supervised_alert and rule_alert:
        print("  🚨 FINAL VERDICT: DDoS ATTACK DETECTED!")
        print(f"     Rule + ML consensus ({rf_ratio:.1%} of flows flagged)")
    elif high_confidence and enough_data:
        print("  🚨 FINAL VERDICT: DDoS ATTACK DETECTED!")
        print(f"     High ML confidence ({rf_ratio:.1%} of flows flagged)")
    elif supervised_alert and not rule_alert and enough_data:
        print("  ⚠  FINAL VERDICT: SUSPICIOUS TRAFFIC")
        print(f"     ML flags {rf_ratio:.1%} of {total} flows — monitor closely")
    else:
        print("  ✅ FINAL VERDICT: Traffic appears BENIGN")
        if not enough_data:
            print(f"     Insufficient flows ({total}) for reliable ML analysis")
        else:
            print(f"     RF: {rf_ratio:.1%} | XGB: {xgb_ratio:.1%} — within normal range")
    print("="*55 + "\n")

# ─── MAIN LOOP ────────────────────────────────────────
print("="*55)
print("  FYP DDoS Detection System — TP077433")
print("  Interface:", INTERFACE)
print("  Cycle Duration:", CAPTURE_TIME, "seconds")
print("="*55 + "\n")

cycle = 1
while True:
    print(f"─── Cycle {cycle} " + "─"*38)
    try:
        if capture_traffic():
            raw_df = pcap_to_flows(PCAP_FILE)
            if raw_df is not None:
                df = preprocess_flows(raw_df.copy())
                detect(df, raw_df)
    except KeyboardInterrupt:
        print("\n[*] Detection system stopped")
        break
    except Exception as e:
        print(f"[-] Error in cycle {cycle}: {e}")

    cycle += 1
    time.sleep(2)
